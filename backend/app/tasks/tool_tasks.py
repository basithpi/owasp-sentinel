"""Individual security-tool execution Celery tasks for OWASP Sentinel v3.

Each task spawns the target CLI tool as a subprocess, captures its output,
parses the results into a normalised ``findings`` list, and returns a
structured dict.  All tasks honour ``settings.tool_timeout`` as the
subprocess deadline.
"""
import json
import logging
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..config import settings
from ..models.tool import Tool
from ._sync_db import get_sync_session
from .celery_app import celery_app

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared subprocess helper
# ---------------------------------------------------------------------------

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "med": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "unknown": "info",
}


def _normalise_severity(raw: str) -> str:
    return _SEVERITY_MAP.get(str(raw).lower(), "info")


def _run_subprocess(
    cmd: List[str],
    timeout: Optional[int] = None,
    cwd: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """Run *cmd* with a timeout and return the CompletedProcess.

    Raises ``subprocess.TimeoutExpired`` or ``subprocess.CalledProcessError``
    on failure so callers can decide how to handle the result.
    """
    effective_timeout = timeout or settings.tool_timeout
    logger.debug("Executing: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=effective_timeout,
        cwd=cwd,
    )


# ---------------------------------------------------------------------------
# Nuclei
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="tool_tasks.run_nuclei_scan", max_retries=1, rate_limit="5/m")
def run_nuclei_scan(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Run Nuclei vulnerability scanner against *target*.

    Nuclei is invoked with ``-json`` so each result line is a JSON object.
    Findings are normalised into the Sentinel finding schema.
    """
    severities = config.get("severity", "critical,high,medium")
    templates = config.get("templates_path", settings.nuclei_templates_path)
    extra_args: List[str] = config.get("extra_args", [])

    with tempfile.NamedTemporaryFile(
        suffix=".jsonl", mode="w", delete=False
    ) as tmp:
        output_file = tmp.name

    cmd = [
        "nuclei",
        "-u", target,
        "-json",
        "-o", output_file,
        "-severity", severities,
        "-silent",
        "-no-color",
    ]
    if os.path.isdir(templates):
        cmd += ["-t", templates]
    cmd += extra_args

    findings: List[Dict[str, Any]] = []
    try:
        proc = _run_subprocess(cmd)
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"nuclei exited {proc.returncode}: {proc.stderr[:500]}")

        with open(output_file) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                findings.append(
                    {
                        "tool_name": "nuclei",
                        "title": item.get("info", {}).get("name", item.get("template-id", "Nuclei Finding")),
                        "description": item.get("info", {}).get("description", ""),
                        "severity": _normalise_severity(item.get("info", {}).get("severity", "info")),
                        "url": item.get("matched-at", target),
                        "owasp_category": _nuclei_owasp(item.get("info", {}).get("classification", {})),
                        "cwe_id": _first_int(
                            item.get("info", {}).get("classification", {}).get("cwe-id", [])
                        ),
                        "cvss_score": item.get("info", {}).get("classification", {}).get("cvss-score"),
                        "evidence": item.get("extracted-results"),
                        "remediation": item.get("info", {}).get("remediation"),
                        "raw_output": item,
                    }
                )
    except subprocess.TimeoutExpired:
        logger.error("nuclei timed out for target %s", target)
        raise self.retry(exc=RuntimeError("nuclei timed out"), countdown=60)
    except Exception as exc:
        logger.exception("run_nuclei_scan failed: %s", exc)
        raise self.retry(exc=exc, countdown=60)
    finally:
        try:
            os.unlink(output_file)
        except OSError:
            pass

    return {"tool": "nuclei", "target": target, "findings": findings}


def _nuclei_owasp(classification: Dict) -> Optional[str]:
    owasp_list = classification.get("owasp-id", [])
    if owasp_list:
        return str(owasp_list[0]).upper()
    return None


def _first_int(value: Any) -> Optional[int]:
    if isinstance(value, list) and value:
        try:
            raw = str(value[0]).split("-")[-1]
            return int(raw)
        except (ValueError, IndexError):
            return None
    if isinstance(value, (int, float)):
        return int(value)
    return None


# ---------------------------------------------------------------------------
# Nmap
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="tool_tasks.run_nmap_scan", max_retries=1)
def run_nmap_scan(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Run Nmap port scanner with NSE scripts.

    Output is captured as XML (``-oX -``) and parsed with
    ``xml.etree.ElementTree``.
    """
    ports = config.get("ports", "1-65535")
    scripts = config.get("scripts", "default,vuln")
    scan_flags: List[str] = config.get("flags", ["-sV", "-sC"])
    extra_args: List[str] = config.get("extra_args", [])

    cmd = [
        "nmap",
        "-p", ports,
        "--script", scripts,
        "-oX", "-",
        "--open",
        "-T4",
    ] + scan_flags + extra_args + [target]

    findings: List[Dict[str, Any]] = []
    try:
        proc = _run_subprocess(cmd)
        if proc.returncode != 0 and not proc.stdout.strip():
            raise RuntimeError(f"nmap exited {proc.returncode}: {proc.stderr[:500]}")

        findings = _parse_nmap_xml(proc.stdout, target)
    except subprocess.TimeoutExpired:
        logger.error("nmap timed out for target %s", target)
        raise self.retry(exc=RuntimeError("nmap timed out"), countdown=60)
    except Exception as exc:
        logger.exception("run_nmap_scan failed: %s", exc)
        raise self.retry(exc=exc, countdown=60)

    return {"tool": "nmap", "target": target, "findings": findings}


def _parse_nmap_xml(xml_data: str, target: str) -> List[Dict[str, Any]]:
    """Convert Nmap XML output into normalised finding dicts."""
    findings: List[Dict[str, Any]] = []
    if not xml_data.strip():
        return findings

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as exc:
        logger.warning("Failed to parse nmap XML: %s", exc)
        return findings

    for host in root.findall("host"):
        host_addr = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                host_addr = addr.get("addr", target)

        for port_el in host.findall("./ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            port_id = port_el.get("portid", "")
            protocol = port_el.get("protocol", "tcp")
            svc_el = port_el.find("service")
            service = svc_el.get("name", "") if svc_el is not None else ""
            product = svc_el.get("product", "") if svc_el is not None else ""
            version = svc_el.get("version", "") if svc_el is not None else ""

            # Collect NSE script output for this port
            scripts_out: List[str] = []
            for script_el in port_el.findall("script"):
                script_id = script_el.get("id", "")
                script_output = script_el.get("output", "")
                if script_output:
                    scripts_out.append(f"{script_id}: {script_output}")

            severity = "info"
            if any(
                vuln_kw in " ".join(scripts_out).lower()
                for vuln_kw in ("vuln", "exploit", "vulnerable", "cve-")
            ):
                severity = "medium"

            findings.append(
                {
                    "tool_name": "nmap",
                    "title": f"Open port {port_id}/{protocol} ({service})",
                    "description": (
                        f"Service: {product} {version}".strip()
                        + ("\n\nNSE Scripts:\n" + "\n".join(scripts_out) if scripts_out else "")
                    ),
                    "severity": severity,
                    "url": f"{host_addr}:{port_id}",
                    "evidence": "\n".join(scripts_out) or None,
                    "raw_output": {
                        "host": host_addr,
                        "port": port_id,
                        "protocol": protocol,
                        "service": service,
                        "scripts": scripts_out,
                    },
                }
            )

    return findings


# ---------------------------------------------------------------------------
# SQLMap
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="tool_tasks.run_sqlmap_scan", max_retries=1, rate_limit="2/m")
def run_sqlmap_scan(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Run SQLMap SQL injection scanner."""
    level = config.get("level", 1)
    risk = config.get("risk", 1)
    extra_args: List[str] = config.get("extra_args", [])
    data = config.get("data")  # POST data

    cmd = [
        "sqlmap",
        "-u", target,
        "--level", str(level),
        "--risk", str(risk),
        "--batch",
        "--no-logging",
        "--output-dir", tempfile.gettempdir(),
        "--forms",
    ]
    if data:
        cmd += ["--data", data]
    cmd += extra_args

    findings: List[Dict[str, Any]] = []
    try:
        proc = _run_subprocess(cmd)
        findings = _parse_sqlmap_output(proc.stdout, target)
    except subprocess.TimeoutExpired:
        logger.error("sqlmap timed out for target %s", target)
        raise self.retry(exc=RuntimeError("sqlmap timed out"), countdown=60)
    except Exception as exc:
        logger.exception("run_sqlmap_scan failed: %s", exc)
        raise self.retry(exc=exc, countdown=60)

    return {"tool": "sqlmap", "target": target, "findings": findings}


def _parse_sqlmap_output(stdout: str, target: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if "is vulnerable" not in stdout.lower() and "sql injection" not in stdout.lower():
        return findings

    # Extract injection points
    for line in stdout.splitlines():
        lower = line.lower()
        if "parameter" in lower and ("injectable" in lower or "sql injection" in lower):
            findings.append(
                {
                    "tool_name": "sqlmap",
                    "title": "SQL Injection Vulnerability",
                    "description": line.strip(),
                    "severity": "high",
                    "url": target,
                    "owasp_category": "A03",
                    "cwe_id": 89,
                    "remediation": (
                        "Use parameterised queries or prepared statements. "
                        "Never interpolate user input into SQL strings."
                    ),
                    "raw_output": {"stdout_line": line.strip()},
                }
            )
    return findings


# ---------------------------------------------------------------------------
# XSStrike
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="tool_tasks.run_xsstrike_scan", max_retries=1)
def run_xsstrike_scan(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Run XSStrike XSS scanner."""
    data = config.get("data")
    extra_args: List[str] = config.get("extra_args", [])

    cmd = [
        "python3",
        "-m", "xsstrike",
        "--url", target,
        "--crawl",
        "--blind",
    ]
    if data:
        cmd += ["--data", data]
    cmd += extra_args

    findings: List[Dict[str, Any]] = []
    try:
        proc = _run_subprocess(cmd)
        findings = _parse_xsstrike_output(proc.stdout + proc.stderr, target)
    except subprocess.TimeoutExpired:
        logger.error("xsstrike timed out for target %s", target)
        raise self.retry(exc=RuntimeError("xsstrike timed out"), countdown=60)
    except Exception as exc:
        logger.exception("run_xsstrike_scan failed: %s", exc)
        raise self.retry(exc=exc, countdown=60)

    return {"tool": "xsstrike", "target": target, "findings": findings}


def _parse_xsstrike_output(output: str, target: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    payload: Optional[str] = None
    for line in output.splitlines():
        lower = line.lower()
        if "xss" in lower and "vulnerable" in lower:
            findings.append(
                {
                    "tool_name": "xsstrike",
                    "title": "Cross-Site Scripting (XSS)",
                    "description": line.strip(),
                    "severity": "high",
                    "url": target,
                    "owasp_category": "A03",
                    "cwe_id": 79,
                    "payload_used": payload,
                    "remediation": (
                        "Encode all user-supplied output, apply a strict "
                        "Content-Security-Policy, and validate input server-side."
                    ),
                    "raw_output": {"output_line": line.strip()},
                }
            )
        elif "payload" in lower:
            payload = line.strip()
    return findings


# ---------------------------------------------------------------------------
# Subfinder
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="tool_tasks.run_subfinder_scan", max_retries=1)
def run_subfinder_scan(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Run Subfinder subdomain enumeration."""
    # Accept a domain or strip scheme/path for bare domain
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    extra_args: List[str] = config.get("extra_args", [])

    cmd = [
        "subfinder",
        "-d", domain,
        "-json",
        "-silent",
    ] + extra_args

    subdomains: List[str] = []
    findings: List[Dict[str, Any]] = []
    try:
        proc = _run_subprocess(cmd)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                subdomain = obj.get("host") or obj.get("subdomain") or str(obj)
            except json.JSONDecodeError:
                subdomain = line
            subdomains.append(subdomain)

        if subdomains:
            findings.append(
                {
                    "tool_name": "subfinder",
                    "title": f"Discovered {len(subdomains)} subdomains for {domain}",
                    "description": "Subfinder identified the following subdomains:\n" + "\n".join(subdomains),
                    "severity": "info",
                    "url": target,
                    "raw_output": {"subdomains": subdomains},
                }
            )
    except subprocess.TimeoutExpired:
        logger.error("subfinder timed out for target %s", target)
        raise self.retry(exc=RuntimeError("subfinder timed out"), countdown=60)
    except Exception as exc:
        logger.exception("run_subfinder_scan failed: %s", exc)
        raise self.retry(exc=exc, countdown=60)

    return {"tool": "subfinder", "target": target, "findings": findings, "subdomains": subdomains}


# ---------------------------------------------------------------------------
# httpx
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="tool_tasks.run_httpx_probe", max_retries=1)
def run_httpx_probe(self, targets: List[str], config: Dict[str, Any]) -> Dict[str, Any]:
    """Run httpx HTTP probe against a list of targets.

    Useful after subfinder enumeration to identify live hosts and gather
    HTTP metadata (status, title, technology fingerprints).
    """
    extra_args: List[str] = config.get("extra_args", [])

    # Write target list to a temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False
    ) as tmp_in:
        tmp_in.write("\n".join(targets))
        input_file = tmp_in.name

    cmd = [
        "httpx",
        "-l", input_file,
        "-json",
        "-silent",
        "-title",
        "-tech-detect",
        "-status-code",
        "-content-length",
        "-follow-redirects",
    ] + extra_args

    findings: List[Dict[str, Any]] = []
    live_hosts: List[Dict[str, Any]] = []
    try:
        proc = _run_subprocess(cmd)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            live_hosts.append(item)
            url = item.get("url", item.get("input", ""))
            status = item.get("status-code", 0)
            title = item.get("title", "")
            technologies = item.get("tech", [])
            findings.append(
                {
                    "tool_name": "httpx",
                    "title": f"Live HTTP service: {url} [{status}]",
                    "description": (
                        f"Title: {title}\n"
                        f"Technologies: {', '.join(technologies) if technologies else 'Unknown'}"
                    ),
                    "severity": "info",
                    "url": url,
                    "raw_output": item,
                }
            )
    except subprocess.TimeoutExpired:
        logger.error("httpx timed out")
        raise self.retry(exc=RuntimeError("httpx timed out"), countdown=60)
    except Exception as exc:
        logger.exception("run_httpx_probe failed: %s", exc)
        raise self.retry(exc=exc, countdown=60)
    finally:
        try:
            os.unlink(input_file)
        except OSError:
            pass

    return {"tool": "httpx", "findings": findings, "live_hosts": live_hosts}


# ---------------------------------------------------------------------------
# Tool health check
# ---------------------------------------------------------------------------


@celery_app.task(name="tool_tasks.check_tool_health")
def check_tool_health(tool_name: str) -> Dict[str, Any]:
    """Check if a security tool is installed and responsive.

    Runs the tool with a harmless flag (``--version`` or ``-version``) and
    returns a status dict.  The result is also persisted to the ``tools``
    table via the sync DB session.
    """
    _HEALTH_COMMANDS: Dict[str, List[str]] = {
        "nuclei": ["nuclei", "-version"],
        "nmap": ["nmap", "--version"],
        "sqlmap": ["sqlmap", "--version"],
        "xsstrike": ["python3", "-m", "xsstrike", "--help"],
        "subfinder": ["subfinder", "-version"],
        "httpx": ["httpx", "-version"],
    }

    cmd = _HEALTH_COMMANDS.get(tool_name)
    if cmd is None:
        return {
            "tool": tool_name,
            "status": "unknown",
            "message": f"No health-check command configured for '{tool_name}'",
        }

    status = "unknown"
    version = None
    message = ""
    try:
        proc = _run_subprocess(cmd, timeout=15)
        output = (proc.stdout + proc.stderr).strip()
        if proc.returncode == 0 or output:
            status = "healthy"
            # Try to pull a version string from the first line
            first_line = output.splitlines()[0] if output else ""
            version = first_line[:50] if first_line else None
            message = f"Tool is installed and responsive. Output: {first_line}"
        else:
            status = "unhealthy"
            message = f"Non-zero exit ({proc.returncode}): {output[:200]}"
    except FileNotFoundError:
        status = "unhealthy"
        message = f"Tool '{tool_name}' not found in PATH"
    except subprocess.TimeoutExpired:
        status = "degraded"
        message = f"Tool '{tool_name}' health check timed out"
    except Exception as exc:
        status = "unhealthy"
        message = str(exc)

    # Persist result to the tools table
    try:
        with get_sync_session() as db:
            tool = db.query(Tool).filter(Tool.name == tool_name).first()
            if tool:
                tool.health_status = status
                tool.is_installed = status in ("healthy", "degraded")
                tool.last_health_check = datetime.now(timezone.utc)
                if version:
                    tool.version = version
    except Exception as exc:
        logger.warning("check_tool_health: failed to persist result: %s", exc)

    logger.info("check_tool_health: %s -> %s", tool_name, status)
    return {"tool": tool_name, "status": status, "version": version, "message": message}

