import xml.etree.ElementTree as ET
from typing import List, Dict, Any

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class NmapTool(BaseTool):
    name = "nmap"
    category = "port-scanner"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        cmd = ["nmap", "-sV", "-sC", "--script=vuln", "-oX", "-", target]
        returncode, stdout, stderr = await self._run_command(cmd)
        findings = await self.parse_output(stdout)
        return ToolResult(
            success=returncode == 0,
            findings=findings,
            raw_output=stdout,
            error=stderr if returncode != 0 else None,
        )

    async def parse_output(self, raw_output: str) -> List[Finding]:
        findings = []
        if not raw_output.strip():
            return findings
        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError as e:
            self.logger.error("Failed to parse nmap XML: %s", e)
            return findings

        for host in root.findall("host"):
            address = host.find("address")
            ip = address.get("addr", "") if address is not None else ""
            ports = host.find("ports")
            if ports is None:
                continue
            for port in ports.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = port.get("portid", "")
                protocol = port.get("protocol", "tcp")
                service = port.find("service")
                svc_name = service.get("name", "") if service is not None else ""
                svc_version = service.get("version", "") if service is not None else ""

                # Collect script output (vuln findings)
                for script in port.findall("script"):
                    script_id = script.get("id", "")
                    script_output = script.get("output", "")
                    severity = FindingSeverity.MEDIUM
                    if "VULNERABLE" in script_output.upper():
                        severity = FindingSeverity.HIGH
                    findings.append(Finding(
                        title=f"Nmap: {script_id} on {ip}:{portid}/{protocol}",
                        description=script_output,
                        severity=severity,
                        url=f"{ip}:{portid}",
                        tool_name="nmap",
                        raw_output={"ip": ip, "port": portid, "protocol": protocol,
                                    "service": svc_name, "version": svc_version,
                                    "script_id": script_id, "output": script_output},
                    ))

                # Open port as INFO if no vuln scripts matched
                if not port.findall("script"):
                    findings.append(Finding(
                        title=f"Open port {portid}/{protocol} ({svc_name}) on {ip}",
                        description=f"Service: {svc_name} {svc_version}",
                        severity=FindingSeverity.INFO,
                        url=f"{ip}:{portid}",
                        tool_name="nmap",
                        raw_output={"ip": ip, "port": portid, "protocol": protocol,
                                    "service": svc_name, "version": svc_version},
                    ))
        return findings

    async def health_check(self) -> HealthCheckResult:
        returncode, stdout, stderr = await self._run_command(["nmap", "--version"])
        if returncode == 0:
            version_line = stdout.splitlines()[0] if stdout else ""
            return HealthCheckResult(status=HealthStatus.HEALTHY, version=version_line)
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message="nmap not found")
