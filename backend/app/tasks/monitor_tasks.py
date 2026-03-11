"""Continuous monitoring Celery tasks for OWASP Sentinel v3.

The beat schedule triggers ``run_continuous_monitors`` every 5 minutes.
That task queries all active monitors from the DB and dispatches the
appropriate per-monitor task based on ``monitor_type``.
"""
import json
import logging
import socket
import ssl
import subprocess
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..config import settings
from ..models.monitor import Monitor
from ..models.notification import Notification
from ..models.target import Target
from ._sync_db import get_sync_session
from .celery_app import celery_app

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Beat entry-point
# ---------------------------------------------------------------------------


@celery_app.task(name="monitor_tasks.run_continuous_monitors")
def run_continuous_monitors() -> Dict[str, Any]:
    """Dispatch individual monitor tasks for all active monitors.

    Called by Celery Beat every 5 minutes.  Returns a summary of how many
    monitors were dispatched by type.
    """
    dispatched: Dict[str, int] = {}
    errors: List[str] = []

    _TASK_MAP = {
        "subdomain": "app.tasks.monitor_tasks.check_subdomain_changes",
        "cert": "app.tasks.monitor_tasks.check_certificate_expiry",
        "technology": "app.tasks.monitor_tasks.check_technology_changes",
        "uptime": "app.tasks.monitor_tasks.check_uptime",
    }

    try:
        with get_sync_session() as db:
            monitors = (
                db.query(Monitor)
                .filter(Monitor.is_active.is_(True))
                .all()
            )
            monitor_data = [
                {
                    "id": str(m.id),
                    "monitor_type": m.monitor_type,
                    "config": m.config or {},
                    "target_id": str(m.target_id),
                }
                for m in monitors
            ]

        # Load target URLs outside the session
        target_urls: Dict[str, str] = {}
        with get_sync_session() as db:
            for md in monitor_data:
                t = db.query(Target).filter(Target.id == md["target_id"]).first()
                if t:
                    target_urls[md["target_id"]] = t.url

        for md in monitor_data:
            task_name = _TASK_MAP.get(md["monitor_type"])
            if task_name is None:
                errors.append(f"Unknown monitor type: {md['monitor_type']}")
                continue
            target_url = target_urls.get(md["target_id"], "")
            celery_app.send_task(
                task_name,
                args=[md["id"], target_url, md["config"]],
            )
            dispatched[md["monitor_type"]] = dispatched.get(md["monitor_type"], 0) + 1

    except Exception as exc:
        logger.exception("run_continuous_monitors failed: %s", exc)
        return {"status": "error", "error": str(exc)}

    logger.info("run_continuous_monitors: dispatched=%s", dispatched)
    return {"status": "dispatched", "counts": dispatched, "errors": errors}


# ---------------------------------------------------------------------------
# Subdomain change monitor
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="monitor_tasks.check_subdomain_changes")
def check_subdomain_changes(
    self,
    monitor_id: str,
    target: str,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    """Run Subfinder, compare results with previous run, alert on new subdomains."""
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    extra_args: List[str] = config.get("extra_args", [])

    cmd = ["subfinder", "-d", domain, "-json", "-silent"] + extra_args
    current_subdomains: List[str] = []

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.tool_timeout,
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                sub = obj.get("host") or obj.get("subdomain") or str(obj)
            except json.JSONDecodeError:
                sub = line
            current_subdomains.append(sub)
    except subprocess.TimeoutExpired:
        logger.error("subfinder timed out for monitor %s", monitor_id)
        raise self.retry(exc=RuntimeError("subfinder timed out"), countdown=120)
    except FileNotFoundError:
        logger.warning("subfinder not found — skipping subdomain monitor %s", monitor_id)
        return {
            "monitor_id": monitor_id,
            "status": "skipped",
            "reason": "subfinder not installed",
        }
    except Exception as exc:
        logger.exception("check_subdomain_changes failed: %s", exc)
        raise self.retry(exc=exc, countdown=120)

    current_set = set(current_subdomains)
    new_subdomains: List[str] = []
    removed_subdomains: List[str] = []

    with get_sync_session() as db:
        monitor = db.query(Monitor).filter(Monitor.id == monitor_id).first()
        if monitor is None:
            return {"monitor_id": monitor_id, "status": "error", "reason": "Monitor not found"}

        previous_result = monitor.last_result or {}
        previous_set = set(previous_result.get("subdomains", []))

        new_subdomains = sorted(current_set - previous_set)
        removed_subdomains = sorted(previous_set - current_set)

        monitor.last_check = datetime.now(timezone.utc)
        monitor.last_result = {"subdomains": sorted(current_set)}

        # Persist notification for new subdomains if alert_on_change is set
        if new_subdomains and monitor.alert_on_change and monitor.created_by:
            notification = Notification(
                id=uuid.uuid4(),
                user_id=monitor.created_by,
                title=f"New subdomains discovered for {domain}",
                message=(
                    f"{len(new_subdomains)} new subdomain(s) found:\n"
                    + "\n".join(new_subdomains[:20])
                    + ("\n…and more" if len(new_subdomains) > 20 else "")
                ),
                type="warning",
                category="scan",
                reference_id=monitor_id,
            )
            db.add(notification)

    result = {
        "monitor_id": monitor_id,
        "domain": domain,
        "status": "completed",
        "total": len(current_subdomains),
        "new": new_subdomains,
        "removed": removed_subdomains,
        "changed": bool(new_subdomains or removed_subdomains),
    }
    logger.info(
        "check_subdomain_changes: domain=%s total=%d new=%d removed=%d",
        domain,
        len(current_subdomains),
        len(new_subdomains),
        len(removed_subdomains),
    )
    return result


# ---------------------------------------------------------------------------
# Certificate expiry monitor
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="monitor_tasks.check_certificate_expiry")
def check_certificate_expiry(
    self,
    monitor_id: str,
    target: str,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    """Check SSL/TLS certificate expiry for the target host."""
    hostname = target.replace("https://", "").replace("http://", "").split("/")[0]
    port = config.get("port", 443)
    warn_days = config.get("warn_days", 30)
    critical_days = config.get("critical_days", 7)

    cert_info: Dict[str, Any] = {}
    days_remaining: Optional[int] = None
    status_level = "info"
    message = ""

    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((hostname, port), timeout=15) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        not_after_str = cert.get("notAfter", "")
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        now = datetime.now(timezone.utc)
        days_remaining = (not_after - now).days

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        san = [v for _type, v in cert.get("subjectAltName", []) if _type == "DNS"]

        cert_info = {
            "subject": subject,
            "issuer": issuer,
            "not_before": cert.get("notBefore"),
            "not_after": not_after_str,
            "days_remaining": days_remaining,
            "san": san,
        }

        if days_remaining <= critical_days:
            status_level = "critical"
            message = f"Certificate expires in {days_remaining} days (CRITICAL)"
        elif days_remaining <= warn_days:
            status_level = "warning"
            message = f"Certificate expires in {days_remaining} days (WARNING)"
        else:
            status_level = "info"
            message = f"Certificate valid for {days_remaining} more days"

    except ssl.SSLCertVerificationError as exc:
        status_level = "critical"
        message = f"SSL certificate verification failed: {exc}"
        cert_info = {"error": str(exc)}
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        status_level = "warning"
        message = f"Could not connect to {hostname}:{port} — {exc}"
        cert_info = {"error": str(exc)}
    except Exception as exc:
        logger.exception("check_certificate_expiry failed: %s", exc)
        raise self.retry(exc=exc, countdown=120)

    # Persist result and optionally create a notification
    with get_sync_session() as db:
        monitor = db.query(Monitor).filter(Monitor.id == monitor_id).first()
        if monitor is None:
            return {"monitor_id": monitor_id, "status": "error", "reason": "Monitor not found"}

        monitor.last_check = datetime.now(timezone.utc)
        monitor.last_result = cert_info

        if status_level in ("critical", "warning") and monitor.alert_on_change and monitor.created_by:
            notification = Notification(
                id=uuid.uuid4(),
                user_id=monitor.created_by,
                title=f"SSL certificate alert for {hostname}",
                message=message,
                type="error" if status_level == "critical" else "warning",
                category="system",
                reference_id=monitor_id,
            )
            db.add(notification)

    result = {
        "monitor_id": monitor_id,
        "hostname": hostname,
        "status": status_level,
        "message": message,
        "days_remaining": days_remaining,
        "cert_info": cert_info,
    }
    logger.info("check_certificate_expiry: %s -> %s", hostname, message)
    return result


# ---------------------------------------------------------------------------
# Technology change monitor
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="monitor_tasks.check_technology_changes")
def check_technology_changes(
    self,
    monitor_id: str,
    target: str,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    """Detect technology stack changes by inspecting HTTP headers and body.

    Uses httpx (sync client) to fetch the target and compares headers /
    fingerprints with the previously stored result.
    """
    import httpx

    timeout = config.get("timeout", 15)
    headers_to_watch = config.get(
        "headers",
        ["server", "x-powered-by", "x-aspnet-version", "x-generator", "x-drupal-cache"],
    )

    current_tech: Dict[str, Any] = {}
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = client.get(target)

        # Collect watched headers (lowercase for comparison)
        observed_headers: Dict[str, str] = {}
        for hdr in headers_to_watch:
            value = response.headers.get(hdr)
            if value:
                observed_headers[hdr] = value

        # Attempt basic technology fingerprinting from response body
        body_lower = response.text.lower()
        detected: List[str] = []
        _FINGERPRINTS = {
            "WordPress": "wp-content",
            "Drupal": "drupal",
            "Joomla": "joomla",
            "Laravel": "laravel_session",
            "Django": "csrfmiddlewaretoken",
            "React": "react",
            "Vue.js": "vue",
            "Angular": "ng-version",
            "jQuery": "jquery",
            "Bootstrap": "bootstrap",
        }
        for tech_name, marker in _FINGERPRINTS.items():
            if marker in body_lower:
                detected.append(tech_name)

        current_tech = {
            "headers": observed_headers,
            "detected_technologies": detected,
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type", ""),
        }

    except httpx.TimeoutException:
        logger.warning("check_technology_changes: timeout for %s", target)
        raise self.retry(exc=RuntimeError("httpx timeout"), countdown=120)
    except Exception as exc:
        logger.exception("check_technology_changes failed: %s", exc)
        raise self.retry(exc=exc, countdown=120)

    changed = False
    changes: Dict[str, Any] = {}

    with get_sync_session() as db:
        monitor = db.query(Monitor).filter(Monitor.id == monitor_id).first()
        if monitor is None:
            return {"monitor_id": monitor_id, "status": "error", "reason": "Monitor not found"}

        previous = monitor.last_result or {}
        prev_headers = previous.get("headers", {})
        prev_detected = set(previous.get("detected_technologies", []))
        curr_detected = set(current_tech["detected_technologies"])

        # Detect header-level changes
        header_changes = {
            k: {"before": prev_headers.get(k), "after": current_tech["headers"].get(k)}
            for k in set(list(prev_headers.keys()) + list(current_tech["headers"].keys()))
            if prev_headers.get(k) != current_tech["headers"].get(k)
        }
        new_tech = sorted(curr_detected - prev_detected)
        removed_tech = sorted(prev_detected - curr_detected)

        if header_changes or new_tech or removed_tech:
            changed = True
            changes = {
                "header_changes": header_changes,
                "new_technologies": new_tech,
                "removed_technologies": removed_tech,
            }

        monitor.last_check = datetime.now(timezone.utc)
        monitor.last_result = current_tech

        if changed and monitor.alert_on_change and monitor.created_by:
            notification = Notification(
                id=uuid.uuid4(),
                user_id=monitor.created_by,
                title=f"Technology stack change detected for {target}",
                message=json.dumps(changes, indent=2),
                type="warning",
                category="scan",
                reference_id=monitor_id,
            )
            db.add(notification)

    result = {
        "monitor_id": monitor_id,
        "target": target,
        "status": "completed",
        "changed": changed,
        "current": current_tech,
        "changes": changes,
    }
    logger.info("check_technology_changes: %s changed=%s", target, changed)
    return result


# ---------------------------------------------------------------------------
# Uptime monitor (bonus — referenced in _TASK_MAP above)
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="monitor_tasks.check_uptime")
def check_uptime(
    self,
    monitor_id: str,
    target: str,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    """Perform a simple HTTP GET to verify the target is reachable."""
    import httpx

    timeout = config.get("timeout", 15)
    expected_status = config.get("expected_status", [200, 201, 301, 302])

    is_up = False
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    message = ""

    try:
        start = datetime.now(timezone.utc)
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = client.get(target)
        elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
        status_code = response.status_code
        response_time_ms = round(elapsed, 2)
        is_up = status_code in expected_status
        message = f"HTTP {status_code} in {response_time_ms}ms"
    except httpx.TimeoutException:
        message = f"Request timed out after {timeout}s"
    except Exception as exc:
        message = str(exc)

    with get_sync_session() as db:
        monitor = db.query(Monitor).filter(Monitor.id == monitor_id).first()
        if monitor is None:
            return {"monitor_id": monitor_id, "status": "error", "reason": "Monitor not found"}

        prev_result = monitor.last_result or {}
        was_up = prev_result.get("is_up", True)

        monitor.last_check = datetime.now(timezone.utc)
        monitor.last_result = {
            "is_up": is_up,
            "status_code": status_code,
            "response_time_ms": response_time_ms,
            "message": message,
        }

        # Alert only when status changes (up→down or down→up)
        if monitor.alert_on_change and was_up != is_up and monitor.created_by:
            notification = Notification(
                id=uuid.uuid4(),
                user_id=monitor.created_by,
                title=f"{'DOWN' if not is_up else 'UP'}: {target}",
                message=message,
                type="error" if not is_up else "success",
                category="system",
                reference_id=monitor_id,
            )
            db.add(notification)

    result = {
        "monitor_id": monitor_id,
        "target": target,
        "is_up": is_up,
        "status_code": status_code,
        "response_time_ms": response_time_ms,
        "message": message,
    }
    logger.info("check_uptime: %s is_up=%s %s", target, is_up, message)
    return result
