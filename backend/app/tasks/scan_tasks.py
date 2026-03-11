"""Scan orchestration Celery tasks for OWASP Sentinel v3."""
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import redis as redis_lib
from celery import chord, group

from ..config import settings
from ..models.finding import Finding
from ..models.scan import Scan
from ._sync_db import get_sync_session
from .celery_app import celery_app

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TOOL_TASK_MAP: Dict[str, str] = {
    "nuclei": "tool_tasks.run_nuclei_scan",
    "nmap": "tool_tasks.run_nmap_scan",
    "sqlmap": "tool_tasks.run_sqlmap_scan",
    "xsstrike": "tool_tasks.run_xsstrike_scan",
    "subfinder": "tool_tasks.run_subfinder_scan",
    "httpx": "tool_tasks.run_httpx_probe",
}


def publish_scan_progress(
    scan_id: str,
    progress: int,
    message: str,
    redis_url: str = settings.redis_url,
) -> None:
    """Publish scan progress to Redis pub-sub channel ``scan:<scan_id>``."""
    try:
        client = redis_lib.from_url(redis_url, decode_responses=True)
        payload = json.dumps(
            {
                "scan_id": scan_id,
                "progress": progress,
                "message": message,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        client.publish(f"scan:{scan_id}", payload)
        client.close()
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to publish scan progress for %s: %s", scan_id, exc)


def _update_scan(
    scan_id: str,
    **kwargs: Any,
) -> None:
    """Update Scan row fields in a short-lived sync session."""
    with get_sync_session() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan is None:
            logger.error("Scan %s not found in DB – cannot update fields.", scan_id)
            return
        for field, value in kwargs.items():
            setattr(scan, field, value)


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="scan_tasks.execute_scan", max_retries=2)
def execute_scan(
    self,
    scan_id: str,
    target_url: str,
    scan_config: Dict[str, Any],
) -> Dict[str, Any]:
    """Main scan orchestration task.

    Steps:
    1. Update scan status to ``running`` in the DB.
    2. Determine which tools to run from ``scan_config["tools"]``.
    3. Execute each tool task (sequentially by default, or via a Celery
       chord when ``scan_config["parallel"] is True``).
    4. Aggregate findings and persist them to the DB.
    5. Mark the scan as ``completed`` (or ``failed`` on error).
    6. Broadcast progress events via Redis pub-sub throughout.
    """
    logger.info("execute_scan started: scan_id=%s target=%s", scan_id, target_url)

    # ------------------------------------------------------------------
    # 1. Mark scan as running
    # ------------------------------------------------------------------
    _update_scan(
        scan_id,
        status="running",
        started_at=datetime.now(timezone.utc),
        progress=0,
        error_message=None,
    )
    publish_scan_progress(scan_id, 0, "Scan started")

    tools: List[str] = scan_config.get("tools", ["nuclei"])
    parallel: bool = scan_config.get("parallel", False)

    try:
        # ------------------------------------------------------------------
        # 2. Run tools
        # ------------------------------------------------------------------
        all_findings: List[Dict[str, Any]] = []

        if parallel and len(tools) > 1:
            # Build a Celery chord: all tool tasks run in parallel, then
            # aggregate_results is called with the collected results.
            tool_signatures = []
            for tool_name in tools:
                task_name = _TOOL_TASK_MAP.get(tool_name)
                if task_name is None:
                    logger.warning("Unknown tool '%s' – skipping.", tool_name)
                    continue
                tool_cfg = scan_config.get(tool_name, {})
                sig = celery_app.signature(
                    task_name,
                    args=[target_url, tool_cfg],
                )
                tool_signatures.append(sig)

            if tool_signatures:
                publish_scan_progress(
                    scan_id, 10, f"Dispatching {len(tool_signatures)} tools in parallel"
                )
                callback = aggregate_results.s(scan_id=scan_id)
                result = chord(group(tool_signatures))(callback)
                # Block until the chord completes (with overall scan timeout).
                final = result.get(timeout=settings.tool_timeout * len(tools))
                all_findings = final.get("findings", [])
        else:
            # Sequential execution — simpler and gives finer progress updates.
            step_size = 80 // max(len(tools), 1)
            for idx, tool_name in enumerate(tools):
                task_name = _TOOL_TASK_MAP.get(tool_name)
                if task_name is None:
                    logger.warning("Unknown tool '%s' – skipping.", tool_name)
                    continue

                progress = 10 + idx * step_size
                publish_scan_progress(
                    scan_id, progress, f"Running {tool_name} ({idx + 1}/{len(tools)})"
                )
                _update_scan(scan_id, progress=progress)

                tool_cfg = scan_config.get(tool_name, {})
                tool_result = run_tool.apply(
                    args=[scan_id, tool_name, target_url, tool_cfg]
                ).get(timeout=settings.tool_timeout)

                if tool_result and isinstance(tool_result.get("findings"), list):
                    all_findings.extend(tool_result["findings"])

            # ------------------------------------------------------------------
            # 3. Aggregate
            # ------------------------------------------------------------------
            publish_scan_progress(scan_id, 90, "Aggregating findings")
            aggregate_results(all_findings, scan_id=scan_id)

        # ------------------------------------------------------------------
        # 4. Mark scan as completed
        # ------------------------------------------------------------------
        _update_scan(
            scan_id,
            status="completed",
            completed_at=datetime.now(timezone.utc),
            progress=100,
        )
        publish_scan_progress(scan_id, 100, "Scan completed successfully")

        summary = {
            "scan_id": scan_id,
            "status": "completed",
            "findings_count": len(all_findings),
        }
        logger.info("execute_scan finished: %s", summary)
        return summary

    except Exception as exc:
        logger.exception("execute_scan failed for scan_id=%s: %s", scan_id, exc)
        _update_scan(
            scan_id,
            status="failed",
            completed_at=datetime.now(timezone.utc),
            error_message=str(exc),
        )
        publish_scan_progress(scan_id, -1, f"Scan failed: {exc}")
        raise self.retry(exc=exc, countdown=30)


@celery_app.task(bind=True, name="scan_tasks.run_tool", max_retries=1)
def run_tool(
    self,
    scan_id: str,
    tool_name: str,
    target: str,
    tool_config: Dict[str, Any],
) -> Dict[str, Any]:
    """Dispatch a single named tool task and return its results.

    This thin wrapper lets ``execute_scan`` call tool tasks by name without
    hard-coding imports, and provides uniform error handling.
    """
    task_name = _TOOL_TASK_MAP.get(tool_name)
    if task_name is None:
        return {"tool": tool_name, "error": f"Unknown tool: {tool_name}", "findings": []}

    try:
        result = celery_app.send_task(
            task_name,
            args=[target, tool_config],
        ).get(timeout=settings.tool_timeout)
        return result
    except Exception as exc:
        logger.exception("run_tool '%s' failed: %s", tool_name, exc)
        return {"tool": tool_name, "error": str(exc), "findings": []}


@celery_app.task(name="scan_tasks.aggregate_results")
def aggregate_results(
    results: List[Any],
    scan_id: str,
) -> Dict[str, Any]:
    """Collect findings from all tool results and persist them to the DB.

    This task is used both as a direct call and as the callback of a Celery
    chord, so ``results`` may be a flat list of finding dicts or a list of
    per-tool result dicts.
    """
    all_findings: List[Dict[str, Any]] = []

    for item in results:
        if isinstance(item, list):
            # Raw list of finding dicts
            all_findings.extend(item)
        elif isinstance(item, dict):
            findings = item.get("findings")
            if isinstance(findings, list):
                all_findings.extend(findings)

    # Retrieve the scan's target_id so we can populate findings correctly.
    with get_sync_session() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan is None:
            logger.error("aggregate_results: scan %s not found", scan_id)
            return {"scan_id": scan_id, "findings": [], "stored": 0}

        target_id = str(scan.target_id)
        stored = 0

        for finding_data in all_findings:
            if not isinstance(finding_data, dict):
                continue
            title = finding_data.get("title") or finding_data.get("name", "Unnamed Finding")
            severity = _normalise_severity(finding_data.get("severity", "info"))
            finding = Finding(
                id=uuid.uuid4(),
                scan_id=uuid.UUID(scan_id),
                target_id=uuid.UUID(target_id),
                title=title[:512],
                description=finding_data.get("description"),
                severity=severity,
                owasp_category=finding_data.get("owasp_category"),
                cwe_id=finding_data.get("cwe_id"),
                cvss_score=finding_data.get("cvss_score"),
                url=finding_data.get("url"),
                parameter=finding_data.get("parameter"),
                payload_used=finding_data.get("payload_used"),
                evidence=finding_data.get("evidence"),
                remediation=finding_data.get("remediation"),
                status="open",
                tool_name=finding_data.get("tool_name"),
                raw_output=finding_data.get("raw_output"),
            )
            db.add(finding)
            stored += 1

    logger.info("aggregate_results: stored %d findings for scan %s", stored, scan_id)
    return {"scan_id": scan_id, "findings": all_findings, "stored": stored}


# ---------------------------------------------------------------------------
# Internal utilities
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
