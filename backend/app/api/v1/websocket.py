from __future__ import annotations

import asyncio
import json
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.finding import Finding
from app.models.notification import Notification
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User

router = APIRouter()

# ---------------------------------------------------------------------------
# In-memory connection registries
# ---------------------------------------------------------------------------

# scan_id (str) -> set of connected WebSockets
_scan_connections: Dict[str, Set[WebSocket]] = defaultdict(set)

# user_id (str) -> set of connected WebSockets (notifications stream)
_notification_connections: Dict[str, Set[WebSocket]] = defaultdict(set)

# All WebSockets subscribed to dashboard updates
_dashboard_connections: Set[WebSocket] = set()


# ---------------------------------------------------------------------------
# Broadcast helpers (used by background tasks / other services)
# ---------------------------------------------------------------------------


async def broadcast_scan_update(scan_id: str, payload: Dict[str, Any]) -> None:
    """Send a JSON payload to every client watching the given scan."""
    message = json.dumps(payload)
    dead: Set[WebSocket] = set()
    for ws in list(_scan_connections.get(scan_id, set())):
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)
    for ws in dead:
        _scan_connections[scan_id].discard(ws)


async def broadcast_notification(user_id: str, payload: Dict[str, Any]) -> None:
    """Send a JSON payload to every notification WebSocket for the given user."""
    message = json.dumps(payload)
    dead: Set[WebSocket] = set()
    for ws in list(_notification_connections.get(user_id, set())):
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)
    for ws in dead:
        _notification_connections[user_id].discard(ws)


async def broadcast_dashboard_update(payload: Dict[str, Any]) -> None:
    """Send a JSON payload to every client watching the dashboard."""
    message = json.dumps(payload)
    dead: Set[WebSocket] = set()
    for ws in list(_dashboard_connections):
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)
    for ws in dead:
        _dashboard_connections.discard(ws)


# ---------------------------------------------------------------------------
# WebSocket endpoints
# ---------------------------------------------------------------------------


@router.websocket("/scans/{scan_id}")
async def scan_stream(
    scan_id: uuid.UUID,
    websocket: WebSocket,
    db: Session = Depends(get_db),
):
    """Stream live status updates for a specific scan.

    The client receives a JSON message every 2 seconds containing the scan's
    current status, progress, and findings count.  The stream closes
    automatically when the scan reaches a terminal state (completed, failed,
    or cancelled).
    """
    await websocket.accept()
    scan_id_str = str(scan_id)
    _scan_connections[scan_id_str].add(websocket)
    try:
        while True:
            scan: Optional[Scan] = (
                db.query(Scan).filter(Scan.id == scan_id).first()
            )
            if scan is None:
                await websocket.send_json(
                    {"error": f"Scan {scan_id_str} not found", "scan_id": scan_id_str}
                )
                break

            payload: Dict[str, Any] = {
                "scan_id": scan_id_str,
                "status": scan.status,
                "progress": scan.progress,
                "findings_count": scan.findings_count,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            }
            await websocket.send_json(payload)

            if scan.status in ("completed", "failed", "cancelled"):
                break

            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
    finally:
        _scan_connections[scan_id_str].discard(websocket)


@router.websocket("/notifications")
async def notification_stream(
    websocket: WebSocket,
    db: Session = Depends(get_db),
):
    """Stream real-time notifications for the authenticated user.

    Authentication is performed via a ``token`` query parameter (JWT access
    token) because standard ``Authorization`` headers are not accessible in
    browser WebSocket handshakes.

    The client receives existing unread notifications immediately after
    connecting, and then new notifications are pushed as they arrive.  The
    server polls the database every 5 seconds and pushes any notifications
    created since the last check.
    """
    token: Optional[str] = websocket.query_params.get("token")
    current_user: Optional[User] = None

    if token:
        try:
            from jose import JWTError

            from app.core.security import decode_token

            payload = decode_token(token)
            user_id_str: Optional[str] = payload.get("sub")
            if user_id_str and payload.get("type") == "access":
                current_user = db.query(User).filter(User.id == uuid.UUID(user_id_str)).first()
        except Exception:
            pass

    if current_user is None:
        await websocket.close(code=4001, reason="Unauthorized")
        return

    await websocket.accept()
    user_id_str = str(current_user.id)
    _notification_connections[user_id_str].add(websocket)

    last_checked = datetime.now(timezone.utc)

    # Push unread notifications that already exist
    existing_unread = (
        db.query(Notification)
        .filter(Notification.user_id == current_user.id, Notification.is_read.is_(False))
        .order_by(Notification.created_at.desc())
        .limit(20)
        .all()
    )
    for notif in reversed(existing_unread):
        try:
            await websocket.send_json(
                {
                    "event": "notification",
                    "id": str(notif.id),
                    "title": notif.title,
                    "message": notif.message,
                    "type": notif.type,
                    "is_read": notif.is_read,
                    "created_at": notif.created_at.isoformat(),
                }
            )
        except Exception:
            break

    try:
        while True:
            await asyncio.sleep(5)
            now = datetime.now(timezone.utc)
            new_notifs = (
                db.query(Notification)
                .filter(
                    Notification.user_id == current_user.id,
                    Notification.created_at > last_checked,
                )
                .order_by(Notification.created_at.asc())
                .all()
            )
            last_checked = now
            for notif in new_notifs:
                await websocket.send_json(
                    {
                        "event": "notification",
                        "id": str(notif.id),
                        "title": notif.title,
                        "message": notif.message,
                        "type": notif.type,
                        "is_read": notif.is_read,
                        "created_at": notif.created_at.isoformat(),
                    }
                )
    except WebSocketDisconnect:
        pass
    finally:
        _notification_connections[user_id_str].discard(websocket)


@router.websocket("/dashboard")
async def dashboard_stream(
    websocket: WebSocket,
    db: Session = Depends(get_db),
):
    """Stream periodic dashboard statistics updates.

    Authentication is performed via a ``token`` query parameter (JWT access
    token).  The server sends an updated stats snapshot every 10 seconds.
    """
    token: Optional[str] = websocket.query_params.get("token")
    current_user: Optional[User] = None

    if token:
        try:
            from jose import JWTError

            from app.core.security import decode_token

            payload = decode_token(token)
            user_id_str: Optional[str] = payload.get("sub")
            if user_id_str and payload.get("type") == "access":
                current_user = db.query(User).filter(User.id == uuid.UUID(user_id_str)).first()
        except Exception:
            pass

    if current_user is None:
        await websocket.close(code=4001, reason="Unauthorized")
        return

    await websocket.accept()
    _dashboard_connections.add(websocket)

    def _build_stats() -> Dict[str, Any]:
        """Collect current dashboard stats for *current_user*."""
        from sqlalchemy import func

        uid = current_user.id
        is_admin = current_user.role == "admin"

        target_q = db.query(Target) if is_admin else db.query(Target).filter(Target.user_id == uid)
        scan_q = db.query(Scan) if is_admin else db.query(Scan).filter(Scan.user_id == uid)
        finding_q = db.query(Finding) if is_admin else db.query(Finding).filter(Finding.user_id == uid)

        severity_rows = (
            finding_q.with_entities(Finding.severity, func.count(Finding.id))
            .group_by(Finding.severity)
            .all()
        )
        severity_counts: Dict[str, int] = {row[0]: row[1] for row in severity_rows}

        return {
            "event": "stats_update",
            "total_targets": target_q.count(),
            "active_targets": target_q.filter(Target.is_active.is_(True)).count(),
            "total_scans": scan_q.count(),
            "running_scans": scan_q.filter(Scan.status == "running").count(),
            "total_findings": finding_q.count(),
            "open_findings": finding_q.filter(Finding.status == "open").count(),
            "critical_findings": severity_counts.get("critical", 0),
            "high_findings": severity_counts.get("high", 0),
        }

    try:
        # Send initial snapshot immediately
        await websocket.send_json(_build_stats())
        while True:
            await asyncio.sleep(10)
            await websocket.send_json(_build_stats())
    except WebSocketDisconnect:
        pass
    finally:
        _dashboard_connections.discard(websocket)
