from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    auth,
    targets,
    scans,
    findings,
    payloads,
    reports,
    tools,
    dashboard,
    monitor,
    notifications,
    settings,
    websocket,
)

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(targets.router, prefix="/targets", tags=["targets"])
api_router.include_router(scans.router, prefix="/scans", tags=["scans"])
api_router.include_router(findings.router, prefix="/findings", tags=["findings"])
api_router.include_router(payloads.router, prefix="/payloads", tags=["payloads"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(tools.router, prefix="/tools", tags=["tools"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
api_router.include_router(monitor.router, prefix="/monitor", tags=["monitor"])
api_router.include_router(notifications.router, prefix="/notifications", tags=["notifications"])
api_router.include_router(settings.router, prefix="/settings", tags=["settings"])
api_router.include_router(websocket.router, prefix="/ws", tags=["websocket"])
