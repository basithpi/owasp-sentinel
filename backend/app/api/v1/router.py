from fastapi import APIRouter

from .auth import router as auth_router
from .dashboard import router as dashboard_router
from .findings import router as findings_router
from .monitors import router as monitors_router
from .notifications import router as notifications_router
from .payloads import router as payloads_router
from .reports import router as reports_router
from .scans import router as scans_router
from .settings import router as settings_router
from .targets import router as targets_router
from .tools import router as tools_router
from .websocket import router as websocket_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth_router, tags=["Authentication"])
api_router.include_router(targets_router, tags=["Targets"])
api_router.include_router(scans_router, tags=["Scans"])
api_router.include_router(findings_router, tags=["Findings"])
api_router.include_router(payloads_router, tags=["Payloads"])
api_router.include_router(reports_router, tags=["Reports"])
api_router.include_router(tools_router, tags=["Tools"])
api_router.include_router(dashboard_router, tags=["Dashboard"])
api_router.include_router(monitors_router, tags=["Monitors"])
api_router.include_router(notifications_router, tags=["Notifications"])
api_router.include_router(settings_router, tags=["Settings"])
api_router.include_router(websocket_router, prefix="/ws", tags=["WebSocket"])
