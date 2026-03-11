from fastapi import APIRouter

from .auth import router as auth_router
from .findings import router as findings_router
from .payloads import router as payloads_router
from .scans import router as scans_router
from .targets import router as targets_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth_router)
api_router.include_router(targets_router)
api_router.include_router(scans_router)
api_router.include_router(findings_router)
api_router.include_router(payloads_router)
