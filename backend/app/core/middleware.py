from __future__ import annotations

import threading
import time
import uuid
from collections import defaultdict
from typing import Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# NOTE: In-memory rate limiting works only for single-worker deployments.
# For multi-worker setups use a Redis-backed implementation instead.
_request_counts: dict = defaultdict(list)
_rate_limit_lock = threading.Lock()
RATE_LIMIT_REQUESTS = 100
RATE_LIMIT_WINDOW = 60


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = str(process_time)
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window_start = now - RATE_LIMIT_WINDOW
        with _rate_limit_lock:
            _request_counts[client_ip] = [
                t for t in _request_counts[client_ip] if t > window_start
            ]
            if len(_request_counts[client_ip]) >= RATE_LIMIT_REQUESTS:
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Try again later."},
                )
            _request_counts[client_ip].append(now)
        return await call_next(request)


def setup_cors(app: FastAPI) -> None:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
