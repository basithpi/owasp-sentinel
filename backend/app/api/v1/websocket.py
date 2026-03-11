from collections.abc import AsyncGenerator

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
import redis.asyncio as aioredis

from ...config import settings
from ...core.security import verify_token

router = APIRouter(tags=["WebSocket"])

# Shared Redis connection pool reused across all WebSocket connections
_redis_pool: aioredis.Redis | None = None


def _get_redis() -> aioredis.Redis:
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = aioredis.from_url(
            settings.redis_url,
            decode_responses=False,
            max_connections=50,
        )
    return _redis_pool


@router.websocket("/scans/{scan_id}")
async def scan_websocket(
    websocket: WebSocket,
    scan_id: str,
    token: str = Query(...),
) -> None:
    """Stream live scan output for a given scan via Redis pub-sub."""
    payload = verify_token(token, token_type="access")
    if payload is None:
        await websocket.close(code=4401)
        return

    await websocket.accept()
    redis_client = _get_redis()
    try:
        pubsub = redis_client.pubsub()
        await pubsub.subscribe(f"scan:{scan_id}:output")
        async for message in pubsub.listen():
            if message["type"] == "message":
                data = message["data"]
                text = data.decode("utf-8") if isinstance(data, bytes) else str(data)
                await websocket.send_text(text)
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(f"scan:{scan_id}:output")
        await pubsub.aclose()


@router.websocket("/notifications")
async def notifications_websocket(
    websocket: WebSocket,
    token: str = Query(...),
) -> None:
    """Push real-time notifications to the authenticated user via Redis pub-sub."""
    payload = verify_token(token, token_type="access")
    if payload is None:
        await websocket.close(code=4401)
        return

    user_id: str = payload.get("sub", "")
    if not user_id:
        await websocket.close(code=4401)
        return

    await websocket.accept()
    redis_client = _get_redis()
    channel = f"notifications:{user_id}"
    try:
        pubsub = redis_client.pubsub()
        await pubsub.subscribe(channel)
        async for message in pubsub.listen():
            if message["type"] == "message":
                data = message["data"]
                text = data.decode("utf-8") if isinstance(data, bytes) else str(data)
                await websocket.send_text(text)
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.aclose()
