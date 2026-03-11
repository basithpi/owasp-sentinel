"""Interactsh wrapper for out-of-band (OOB) interaction detection."""
from __future__ import annotations

import logging
import secrets
import uuid
from typing import Any

logger = logging.getLogger("owasp_sentinel.tools.interactsh")

_DEFAULT_SERVER = "https://oast.pro"


class InteractshWrapper:
    """Client for the Interactsh OOB interaction server."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self.server = self.config.get("server", _DEFAULT_SERVER).rstrip("/")
        self.token = self.config.get("token", "")
        self._registered_id: str | None = None
        self._secret_key: str | None = None

    async def register(self) -> dict[str, Any]:
        """Register with the Interactsh server and obtain a unique subdomain."""
        try:
            import httpx
        except ImportError:
            return {"success": False, "error": "httpx not installed"}

        correlation_id = secrets.token_hex(10)
        secret_key = secrets.token_urlsafe(32)

        headers: dict[str, str] = {}
        if self.token:
            headers["Authorization"] = self.token

        payload = {"public-key": secret_key, "secret-key": secret_key, "correlation-id": correlation_id}
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(f"{self.server}/register", json=payload, headers=headers)
                data = resp.json()
                self._registered_id = data.get("correlation-id", correlation_id)
                self._secret_key = secret_key
                return {
                    "success": True,
                    "correlation_id": self._registered_id,
                    "domain": f"{self._registered_id}.{self.server.replace('https://', '').replace('http://', '')}",
                }
        except Exception as exc:
            logger.debug("Interactsh registration failed: %s", exc)
            # Fallback: generate a local-only tracking ID
            self._registered_id = str(uuid.uuid4()).replace("-", "")[:20]
            host = self.server.replace("https://", "").replace("http://", "")
            return {
                "success": False,
                "error": str(exc),
                "correlation_id": self._registered_id,
                "domain": f"{self._registered_id}.{host}",
            }

    def generate_url(self, test_id: str | None = None) -> str:
        """Generate a unique OOB callback URL for a test."""
        host = self.server.replace("https://", "").replace("http://", "")
        tid = test_id or secrets.token_hex(8)
        cid = self._registered_id or secrets.token_hex(10)
        return f"http://{cid}-{tid}.{host}"

    async def poll_interactions(self) -> dict[str, Any]:
        """Poll the server for received interactions."""
        if not self._registered_id:
            return {"interactions": [], "error": "Not registered — call register() first"}

        try:
            import httpx
        except ImportError:
            return {"interactions": [], "error": "httpx not installed"}

        headers: dict[str, str] = {}
        if self.token:
            headers["Authorization"] = self.token

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"{self.server}/poll",
                    params={"id": self._registered_id, "secret": self._secret_key or ""},
                    headers=headers,
                )
                data = resp.json()
                return {"interactions": data.get("data", []), "aes_key": data.get("aes_key", "")}
        except Exception as exc:
            logger.debug("Interactsh poll failed: %s", exc)
            return {"interactions": [], "error": str(exc)}

    async def get_interactions_for_id(self, test_id: str) -> list[dict[str, Any]]:
        """Filter polled interactions by a specific test ID."""
        result = await self.poll_interactions()
        all_interactions: list[dict[str, Any]] = result.get("interactions", [])
        return [i for i in all_interactions if test_id in str(i.get("full-id", ""))]

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Register and return an OOB URL to use during testing of target."""
        reg = await self.register()
        url = self.generate_url()
        return {
            "target": target,
            "oob_url": url,
            "correlation_id": self._registered_id,
            "registration": reg,
            "usage": f"Inject {url} into target parameters and call poll_interactions() to check for callbacks.",
        }
