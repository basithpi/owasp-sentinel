"""Caido web proxy integration wrapper.

Manages Caido proxy sessions via its HTTP API, exports recorded traffic,
and imports findings back into OWASP Sentinel.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger("owasp_sentinel.tools.caido")


class CaidoWrapper:
    """Wrapper for Caido web proxy integration via its REST API."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialise with optional config dict.

        Args:
            config: Optional configuration overrides.  Recognised keys:
                ``api_url``  – base URL of the Caido API (default ``http://localhost:8080``).
                ``api_key``  – Caido API token.
                ``timeout``  – HTTP timeout in seconds (default 30).
        """
        self.config: dict[str, Any] = config or {}
        self.api_url: str = self.config.get("api_url", "http://localhost:8080")
        self.api_key: str = self.config.get("api_key", "")
        self.timeout: int = int(self.config.get("timeout", 30))
        self._session_id: str | None = None
        self._client = httpx.AsyncClient(
            base_url=self.api_url,
            headers={"Authorization": f"Bearer {self.api_key}"} if self.api_key else {},
            timeout=self.timeout,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Start a Caido session for *target* and return session metadata.

        Args:
            target: The base URL to proxy traffic for.
            **kwargs: Additional options forwarded to :meth:`start_session`.

        Returns:
            Dictionary with ``session_id`` and ``target``.
        """
        session_id = await self.start_session(target, **kwargs)
        return {"session_id": session_id, "target": target}

    async def start_session(self, target: str, **kwargs: Any) -> str:
        """Start a new Caido proxy session.

        Args:
            target: Target scope URL.
            **kwargs: Extra body parameters for the Caido API.

        Returns:
            The new session identifier string.
        """
        logger.info("Starting Caido session for target: %s", target)
        payload: dict[str, Any] = {"target": target, **kwargs}
        try:
            response = await self._client.post("/api/sessions", json=payload)
            response.raise_for_status()
            data = response.json()
            self._session_id = str(data.get("id", ""))
            logger.debug("Caido session started: %s", self._session_id)
            return self._session_id
        except httpx.HTTPError as exc:
            logger.error("Failed to start Caido session: %s", exc)
            raise

    async def stop_session(self, session_id: str | None = None) -> bool:
        """Stop the specified (or current) Caido session.

        Args:
            session_id: Session to stop.  Uses the active session when omitted.

        Returns:
            ``True`` on success.
        """
        sid = session_id or self._session_id
        if not sid:
            logger.warning("No active Caido session to stop")
            return False
        logger.info("Stopping Caido session: %s", sid)
        try:
            response = await self._client.delete(f"/api/sessions/{sid}")
            response.raise_for_status()
            if sid == self._session_id:
                self._session_id = None
            return True
        except httpx.HTTPError as exc:
            logger.error("Failed to stop Caido session %s: %s", sid, exc)
            raise

    async def export_findings(self, session_id: str | None = None) -> list[dict[str, Any]]:
        """Export findings recorded in a session.

        Args:
            session_id: Source session.  Defaults to the active session.

        Returns:
            List of finding dictionaries returned by Caido.
        """
        sid = session_id or self._session_id
        if not sid:
            return []
        logger.info("Exporting findings from Caido session: %s", sid)
        try:
            response = await self._client.get(f"/api/sessions/{sid}/findings")
            response.raise_for_status()
            raw: list[dict[str, Any]] = response.json().get("findings", [])
            return [self.parse_output(item) for item in raw]
        except httpx.HTTPError as exc:
            logger.error("Failed to export findings: %s", exc)
            return []

    async def import_requests(
        self,
        requests: list[dict[str, Any]],
        session_id: str | None = None,
    ) -> bool:
        """Import a list of raw HTTP request dicts into a Caido session.

        Args:
            requests: List of request objects (method, url, headers, body).
            session_id: Target session.  Defaults to the active session.

        Returns:
            ``True`` if the import was accepted.
        """
        sid = session_id or self._session_id
        if not sid:
            logger.error("No active session for import_requests")
            return False
        logger.info("Importing %d requests into Caido session %s", len(requests), sid)
        try:
            response = await self._client.post(
                f"/api/sessions/{sid}/requests",
                json={"requests": requests},
            )
            response.raise_for_status()
            return True
        except httpx.HTTPError as exc:
            logger.error("Failed to import requests: %s", exc)
            return False

    def parse_output(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalise a raw Caido finding dict into OWASP Sentinel format.

        Args:
            raw: Raw finding dictionary from the Caido API.

        Returns:
            Normalised finding dictionary.
        """
        return {
            "title": raw.get("title", "Caido Finding"),
            "severity": raw.get("severity", "info").lower(),
            "description": raw.get("description", ""),
            "evidence": raw.get("request", ""),
            "url": raw.get("url", ""),
            "source": "caido",
            "raw": raw,
        }

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()
