"""C15 – WebSocket security tester.

Tests WebSocket handshake security, origin bypass, message injection,
CSWSH detection, authentication bypass, rate limiting, and protocol downgrade.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import re
import time
from datetime import datetime
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

try:
    import websockets  # type: ignore
    import websockets.exceptions  # type: ignore
    _WS_AVAILABLE = True
except ImportError:
    _WS_AVAILABLE = False

from app.modules.base_module import BaseModule

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "';alert(1);//",
]

_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users;--",
    "1' UNION SELECT null,null,null--",
    "' OR 1=1--",
    "\" OR \"\"=\"",
]

_ORIGINS_TO_TEST = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
    "http://localhost",
    "https://sub.target.com",
]

_WS_KEY_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class WebSocketTester(BaseModule):
    """Tests WebSocket security: handshake, origin bypass, message injection,
    CSWSH, auth bypass, rate limiting, and protocol downgrade."""

    name = "websocket_tester"
    description = (
        "Audits WebSocket endpoints for origin bypass, message injection, "
        "CSWSH, authentication bypass, rate limiting, and protocol downgrade."
    )
    version = "1.0.0"
    category = "web_security"

    async def run(self, target: str, **kwargs) -> dict[str, Any]:
        """Test WebSocket security on *target*.

        Args:
            target: WebSocket URL (ws:// or wss://) or HTTP URL to probe.
            **kwargs:
                ws_path (str): Path for WebSocket endpoint (default: /).
                auth_token (str): Authentication token to include in headers.
                timeout (int): Per-connection timeout in seconds (default: 10).
                rate_limit_requests (int): Requests to send for rate-limit testing (default: 20).

        Returns:
            Dict with ``findings``, ``handshake_details``, and metadata.
        """
        self.started_at = datetime.utcnow()
        ws_path: str = kwargs.get("ws_path", "/")
        auth_token: str = kwargs.get("auth_token", "")
        timeout = int(kwargs.get("timeout", 10))
        rate_requests = min(int(kwargs.get("rate_limit_requests", 20)), 50)

        ws_url = _to_ws_url(target, ws_path)
        http_url = _to_http_url(target, ws_path)

        handshake_details: dict[str, Any] = {}

        # 1. Handshake header analysis (via HTTP upgrade probe)
        handshake_details = await self._analyse_handshake(http_url, timeout)

        # 2. Origin bypass testing
        await self._test_origin_bypass(ws_url, timeout)

        # 3. CSWSH detection
        self._check_cswsh(handshake_details)

        # 4. Auth bypass on upgrade
        await self._test_auth_bypass(ws_url, timeout, auth_token)

        # 5. Protocol downgrade
        await self._test_protocol_downgrade(target, ws_path, timeout)

        # 6. Message injection (if websockets available)
        if _WS_AVAILABLE:
            await self._test_message_injection(ws_url, timeout, auth_token)
            await self._test_rate_limiting(ws_url, timeout, auth_token, rate_requests)
        else:
            self.logger.warning("websockets library not available; skipping message injection and rate limit tests")

        self.completed_at = datetime.utcnow()
        return {
            "module": self.name,
            "target": ws_url,
            "findings": self.results,
            "handshake_details": handshake_details,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
        }

    # ------------------------------------------------------------------ #
    # Handshake analysis                                                   #
    # ------------------------------------------------------------------ #

    async def _analyse_handshake(self, http_url: str, timeout: int) -> dict[str, Any]:
        """Send an HTTP Upgrade request and inspect the handshake headers."""
        ws_key = base64.b64encode(os.urandom(16)).decode()
        headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": ws_key,
            "Sec-WebSocket-Version": "13",
            "Origin": "https://example.com",
        }
        details: dict[str, Any] = {"url": http_url, "upgrade_headers": headers}
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                resp = await client.get(http_url, headers=headers)
            details["status_code"] = resp.status_code
            details["response_headers"] = dict(resp.headers)

            # Validate Sec-WebSocket-Accept
            expected_accept = base64.b64encode(
                hashlib.sha1((ws_key + _WS_KEY_GUID).encode()).digest()
            ).decode()
            actual_accept = resp.headers.get("sec-websocket-accept", "")
            details["accept_valid"] = actual_accept == expected_accept

            if resp.status_code == 101:
                details["ws_endpoint_confirmed"] = True
                if not resp.headers.get("sec-websocket-accept"):
                    self.add_finding(
                        title="Missing Sec-WebSocket-Accept header",
                        severity="medium",
                        description=(
                            "The WebSocket upgrade response is missing the "
                            "Sec-WebSocket-Accept header. This violates RFC 6455."
                        ),
                        evidence=f"Response headers: {dict(resp.headers)}",
                        url=http_url,
                    )
            elif resp.status_code not in (400, 426):
                details["ws_endpoint_confirmed"] = False
        except Exception as exc:
            details["error"] = str(exc)
        return details

    # ------------------------------------------------------------------ #
    # Origin bypass                                                        #
    # ------------------------------------------------------------------ #

    async def _test_origin_bypass(self, ws_url: str, timeout: int) -> None:
        """Test whether the server accepts connections from arbitrary origins."""
        http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")
        ws_key = base64.b64encode(os.urandom(16)).decode()

        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            for origin in _ORIGINS_TO_TEST:
                headers = {
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": ws_key,
                    "Sec-WebSocket-Version": "13",
                    "Origin": origin,
                }
                try:
                    resp = await client.get(http_url, headers=headers)
                    if resp.status_code == 101:
                        self.add_finding(
                            title=f"WebSocket origin bypass: accepted '{origin}'",
                            severity="high",
                            description=(
                                f"The server accepted a WebSocket upgrade from untrusted "
                                f"origin '{origin}'. This allows cross-origin WebSocket hijacking."
                            ),
                            evidence=f"HTTP 101 with Origin: {origin}",
                            url=http_url,
                            bypass_origin=origin,
                        )
                except Exception:
                    continue

    # ------------------------------------------------------------------ #
    # CSWSH detection                                                      #
    # ------------------------------------------------------------------ #

    def _check_cswsh(self, handshake: dict[str, Any]) -> None:
        """Check if the WebSocket upgrade lacks CSRF protection."""
        headers = handshake.get("response_headers", {})
        # Look for absence of CSRF token requirement or same-origin checks
        cookie_header = headers.get("set-cookie", "")
        has_samesite = "samesite" in cookie_header.lower()
        has_csrf = any(
            k.lower() in ("x-csrf-token", "x-xsrf-token") for k in headers
        )
        if not has_samesite and not has_csrf:
            self.add_finding(
                title="Possible Cross-Site WebSocket Hijacking (CSWSH)",
                severity="high",
                description=(
                    "The WebSocket upgrade endpoint does not appear to use CSRF tokens "
                    "or SameSite cookie attributes. An attacker may be able to hijack "
                    "WebSocket connections from a malicious site."
                ),
                evidence="No CSRF token or SameSite cookie attribute in upgrade response",
                url=handshake.get("url", ""),
            )

    # ------------------------------------------------------------------ #
    # Auth bypass                                                          #
    # ------------------------------------------------------------------ #

    async def _test_auth_bypass(
        self, ws_url: str, timeout: int, auth_token: str
    ) -> None:
        """Attempt WebSocket upgrade without authentication headers."""
        http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")
        ws_key = base64.b64encode(os.urandom(16)).decode()
        headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": ws_key,
            "Sec-WebSocket-Version": "13",
        }
        # Don't include any auth token
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                resp = await client.get(http_url, headers=headers)
            if resp.status_code == 101:
                self.add_finding(
                    title="WebSocket authentication bypass",
                    severity="critical",
                    description=(
                        "The WebSocket endpoint accepted an upgrade request without any "
                        "authentication credentials. Unauthenticated WebSocket access may "
                        "expose sensitive data or functionality."
                    ),
                    evidence=f"HTTP 101 without Authorization header",
                    url=http_url,
                )
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Protocol downgrade                                                   #
    # ------------------------------------------------------------------ #

    async def _test_protocol_downgrade(
        self, target: str, ws_path: str, timeout: int
    ) -> None:
        """Check if a wss:// endpoint also accepts ws:// (plaintext) connections."""
        parsed = urlparse(target)
        if parsed.scheme in ("https", "wss"):
            insecure_url = _to_ws_url(target.replace("https://", "http://").replace("wss://", "ws://"), ws_path)
            http_url = insecure_url.replace("ws://", "http://")
            ws_key = base64.b64encode(os.urandom(16)).decode()
            headers = {
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": ws_key,
                "Sec-WebSocket-Version": "13",
            }
            try:
                async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                    resp = await client.get(http_url, headers=headers)
                if resp.status_code == 101:
                    self.add_finding(
                        title="WebSocket protocol downgrade to ws://",
                        severity="high",
                        description=(
                            "The server accepted a plaintext ws:// WebSocket upgrade even "
                            "though HTTPS/WSS is available. This allows traffic interception."
                        ),
                        evidence=f"HTTP 101 on {http_url}",
                        url=http_url,
                    )
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # Message injection                                                    #
    # ------------------------------------------------------------------ #

    async def _test_message_injection(
        self, ws_url: str, timeout: int, auth_token: str
    ) -> None:
        """Send XSS and SQLi payloads via WebSocket and check responses."""
        extra_headers: dict[str, str] = {}
        if auth_token:
            extra_headers["Authorization"] = f"Bearer {auth_token}"
        payloads = _XSS_PAYLOADS + _SQLI_PAYLOADS

        for payload in payloads:
            try:
                async with websockets.connect(  # type: ignore[attr-defined]
                    ws_url,
                    extra_headers=extra_headers,
                    open_timeout=timeout,
                    ssl=None,
                ) as ws:
                    await asyncio.wait_for(ws.send(payload), timeout=timeout)
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=timeout)
                        if payload in str(response):
                            self.add_finding(
                                title="WebSocket message injection reflected",
                                severity="high",
                                description=(
                                    f"The payload '{payload[:60]}' was reflected in the "
                                    "WebSocket response. This may indicate XSS or injection vulnerability."
                                ),
                                evidence=f"Payload: {payload[:60]}\nResponse: {str(response)[:200]}",
                                url=ws_url,
                                payload=payload[:60],
                            )
                    except asyncio.TimeoutError:
                        pass
            except Exception:
                continue

    # ------------------------------------------------------------------ #
    # Rate limit testing                                                   #
    # ------------------------------------------------------------------ #

    async def _test_rate_limiting(
        self, ws_url: str, timeout: int, auth_token: str, count: int
    ) -> None:
        """Send rapid messages to test for rate limiting on WebSocket endpoints."""
        extra_headers: dict[str, str] = {}
        if auth_token:
            extra_headers["Authorization"] = f"Bearer {auth_token}"
        errors = 0
        try:
            async with websockets.connect(  # type: ignore[attr-defined]
                ws_url,
                extra_headers=extra_headers,
                open_timeout=timeout,
                ssl=None,
            ) as ws:
                start = time.monotonic()
                for i in range(count):
                    try:
                        await ws.send(f"rate_limit_test_{i}")
                    except Exception:
                        errors += 1
                elapsed = time.monotonic() - start

            if errors == 0:
                self.add_finding(
                    title="No WebSocket rate limiting detected",
                    severity="medium",
                    description=(
                        f"Sent {count} messages in {elapsed:.2f}s without any rate limiting "
                        "or disconnection. The endpoint may be susceptible to DoS or flooding."
                    ),
                    evidence=f"Sent {count} messages, errors: {errors}, time: {elapsed:.2f}s",
                    url=ws_url,
                )
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _to_ws_url(target: str, path: str = "/") -> str:
    """Convert http(s) or bare host to a ws(s) URL."""
    if target.startswith("ws://") or target.startswith("wss://"):
        return target
    if target.startswith("https://"):
        return "wss://" + target[8:].rstrip("/") + path
    if target.startswith("http://"):
        return "ws://" + target[7:].rstrip("/") + path
    return f"wss://{target.rstrip('/')}{path}"


def _to_http_url(target: str, path: str = "/") -> str:
    """Convert ws(s) URL to http(s)."""
    if target.startswith("wss://"):
        return "https://" + target[6:].rstrip("/") + path
    if target.startswith("ws://"):
        return "http://" + target[5:].rstrip("/") + path
    if target.startswith("https://") or target.startswith("http://"):
        return target.rstrip("/") + path
    return f"https://{target.rstrip('/')}{path}"
