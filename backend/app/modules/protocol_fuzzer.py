"""C1 – Protocol-aware fuzzer.

Tests HTTP/1.1, HTTP/2, HTTP/3, WebSocket, GraphQL, and gRPC endpoints for
protocol-specific vulnerabilities including differential analysis, downgrade
attacks, HPACK bombs, and gRPC reflection enumeration.
"""

from __future__ import annotations

import asyncio
import struct
import time
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import httpx

try:
    import websockets  # type: ignore
    _WS_AVAILABLE = True
except ImportError:
    _WS_AVAILABLE = False

from app.modules.base_module import BaseModule

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_GRAPHQL_INTROSPECTION = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind description }
    directives { name description locations args { name } }
  }
}
""".strip()

_GRPC_LIST_SERVICES_BODY = (
    b"\x00"  # compressed-flag = 0
    + struct.pack(">I", 4)  # message length
    + b"\n\x00"  # ListServices request (empty service name)
    + b"\x00\x00"  # padding to 4 bytes
)


def _ws_url(http_url: str) -> str:
    """Convert an http(s) URL to ws(s)."""
    return http_url.replace("https://", "wss://", 1).replace("http://", "ws://", 1)


def _base_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class ProtocolFuzzer(BaseModule):
    """Protocol-aware fuzzer covering HTTP/1.1, HTTP/2, WebSocket, GraphQL, gRPC."""

    name = "protocol_fuzzer"
    description = (
        "Fuzz HTTP/1.1, HTTP/2, WebSocket, GraphQL, and gRPC endpoints; "
        "detect protocol downgrade attacks, HPACK bombs, and gRPC reflection."
    )
    version = "1.0.0"
    category = "fuzzing"

    # ------------------------------------------------------------------ #
    # Public entry-point                                                   #
    # ------------------------------------------------------------------ #

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Run all protocol fuzz tests against *target*.

        Args:
            target: Base URL or hostname of the target application.
            **kwargs: Optional overrides:
                - timeout (int): Per-request timeout in seconds (default 10).
                - ws_path (str): WebSocket path to test (default "/").
                - graphql_path (str): GraphQL endpoint path (default "/graphql").
                - grpc_port (int): gRPC port (default 50051).
        """
        self.started_at = datetime.utcnow()
        base = _base_url(target)
        timeout = int(kwargs.get("timeout", 10))

        tasks = [
            self._fuzz_http11_vs_http2(base, timeout),
            self._detect_protocol_downgrade(base, timeout),
            self._test_hpack_bomb(base, timeout),
            self._fuzz_graphql(base, kwargs.get("graphql_path", "/graphql"), timeout),
            self._fuzz_grpc_reflection(
                urlparse(base).hostname or target,
                int(kwargs.get("grpc_port", 50051)),
                timeout,
            ),
        ]
        if _WS_AVAILABLE:
            tasks.append(
                self._fuzz_websocket(
                    base, kwargs.get("ws_path", "/"), timeout
                )
            )

        await asyncio.gather(*tasks, return_exceptions=True)

        self.completed_at = datetime.utcnow()
        return self.to_dict()

    # ------------------------------------------------------------------ #
    # HTTP/1.1 vs HTTP/2 differential analysis                            #
    # ------------------------------------------------------------------ #

    async def _fuzz_http11_vs_http2(self, base: str, timeout: int) -> None:
        """Send the same request over HTTP/1.1 and HTTP/2 and compare responses."""
        fuzz_headers = {
            "X-Fuzz-Transfer-Encoding": "chunked, identity",
            "Content-Length": "0",
            "Transfer-Encoding": "chunked",
        }

        try:
            async with httpx.AsyncClient(
                http2=False, timeout=timeout, verify=False
            ) as h1:
                r1 = await h1.get(base, headers=fuzz_headers)

            async with httpx.AsyncClient(
                http2=True, timeout=timeout, verify=False
            ) as h2:
                r2 = await h2.get(base, headers=fuzz_headers)

            if r1.status_code != r2.status_code:
                self.add_finding(
                    title="HTTP/1.1 vs HTTP/2 Differential Response",
                    severity="medium",
                    description=(
                        "The server returns different status codes for HTTP/1.1 "
                        f"({r1.status_code}) and HTTP/2 ({r2.status_code}) for "
                        "an identical request containing smuggling-probe headers. "
                        "This may indicate a request-smuggling or desynchronisation "
                        "vulnerability at the protocol boundary."
                    ),
                    evidence=(
                        f"HTTP/1.1 status={r1.status_code}  "
                        f"HTTP/2 status={r2.status_code}"
                    ),
                    url=base,
                    protocol_h1=r1.status_code,
                    protocol_h2=r2.status_code,
                )
                self.logger.info(
                    "Differential response detected: H1=%s H2=%s",
                    r1.status_code,
                    r2.status_code,
                )
            else:
                self.logger.debug(
                    "H1/H2 responses consistent (%s)", r1.status_code
                )

            # Check whether HTTP/2 is actually negotiated (ALPN)
            h2_negotiated = r2.http_version == "HTTP/2"
            if not h2_negotiated:
                self.add_finding(
                    title="HTTP/2 Not Supported (ALPN Fallback)",
                    severity="info",
                    description=(
                        "The server does not advertise HTTP/2 via ALPN. "
                        "Clients will fall back to HTTP/1.1, which offers "
                        "fewer built-in protections against request smuggling."
                    ),
                    evidence=f"Negotiated version: {r2.http_version}",
                    url=base,
                )

        except Exception as exc:
            self.logger.debug("H1/H2 diff test error: %s", exc)

    # ------------------------------------------------------------------ #
    # Protocol downgrade detection                                         #
    # ------------------------------------------------------------------ #

    async def _detect_protocol_downgrade(self, base: str, timeout: int) -> None:
        """Detect whether the server can be forced to downgrade from HTTPS to HTTP."""
        parsed = urlparse(base)
        if parsed.scheme != "https":
            return

        http_url = base.replace("https://", "http://", 1)
        try:
            async with httpx.AsyncClient(
                timeout=timeout, verify=False, follow_redirects=False
            ) as client:
                r = await client.get(http_url)

            # A 200 on plain HTTP is a downgrade risk
            if r.status_code == 200:
                hsts = r.headers.get("strict-transport-security", "")
                self.add_finding(
                    title="Protocol Downgrade – HTTP Accepted Without Redirect",
                    severity="high",
                    description=(
                        "The server responds with HTTP 200 to plain-HTTP requests "
                        "without redirecting to HTTPS. An active network attacker "
                        "can strip TLS and intercept all traffic. "
                        + ("HSTS header is absent." if not hsts else f"HSTS present: {hsts}")
                    ),
                    evidence=f"HTTP GET {http_url} → {r.status_code}",
                    url=http_url,
                    hsts_header=hsts,
                )
            elif r.status_code in (301, 302, 307, 308):
                location = r.headers.get("location", "")
                if location.startswith("http://"):
                    self.add_finding(
                        title="Protocol Downgrade – Redirect to HTTP",
                        severity="critical",
                        description=(
                            "The server redirects from HTTPS to HTTP, exposing "
                            "the entire session to interception."
                        ),
                        evidence=f"Location: {location}",
                        url=http_url,
                    )
        except Exception as exc:
            self.logger.debug("Downgrade probe error: %s", exc)

    # ------------------------------------------------------------------ #
    # HPACK bomb detection                                                 #
    # ------------------------------------------------------------------ #

    async def _test_hpack_bomb(self, base: str, timeout: int) -> None:
        """Probe for HPACK bomb vulnerability (CVE-2019-9512 / CVE-2019-9515).

        Sends a request with a large number of repeated header references that
        expand to a disproportionately large decompressed size.  A vulnerable
        server will either crash, reset the stream, or take an unusually long
        time to respond.
        """
        try:
            bomb_headers = {f"x-hpack-{i:04d}": "A" * 64 for i in range(200)}
            start = time.monotonic()
            async with httpx.AsyncClient(
                http2=True, timeout=timeout, verify=False
            ) as client:
                r = await client.get(base, headers=bomb_headers)
            elapsed = time.monotonic() - start

            if elapsed > timeout * 0.8:
                self.add_finding(
                    title="Potential HPACK Bomb Vulnerability (CVE-2019-9512)",
                    severity="high",
                    description=(
                        "The server took an unusually long time to respond to a "
                        "request with 200 inflated HPACK headers, suggesting it "
                        "may be vulnerable to HPACK-bomb denial-of-service attacks."
                    ),
                    evidence=(
                        f"Response time {elapsed:.2f}s with 200 synthetic headers; "
                        f"status={r.status_code}"
                    ),
                    url=base,
                    response_time_s=round(elapsed, 3),
                )
            elif r.status_code == 431:
                self.add_finding(
                    title="HPACK Bomb – Server Correctly Rejects Oversized Headers",
                    severity="info",
                    description=(
                        "The server returned HTTP 431 (Request Header Fields Too Large) "
                        "for an HPACK-bomb probe, indicating proper header-size limits."
                    ),
                    evidence=f"status={r.status_code}",
                    url=base,
                )
        except httpx.RemoteProtocolError as exc:
            self.add_finding(
                title="Potential HPACK Bomb – Server Reset Stream",
                severity="medium",
                description=(
                    "The server reset the HTTP/2 stream in response to a "
                    "large header block, which may indicate a parsing bug."
                ),
                evidence=str(exc),
                url=base,
            )
        except Exception as exc:
            self.logger.debug("HPACK bomb probe error: %s", exc)

    # ------------------------------------------------------------------ #
    # GraphQL introspection & fuzzing                                      #
    # ------------------------------------------------------------------ #

    async def _fuzz_graphql(
        self, base: str, path: str, timeout: int
    ) -> None:
        """Test GraphQL endpoint for introspection exposure and batch attacks."""
        url = base.rstrip("/") + path
        try:
            async with httpx.AsyncClient(
                http2=True, timeout=timeout, verify=False
            ) as client:
                # --- introspection ---
                r = await client.post(
                    url,
                    json={"query": _GRAPHQL_INTROSPECTION},
                    headers={"Content-Type": "application/json"},
                )
                if r.status_code == 200:
                    body = r.text
                    if "__schema" in body:
                        self.add_finding(
                            title="GraphQL Introspection Enabled",
                            severity="medium",
                            description=(
                                "The GraphQL endpoint allows unauthenticated "
                                "introspection queries, exposing the full schema "
                                "including all types, fields, and directives. "
                                "Attackers can use this to enumerate hidden "
                                "endpoints and craft targeted attacks."
                            ),
                            evidence=body[:500],
                            url=url,
                        )
                        self.logger.info("GraphQL introspection exposed at %s", url)

                    # --- batch query DoS probe ---
                    batch = [{"query": "{ __typename }"}] * 50
                    rb = await client.post(
                        url,
                        json=batch,
                        headers={"Content-Type": "application/json"},
                    )
                    if rb.status_code == 200 and isinstance(rb.json(), list):
                        self.add_finding(
                            title="GraphQL Batched Query Execution (DoS Risk)",
                            severity="medium",
                            description=(
                                "The server processes batched GraphQL queries "
                                "(an array of operation objects in a single POST). "
                                "Without rate limiting, an attacker can amplify "
                                "server load by sending thousands of queries per request."
                            ),
                            evidence=f"50-query batch returned {rb.status_code}",
                            url=url,
                        )

                elif r.status_code == 404:
                    self.logger.debug("No GraphQL endpoint at %s", url)

        except Exception as exc:
            self.logger.debug("GraphQL fuzz error at %s: %s", url, exc)

    # ------------------------------------------------------------------ #
    # gRPC reflection enumeration                                          #
    # ------------------------------------------------------------------ #

    async def _fuzz_grpc_reflection(
        self, host: str, port: int, timeout: int
    ) -> None:
        """Attempt gRPC server reflection to enumerate exposed services.

        Uses raw TCP with the gRPC HTTP/2 framing (no grpcio required).
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
        except (TimeoutError, OSError) as exc:
            self.logger.debug("gRPC connect %s:%s failed: %s", host, port, exc)
            return

        try:
            # Send HTTP/2 client preface + SETTINGS frame
            preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            settings_frame = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
            writer.write(preface + settings_frame)
            await writer.drain()

            # Read server response (up to 1 KB)
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)

            if data and b"HTTP/2" in data or data[:3] == b"\x00\x00":
                # gRPC server is responding with HTTP/2 frames
                self.add_finding(
                    title="gRPC Server Reflection Reachable",
                    severity="info",
                    description=(
                        f"A gRPC server is listening on {host}:{port} and "
                        "responded to the HTTP/2 client preface. "
                        "If server reflection is enabled, service methods and "
                        "message schemas can be enumerated without source code."
                    ),
                    evidence=f"Server replied with {len(data)} bytes to HTTP/2 preface",
                    url=f"grpc://{host}:{port}",
                )

                # Try to detect reflection service by sending a
                # ServerReflectionInfo request on stream 1
                # (grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo)
                reflection_payload = b"\n\x07\x0a\x00"  # list_services("")
                data_frame = (
                    struct.pack(">I", 3)[:3]  # 3-byte length prefix (big-endian)
                    + b"\x00"  # flags
                    + b"\x00\x00\x00\x01"  # stream ID = 1
                )
                writer.write(data_frame + reflection_payload)
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if resp and len(resp) > 9:
                    self.add_finding(
                        title="gRPC Server Reflection Enabled",
                        severity="medium",
                        description=(
                            "The gRPC server reflection API is enabled. Attackers "
                            "can enumerate all service names, method signatures, and "
                            "protobuf message structures without any credentials."
                        ),
                        evidence=f"Reflection response: {resp[:120].hex()}",
                        url=f"grpc://{host}:{port}",
                    )
        except TimeoutError:
            self.logger.debug("gRPC read timeout for %s:%s", host, port)
        except Exception as exc:
            self.logger.debug("gRPC probe error %s:%s: %s", host, port, exc)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # WebSocket fuzzing                                                    #
    # ------------------------------------------------------------------ #

    async def _fuzz_websocket(
        self, base: str, path: str, timeout: int
    ) -> None:
        """Fuzz WebSocket endpoint for origin bypass and message injection."""
        if not _WS_AVAILABLE:
            return

        ws_url = _ws_url(base.rstrip("/") + path)
        fuzz_messages = [
            '{"type":"__proto__","payload":"polluted"}',
            "<script>alert(1)</script>",
            "' OR '1'='1",
            "../../../etc/passwd",
            '{"action":"subscribe","channel":"admin"}',
        ]

        # Test 1: Connection without Origin header (cross-origin bypass)
        try:
            ssl_ctx: Any = False
            if ws_url.startswith("wss://"):
                import ssl as _ssl

                ssl_ctx = _ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = _ssl.CERT_NONE

            extra_headers = {}  # no Origin header
            async with websockets.connect(  # type: ignore[attr-defined]
                ws_url,
                ssl=ssl_ctx if ws_url.startswith("wss://") else None,
                additional_headers=extra_headers,
                open_timeout=timeout,
            ) as ws:
                self.add_finding(
                    title="WebSocket Accepts Connection Without Origin Header",
                    severity="medium",
                    description=(
                        "The WebSocket endpoint accepted a connection that did not "
                        "include an Origin header. Browsers always send Origin for "
                        "WebSocket upgrades; its absence suggests a server-side "
                        "client or a missing origin validation check, enabling "
                        "cross-site WebSocket hijacking."
                    ),
                    evidence=f"Connected to {ws_url} without Origin",
                    url=ws_url,
                )

                # Fuzz with malicious payloads
                vulnerable_msgs: list[str] = []
                for msg in fuzz_messages:
                    try:
                        await asyncio.wait_for(ws.send(msg), timeout=timeout)
                        reply = await asyncio.wait_for(ws.recv(), timeout=3)
                        if msg in str(reply):
                            vulnerable_msgs.append(msg)
                    except Exception:
                        pass

                if vulnerable_msgs:
                    self.add_finding(
                        title="WebSocket Message Reflection (Potential XSS/Injection)",
                        severity="high",
                        description=(
                            "The WebSocket endpoint reflected injected payload "
                            "content back in its response, indicating insufficient "
                            "input sanitisation. This may enable stored XSS or "
                            "server-side injection via WebSocket messages."
                        ),
                        evidence=f"Reflected payloads: {vulnerable_msgs[:3]}",
                        url=ws_url,
                    )

        except Exception as exc:
            self.logger.debug("WebSocket fuzz error %s: %s", ws_url, exc)

        # Test 2: Cross-origin connection with a spoofed Origin
        spoofed_origins = [
            "https://evil.example.com",
            "null",
            f"https://{urlparse(base).hostname}.evil.com",
        ]
        for origin in spoofed_origins:
            try:
                ssl_ctx2: Any = None
                if ws_url.startswith("wss://"):
                    import ssl as _ssl2

                    ssl_ctx2 = _ssl2.create_default_context()
                    ssl_ctx2.check_hostname = False
                    ssl_ctx2.verify_mode = _ssl2.CERT_NONE

                async with websockets.connect(  # type: ignore[attr-defined]
                    ws_url,
                    ssl=ssl_ctx2,
                    additional_headers={"Origin": origin},
                    open_timeout=timeout,
                ):
                    self.add_finding(
                        title="WebSocket Cross-Origin Hijacking Risk",
                        severity="high",
                        description=(
                            "The WebSocket endpoint accepted a connection from an "
                            f"untrusted origin '{origin}'. Without origin validation, "
                            "a malicious web page can initiate WebSocket connections "
                            "on behalf of a victim, stealing data or performing "
                            "actions using their session cookie."
                        ),
                        evidence=f"Connected from Origin: {origin}",
                        url=ws_url,
                        spoofed_origin=origin,
                    )
                    break
            except Exception:
                pass
