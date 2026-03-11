"""C8 – CORS misconfiguration tester.

Tests for: origin reflection, null origin bypass, subdomain wildcard trust,
pre-flight analysis, CORS+CSRF chains, and Access-Control-Allow-Credentials
misconfigurations.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from app.modules.base_module import BaseModule

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CORS_HEADERS = [
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "access-control-max-age",
    "vary",
]

# Templates used to build attacker/test origins
_ORIGIN_TESTS: list[dict[str, str]] = [
    {"label": "arbitrary_origin",        "template": "https://evil.example.com"},
    {"label": "null_origin",             "template": "null"},
    {"label": "subdomain_of_target",     "template": "https://evil.{host}"},
    {"label": "target_prefixed",         "template": "https://{host}.evil.com"},
    {"label": "target_suffixed",         "template": "https://not{host}"},
    {"label": "http_downgrade",          "template": "http://{host}"},
    {"label": "underscore_subdomain",    "template": "https://_.{host}"},
    {"label": "data_origin",             "template": "data://"},
    {"label": "xss_origin",             "template": 'https://{host}"<script>alert(1)</script>'},
]


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class CORSTester(BaseModule):
    """CORS misconfiguration tester."""

    name = "cors_tester"
    description = (
        "Test all CORS headers for origin reflection, null origin bypass, "
        "subdomain wildcard trust, pre-flight analysis, CORS+CSRF chain, "
        "and credential flag misconfiguration."
    )
    version = "1.0.0"
    category = "misconfiguration"

    # ------------------------------------------------------------------ #
    # Public entry-point                                                   #
    # ------------------------------------------------------------------ #

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Run all CORS tests against *target*.

        Args:
            target: Base URL of the target.
            **kwargs:
                - paths (List[str]): Paths to test (default ["/"]).
                - methods (List[str]): HTTP methods to pre-flight (default common set).
                - timeout (int): Timeout in seconds (default 10).
                - cookies (str): Cookie header to include (for CSRF chain test).
        """
        self.started_at = datetime.utcnow()
        base = target if target.startswith("http") else f"https://{target}"
        paths: list[str] = kwargs.get("paths", ["/", "/api", "/api/v1"])
        timeout: int = int(kwargs.get("timeout", 10))
        cookies: str = kwargs.get("cookies", "")

        parsed = urlparse(base)
        host = parsed.hostname or target

        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=True
        ) as client:
            for path in paths:
                url = base.rstrip("/") + path
                await asyncio.gather(
                    self._test_origin_reflection(client, url, host),
                    self._test_preflight(client, url, host, kwargs.get("methods")),
                    self._test_credentials_wildcard(client, url, host),
                    self._test_cors_csrf_chain(client, url, host, cookies),
                    return_exceptions=True,
                )

        self.completed_at = datetime.utcnow()
        return self.to_dict()

    # ------------------------------------------------------------------ #
    # Origin reflection                                                    #
    # ------------------------------------------------------------------ #

    async def _test_origin_reflection(
        self, client: httpx.AsyncClient, url: str, host: str
    ) -> None:
        """Test whether the server reflects arbitrary Origin values."""
        for entry in _ORIGIN_TESTS:
            label = entry["label"]
            origin = entry["template"].replace("{host}", host)

            r = await self._get_with_origin(client, url, origin)
            if r is None:
                continue

            acao = r.headers.get("access-control-allow-origin", "")
            acac = r.headers.get("access-control-allow-credentials", "").lower()
            cors_info = self._collect_cors_headers(r)

            if acao == origin:
                severity = "critical" if acac == "true" else "high"
                self.add_finding(
                    title=f"CORS Origin Reflection – {label}",
                    severity=severity,
                    description=(
                        f"The server reflects the supplied Origin header ({origin!r}) "
                        f"verbatim in Access-Control-Allow-Origin. "
                        + (
                            "Combined with Access-Control-Allow-Credentials: true, this "
                            "allows a malicious page to make authenticated cross-origin "
                            "requests and read the response (session hijacking risk)."
                            if acac == "true"
                            else "Without credentials enabled the impact is limited to "
                            "unauthenticated data exposure."
                        )
                    ),
                    evidence=self._format_cors_evidence(origin, cors_info),
                    url=url,
                    owasp_category="A05",
                    cwe="CWE-942",
                    cors_headers=cors_info,
                    tested_origin=origin,
                )
                self.logger.info("CORS reflection %s at %s (creds=%s)", label, url, acac)

            elif acao == "*" and acac == "true":
                self.add_finding(
                    title="CORS Wildcard + Credentials Enabled",
                    severity="critical",
                    description=(
                        "Access-Control-Allow-Origin: * combined with "
                        "Access-Control-Allow-Credentials: true is rejected by "
                        "browsers but indicates a server misconfiguration that may "
                        "work in non-browser contexts (e.g., mobile apps, curl-based tools)."
                    ),
                    evidence=self._format_cors_evidence(origin, cors_info),
                    url=url,
                    owasp_category="A05",
                    cwe="CWE-942",
                )

    # ------------------------------------------------------------------ #
    # Pre-flight analysis                                                  #
    # ------------------------------------------------------------------ #

    async def _test_preflight(
        self,
        client: httpx.AsyncClient,
        url: str,
        host: str,
        methods: list[str] | None,
    ) -> None:
        """Send OPTIONS pre-flight requests and analyse the response headers."""
        test_methods = methods or ["PUT", "DELETE", "PATCH", "CONNECT", "TRACE"]
        test_origin = f"https://evil.{host}"

        for method in test_methods:
            try:
                r = await client.options(
                    url,
                    headers={
                        "Origin": test_origin,
                        "Access-Control-Request-Method": method,
                        "Access-Control-Request-Headers": "Authorization, X-Custom-Header",
                    },
                )
                acao = r.headers.get("access-control-allow-origin", "")
                acam = r.headers.get("access-control-allow-methods", "")
                acah = r.headers.get("access-control-allow-headers", "")
                acac = r.headers.get("access-control-allow-credentials", "")

                if acao in (test_origin, "*") or method in acam:
                    severity = "high" if acac.lower() == "true" else "medium"
                    self.add_finding(
                        title=f"CORS Pre-flight Allows Dangerous Method – {method}",
                        severity=severity,
                        description=(
                            f"The pre-flight OPTIONS response for method {method} "
                            f"returned ACAO={acao!r} and ACAM={acam!r}. "
                            "Allowing dangerous methods (DELETE, PUT, TRACE) from "
                            "cross-origin requests can enable data manipulation and "
                            "HTTP response splitting attacks."
                        ),
                        evidence=(
                            f"Origin: {test_origin}\n"
                            f"ACAO: {acao}\nACAM: {acam}\n"
                            f"ACAH: {acah}\nACAC: {acac}"
                        ),
                        url=url,
                        owasp_category="A05",
                        allowed_method=method,
                    )
            except Exception as exc:
                self.logger.debug("Pre-flight %s error at %s: %s", method, url, exc)

    # ------------------------------------------------------------------ #
    # Wildcard + credentials misconfiguration                              #
    # ------------------------------------------------------------------ #

    async def _test_credentials_wildcard(
        self, client: httpx.AsyncClient, url: str, host: str
    ) -> None:
        """Check Access-Control-Allow-Credentials: true without a specific origin."""
        try:
            r = await client.get(url, headers={"Origin": f"https://{host}"})
            acac = r.headers.get("access-control-allow-credentials", "").lower()
            acao = r.headers.get("access-control-allow-origin", "")

            if acac == "true" and acao == "*":
                self.add_finding(
                    title="CORS – Credentials Allowed with Wildcard Origin",
                    severity="high",
                    description=(
                        "The response includes both Access-Control-Allow-Credentials: true "
                        "and Access-Control-Allow-Origin: *. Browsers block this combination, "
                        "but it indicates a server-side misconfiguration that could be "
                        "exploited by non-browser HTTP clients."
                    ),
                    evidence=f"ACAO: {acao}  ACAC: {acac}",
                    url=url,
                    owasp_category="A05",
                    cwe="CWE-942",
                )
        except Exception as exc:
            self.logger.debug("Credentials wildcard test error at %s: %s", url, exc)

    # ------------------------------------------------------------------ #
    # CORS + CSRF chain detection                                          #
    # ------------------------------------------------------------------ #

    async def _test_cors_csrf_chain(
        self, client: httpx.AsyncClient, url: str, host: str, cookies: str
    ) -> None:
        """Detect exploitable CORS+CSRF chain by making a state-changing cross-origin request."""
        state_changing_paths = [
            (url.rstrip("/") + "/password", "PUT"),
            (url.rstrip("/") + "/email", "PUT"),
            (url.rstrip("/") + "/account", "DELETE"),
            (url.rstrip("/") + "/profile", "PATCH"),
        ]
        attacker_origin = f"https://evil.{host}"
        for target_url, method in state_changing_paths:
            try:
                r = await client.request(
                    method,
                    target_url,
                    headers={
                        "Origin": attacker_origin,
                        "Content-Type": "application/json",
                        **({"Cookie": cookies} if cookies else {}),
                    },
                    json={"email": "attacker@evil.com", "password": "hacked"},
                )
                acao = r.headers.get("access-control-allow-origin", "")
                acac = r.headers.get("access-control-allow-credentials", "").lower()

                if acao == attacker_origin and acac == "true" and r.status_code < 400:
                    self.add_finding(
                        title=f"CORS + CSRF Chain – {method} {target_url}",
                        severity="critical",
                        description=(
                            f"A cross-origin {method} request from {attacker_origin!r} "
                            f"was accepted with credentials enabled (ACAO={acao}, ACAC=true). "
                            "A malicious web page can perform account takeover by "
                            "combining CORS misconfiguration with CSRF."
                        ),
                        evidence=(
                            f"{method} {target_url} with Origin={attacker_origin} "
                            f"→ {r.status_code}"
                        ),
                        url=target_url,
                        owasp_category="A05",
                        cwe="CWE-942",
                    )
            except Exception as exc:
                self.logger.debug("CORS+CSRF chain error at %s: %s", target_url, exc)

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    async def _get_with_origin(
        self,
        client: httpx.AsyncClient,
        url: str,
        origin: str,
    ) -> httpx.Response | None:
        """GET request with specified Origin header; returns response or None on error."""
        try:
            return await client.get(url, headers={"Origin": origin})
        except Exception as exc:
            self.logger.debug("GET %s with Origin=%s failed: %s", url, origin, exc)
            return None

    def _collect_cors_headers(self, response: httpx.Response) -> dict[str, str]:
        """Extract all CORS-related headers from a response."""
        return {h: response.headers.get(h, "") for h in _CORS_HEADERS if response.headers.get(h)}

    @staticmethod
    def _format_cors_evidence(origin: str, headers: dict[str, str]) -> str:
        lines = [f"Origin tested: {origin}"]
        lines.extend(f"{k}: {v}" for k, v in headers.items())
        return "\n".join(lines)
