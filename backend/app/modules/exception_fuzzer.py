"""C11 – Exception / Error-boundary fuzzer.

Tests error-handling boundaries with invalid inputs, extracts stack traces,
detects fail-open logic, integer overflow, type confusion, null byte injection,
and malformed encoding attacks.
"""

from __future__ import annotations

import asyncio
import math
import re
from datetime import datetime
from typing import Any, Dict
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from app.modules.base_module import BaseModule

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INT_OVERFLOW_VALUES = [
    2**31 - 1,   # INT32_MAX
    2**31,       # INT32 overflow
    -(2**31),    # INT32_MIN
    -1,
    0,
    2**63 - 1,   # INT64_MAX
    2**63,       # INT64 overflow
    -(2**63),    # INT64_MIN
    2**32,       # UINT32 overflow
]

SPECIAL_CHAR_PAYLOADS = [
    "' OR '1'='1",
    "<script>alert(1)</script>",
    "$(whoami)",
    "; ls -la",
    "../../etc/passwd",
    "{}[]|&^%$#@!",
    "\x00\x01\x02\x03\x04\x05",
    "𝕳𝖊𝖑𝖑𝖔",  # Unicode mathematical bold
    "\u202e\u200b\u200c\u200d",  # Invisible / directional chars
]

NULL_BYTE_PAYLOADS = [
    "%00",
    "\x00",
    "\u0000",
    "test%00.jpg",
    "admin%00@evil.com",
    "../../../../etc/passwd%00",
    "file\x00.php",
]

MALFORMED_ENCODING_PAYLOADS = [
    "\xff\xfe",            # UTF-16 LE BOM
    "\xfe\xff",            # UTF-16 BE BOM
    "\xef\xbb\xbf",        # UTF-8 BOM
    "\xff\xff\xff\xff",    # Invalid UTF-8 sequence
    "\xc0\xaf",            # Overlong encoding of '/'
    "\xe0\x80\xaf",        # Overlong encoding (3-byte)
    "test\xed\xa0\x80",   # UTF-16 surrogate in UTF-8
]

TYPE_CONFUSION_PAYLOADS = [
    # (content_type, body) pairs
    ("application/json", '{"id": "string_not_int"}'),
    ("application/json", '{"id": [1, 2, 3]}'),
    ("application/json", '{"id": {"nested": true}}'),
    ("application/json", '{"id": null}'),
    ("application/json", '{"id": true}'),
    ("application/json", '{"count": "999999999999999999999999"}'),
    ("application/json", '{"data": [[[[[[[[[[[[[]]]]]]]]]]]]]}'),
]

VERY_LONG_STRING = "A" * 100_000
VERY_LONG_HEADER = "X" * 8192

# Stack trace patterns keyed by platform
_TRACEBACK_PATTERNS = {
    "Python": [
        re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
        re.compile(r'File "[^"]+", line \d+', re.IGNORECASE),
        re.compile(r"(SyntaxError|TypeError|ValueError|AttributeError|KeyError|IndexError):", re.IGNORECASE),
    ],
    "Java": [
        re.compile(r"at [\w$.]+\([\w$.]+\.java:\d+\)", re.IGNORECASE),
        re.compile(r"java\.lang\.\w+Exception", re.IGNORECASE),
        re.compile(r"org\.springframework", re.IGNORECASE),
    ],
    "PHP": [
        re.compile(r"Fatal error:|Warning:|Parse error:", re.IGNORECASE),
        re.compile(r"in /[\w/.]+ on line \d+", re.IGNORECASE),
        re.compile(r"Stack trace:", re.IGNORECASE),
    ],
    "Ruby": [
        re.compile(r"\.rb:\d+:in `", re.IGNORECASE),
        re.compile(r"ActionController|ActiveRecord", re.IGNORECASE),
        re.compile(r"NoMethodError|NameError|ArgumentError", re.IGNORECASE),
    ],
    "Node.js": [
        re.compile(r"at Object\.<anonymous> \(", re.IGNORECASE),
        re.compile(r"at Module\._compile", re.IGNORECASE),
        re.compile(r"(ReferenceError|TypeError|SyntaxError):", re.IGNORECASE),
    ],
    "ASP.NET": [
        re.compile(r"System\.(Web|MVC|Net)\.", re.IGNORECASE),
        re.compile(r"at System\.", re.IGNORECASE),
        re.compile(r"Server Error in '/'", re.IGNORECASE),
    ],
}

VERBOSE_ERROR_PATTERNS = [
    re.compile(r"(error|exception|warning|fatal|critical|fail)", re.IGNORECASE),
    re.compile(r"sql syntax|mysql_fetch|pg_query|sqlite", re.IGNORECASE),
    re.compile(r"undefined (variable|index|method|function)", re.IGNORECASE),
    re.compile(r"division by zero|null pointer|null reference", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class ExceptionFuzzer(BaseModule):
    """Error-boundary fuzzer: tests invalid inputs, overflow, type confusion,
    null bytes, encoding attacks, and catalogues verbose error responses."""

    name = "exception_fuzzer"
    description = (
        "Tests error-handling boundaries via integer overflow, type confusion, "
        "null byte injection, malformed encoding, and analyses stack traces in responses."
    )
    version = "1.0.0"
    category = "fuzzing"

    # ------------------------------------------------------------------ #
    # Public entry-point                                                   #
    # ------------------------------------------------------------------ #

    async def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Fuzz error boundaries on *target*.

        Args:
            target: Base URL of the application under test.
            **kwargs:
                paths (list[str]): Specific paths to fuzz (default: common).
                timeout (int): Per-request timeout in seconds (default: 10).
                concurrency (int): Max parallel requests (default: 10).

        Returns:
            Dict with ``findings``, ``verbose_errors``, and summary metadata.
        """
        self.started_at = datetime.utcnow()
        base = _normalise_url(target)
        timeout = int(kwargs.get("timeout", 10))
        concurrency = min(int(kwargs.get("concurrency", 10)), 50)
        paths: list[str] = kwargs.get("paths", ["/"]) or ["/"]
        verbose_errors: list[dict[str, Any]] = []

        limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
        async with httpx.AsyncClient(
            base_url=base,
            timeout=timeout,
            verify=False,
            follow_redirects=True,
            limits=limits,
        ) as client:
            sem = asyncio.Semaphore(concurrency)
            tasks = []
            for path in paths:
                tasks += [
                    self._fuzz_integers(client, path, sem),
                    self._fuzz_special_chars(client, path, sem),
                    self._fuzz_null_bytes(client, path, sem),
                    self._fuzz_encoding(client, path, sem),
                    self._fuzz_type_confusion(client, path, sem),
                    self._fuzz_long_input(client, path, sem),
                ]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Flatten verbose error catalogue
        for batch in batch_results:
            if isinstance(batch, list):
                verbose_errors.extend(batch)

        self.completed_at = datetime.utcnow()
        return {
            "module": self.name,
            "target": base,
            "findings": self.results,
            "verbose_errors": verbose_errors,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
        }

    # ------------------------------------------------------------------ #
    # Fuzzing helpers                                                      #
    # ------------------------------------------------------------------ #

    async def _fuzz_integers(
        self, client: httpx.AsyncClient, path: str, sem: asyncio.Semaphore
    ) -> list[dict[str, Any]]:
        """Send integer overflow / underflow values as query-param ``id``."""
        errors: list[dict[str, Any]] = []
        for val in INT_OVERFLOW_VALUES:
            url = f"{path}?id={val}"
            resp = await _safe_request(client, "GET", url, sem)
            if resp is None:
                continue
            errors += self._analyse_response(resp, url, f"integer_overflow:{val}")
            self._check_fail_open(resp, url, f"Integer overflow ({val})")
        return errors

    async def _fuzz_special_chars(
        self, client: httpx.AsyncClient, path: str, sem: asyncio.Semaphore
    ) -> list[dict[str, Any]]:
        """Send special-character payloads as query-param ``q``."""
        errors: list[dict[str, Any]] = []
        for payload in SPECIAL_CHAR_PAYLOADS:
            url = f"{path}?q={payload}"
            resp = await _safe_request(client, "GET", url, sem)
            if resp is None:
                continue
            errors += self._analyse_response(resp, url, f"special_chars:{payload[:30]}")
            self._check_fail_open(resp, url, f"Special char ({payload[:30]})")
        return errors

    async def _fuzz_null_bytes(
        self, client: httpx.AsyncClient, path: str, sem: asyncio.Semaphore
    ) -> list[dict[str, Any]]:
        """Inject null-byte variations into query parameters and POST bodies."""
        errors: list[dict[str, Any]] = []
        for payload in NULL_BYTE_PAYLOADS:
            # GET param
            url = f"{path}?file={payload}"
            resp = await _safe_request(client, "GET", url, sem)
            if resp:
                errors += self._analyse_response(resp, url, f"null_byte_GET:{payload!r}")
            # POST body
            resp2 = await _safe_request(
                client, "POST", path, sem,
                content=payload.encode("utf-8", errors="surrogateescape"),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp2:
                errors += self._analyse_response(resp2, path, f"null_byte_POST:{payload!r}")
        return errors

    async def _fuzz_encoding(
        self, client: httpx.AsyncClient, path: str, sem: asyncio.Semaphore
    ) -> list[dict[str, Any]]:
        """Send malformed encoding payloads in request bodies."""
        errors: list[dict[str, Any]] = []
        for payload in MALFORMED_ENCODING_PAYLOADS:
            resp = await _safe_request(
                client, "POST", path, sem,
                content=payload.encode("latin-1"),
                headers={"Content-Type": "text/plain; charset=utf-8"},
            )
            if resp:
                errors += self._analyse_response(resp, path, f"encoding:{payload!r}")
        return errors

    async def _fuzz_type_confusion(
        self, client: httpx.AsyncClient, path: str, sem: asyncio.Semaphore
    ) -> list[dict[str, Any]]:
        """POST type-confusion payloads and look for unhandled exceptions."""
        errors: list[dict[str, Any]] = []
        for ct, body in TYPE_CONFUSION_PAYLOADS:
            resp = await _safe_request(
                client, "POST", path, sem,
                content=body.encode(),
                headers={"Content-Type": ct},
            )
            if resp:
                errors += self._analyse_response(resp, path, f"type_confusion:{body[:40]}")
        return errors

    async def _fuzz_long_input(
        self, client: httpx.AsyncClient, path: str, sem: asyncio.Semaphore
    ) -> list[dict[str, Any]]:
        """Send extremely long strings in query params and headers."""
        errors: list[dict[str, Any]] = []
        # Long query param
        url = f"{path}?q={VERY_LONG_STRING}"
        resp = await _safe_request(client, "GET", url, sem)
        if resp:
            errors += self._analyse_response(resp, url, "long_string_GET")
        # Long header
        resp2 = await _safe_request(
            client, "GET", path, sem,
            headers={"X-Custom": VERY_LONG_HEADER},
        )
        if resp2:
            errors += self._analyse_response(resp2, path, "long_header")
        return errors

    # ------------------------------------------------------------------ #
    # Analysis helpers                                                     #
    # ------------------------------------------------------------------ #

    def _analyse_response(
        self, resp: httpx.Response, url: str, tag: str
    ) -> list[dict[str, Any]]:
        """Extract stack traces and verbose error messages from *resp*."""
        collected: list[dict[str, Any]] = []
        text = ""
        try:
            text = resp.text
        except Exception:
            return collected

        # Stack-trace detection
        for platform, patterns in _TRACEBACK_PATTERNS.items():
            matched = [p.search(text) for p in patterns]
            if sum(1 for m in matched if m) >= 2:
                snippet = _extract_snippet(text, matched[0].start() if matched[0] else 0)
                self.add_finding(
                    title=f"Stack trace exposed ({platform})",
                    severity="high",
                    description=(
                        f"A {platform} stack trace was found in the response to "
                        f"payload tag '{tag}'. This exposes internal application "
                        f"paths and logic."
                    ),
                    evidence=snippet,
                    url=url,
                    platform=platform,
                    payload_tag=tag,
                )
                collected.append({"url": url, "platform": platform, "tag": tag, "snippet": snippet})

        # Verbose error messages (not necessarily stack traces)
        for pattern in VERBOSE_ERROR_PATTERNS:
            m = pattern.search(text)
            if m:
                snippet = _extract_snippet(text, m.start())
                collected.append({"url": url, "pattern": pattern.pattern, "tag": tag, "snippet": snippet})
                break

        return collected

    def _check_fail_open(self, resp: httpx.Response, url: str, label: str) -> None:
        """Detect fail-open logic: a 2xx response to a clearly invalid input."""
        if resp.status_code in range(200, 300):
            # Heuristic: if the response looks like an authenticated / privileged page
            text = ""
            try:
                text = resp.text.lower()
            except Exception:
                return
            access_indicators = [
                "welcome", "dashboard", "account", "profile",
                "admin", "success", "logged in", "authorized",
            ]
            for indicator in access_indicators:
                if indicator in text:
                    self.add_finding(
                        title="Possible fail-open logic detected",
                        severity="high",
                        description=(
                            f"The server returned HTTP {resp.status_code} with "
                            f"access-indicating content ('{indicator}') in response to "
                            f"an invalid/malformed input ({label}). This may indicate "
                            "fail-open error handling."
                        ),
                        evidence=f"Status: {resp.status_code}, indicator: '{indicator}'",
                        url=url,
                        payload_label=label,
                    )
                    break


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _normalise_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def _extract_snippet(text: str, pos: int, window: int = 500) -> str:
    start = max(0, pos - 50)
    end = min(len(text), pos + window)
    return text[start:end]


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
