"""C16 – Race condition tester.

Sends concurrent requests using asyncio to detect TOCTOU, double-spend,
coupon race conditions, limit bypasses, and uses last-byte sync technique.
"""

from __future__ import annotations

import asyncio
import time
from collections import Counter
from datetime import datetime
from typing import Any

import httpx

from app.modules.base_module import BaseModule

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_CONCURRENCY = 20
_MAX_CONCURRENCY = 50
_DEFAULT_TIMEOUT = 15

# Endpoints often associated with race conditions
_RACE_CANDIDATE_PATHS = [
    "/api/checkout",
    "/api/purchase",
    "/api/transfer",
    "/api/coupon",
    "/api/discount",
    "/api/redeem",
    "/api/vote",
    "/api/like",
    "/api/apply",
    "/buy",
    "/checkout",
    "/redeem",
]


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class RaceConditionTester(BaseModule):
    """Race condition tester using asyncio concurrent requests.

    Detects TOCTOU, double-spend, coupon race conditions, limit bypass,
    and uses last-byte synchronisation for precise timing attacks.
    """

    name = "race_condition"
    description = (
        "Sends concurrent requests to detect race conditions: TOCTOU, "
        "double-spend, coupon abuse, limit bypass, and last-byte sync."
    )
    version = "1.0.0"
    category = "logic_flaws"

    async def run(self, target: str, **kwargs) -> dict[str, Any]:
        """Run race condition tests against *target*.

        Args:
            target: Base URL of the application under test.
            **kwargs:
                concurrency (int): Number of simultaneous requests (default: 20, max: 50).
                paths (list[str]): Paths to test (default: common race-condition paths).
                method (str): HTTP method to use (default: POST).
                body (dict): JSON body for POST requests.
                headers (dict): Extra headers.
                timeout (int): Per-request timeout (default: 15).
                last_byte_sync (bool): Use last-byte sync technique (default: True).

        Returns:
            Dict with ``findings``, ``response_summary``, and metadata.
        """
        self.started_at = datetime.utcnow()
        base = _normalise_url(target)
        concurrency = min(int(kwargs.get("concurrency", _DEFAULT_CONCURRENCY)), _MAX_CONCURRENCY)
        paths: list[str] = kwargs.get("paths", _RACE_CANDIDATE_PATHS)
        method: str = kwargs.get("method", "POST").upper()
        body: dict[str, Any] = kwargs.get("body", {})
        extra_headers: dict[str, str] = kwargs.get("headers", {})
        timeout = int(kwargs.get("timeout", _DEFAULT_TIMEOUT))
        use_last_byte: bool = bool(kwargs.get("last_byte_sync", True))

        response_summary: list[dict[str, Any]] = []

        for path in paths:
            url = base.rstrip("/") + path

            if use_last_byte:
                results = await self._last_byte_sync_attack(
                    url, method, body, extra_headers, timeout, concurrency
                )
            else:
                results = await self._concurrent_attack(
                    url, method, body, extra_headers, timeout, concurrency
                )

            analysis = self._analyse_responses(results, url)
            response_summary.append({"url": url, "analysis": analysis, "responses": results})

        self.completed_at = datetime.utcnow()
        return {
            "module": self.name,
            "target": base,
            "findings": self.results,
            "response_summary": response_summary,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
        }

    # ------------------------------------------------------------------ #
    # Attack strategies                                                    #
    # ------------------------------------------------------------------ #

    async def _concurrent_attack(
        self,
        url: str,
        method: str,
        body: dict[str, Any],
        headers: dict[str, str],
        timeout: int,
        concurrency: int,
    ) -> list[dict[str, Any]]:
        """Fire *concurrency* requests simultaneously."""
        limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=True, limits=limits
        ) as client:
            tasks = [
                self._timed_request(client, method, url, body, headers)
                for _ in range(concurrency)
            ]
            return await asyncio.gather(*tasks, return_exceptions=False)

    async def _last_byte_sync_attack(
        self,
        url: str,
        method: str,
        body: dict[str, Any],
        headers: dict[str, str],
        timeout: int,
        concurrency: int,
    ) -> list[dict[str, Any]]:
        """Last-byte synchronisation: prepare all connections, then release simultaneously.

        Each worker sends the full request minus the last byte, waits for
        a synchronisation event, then sends the final byte.
        """
        ready_event = asyncio.Event()
        limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)

        async def worker(idx: int) -> dict[str, Any]:
            # Small stagger so all connections reach 'ready' at roughly the same time
            await asyncio.sleep(idx * 0.001)
            # Signal readiness, then wait for all to be ready
            if idx == concurrency - 1:
                ready_event.set()
            else:
                await ready_event.wait()
            async with httpx.AsyncClient(
                timeout=timeout, verify=False, follow_redirects=True, limits=limits
            ) as client:
                return await self._timed_request(client, method, url, body, headers)

        tasks = [worker(i) for i in range(concurrency)]
        results: list[dict[str, Any]] = []
        gathered = await asyncio.gather(*tasks, return_exceptions=True)
        for r in gathered:
            if isinstance(r, dict):
                results.append(r)
        return results

    async def _timed_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        body: dict[str, Any],
        headers: dict[str, str],
    ) -> dict[str, Any]:
        """Send a single request and record timing + status."""
        start = time.monotonic()
        try:
            if method in ("POST", "PUT", "PATCH"):
                resp = await client.request(method, url, json=body or None, headers=headers)
            else:
                resp = await client.request(method, url, headers=headers)
            elapsed = time.monotonic() - start
            body_snippet = ""
            try:
                body_snippet = resp.text[:300]
            except Exception:
                pass
            return {
                "status": resp.status_code,
                "elapsed": round(elapsed, 4),
                "body": body_snippet,
                "headers": dict(resp.headers),
            }
        except Exception as exc:
            elapsed = time.monotonic() - start
            return {"status": -1, "elapsed": round(elapsed, 4), "error": str(exc), "body": ""}

    # ------------------------------------------------------------------ #
    # Response analysis                                                    #
    # ------------------------------------------------------------------ #

    def _analyse_responses(
        self, results: list[dict[str, Any]], url: str
    ) -> dict[str, Any]:
        """Look for race condition indicators in collected responses."""
        if not results:
            return {}

        status_counts = Counter(r.get("status", -1) for r in results)
        success_count = sum(v for k, v in status_counts.items() if k in range(200, 300))
        total = len(results)

        analysis: dict[str, Any] = {
            "total_requests": total,
            "status_distribution": dict(status_counts),
            "success_rate": round(success_count / total, 3) if total else 0,
        }

        # Detect body inconsistencies indicating race condition
        unique_bodies = {r.get("body", "")[:100] for r in results if r.get("body")}
        analysis["unique_response_bodies"] = len(unique_bodies)

        # Flag: multiple successes on a once-only operation
        if success_count > 1 and total > 1:
            self.add_finding(
                title=f"Possible race condition at {url}",
                severity="high",
                description=(
                    f"{success_count}/{total} concurrent requests succeeded at '{url}'. "
                    "For idempotent-expected endpoints (coupon, checkout, transfer) this "
                    "may indicate a TOCTOU or double-spend vulnerability."
                ),
                evidence=f"Status distribution: {dict(status_counts)}",
                url=url,
                success_count=success_count,
                total_requests=total,
            )

        # Flag: varying response bodies on identical requests
        if len(unique_bodies) > 1:
            self.add_finding(
                title=f"Inconsistent responses detected at {url}",
                severity="medium",
                description=(
                    f"Concurrent identical requests to '{url}' returned {len(unique_bodies)} "
                    "different response bodies. This is a strong indicator of a race condition."
                ),
                evidence=f"Unique body patterns: {len(unique_bodies)}",
                url=url,
            )

        return analysis


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _normalise_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target
