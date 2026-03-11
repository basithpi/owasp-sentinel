"""GoSpider web crawler wrapper.

Spawns the ``gospider`` binary as a subprocess and parses its output into
structured URL/endpoint findings.
"""

from __future__ import annotations

import asyncio
import logging
import re
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("owasp_sentinel.tools.gospider")

# Regex patterns for output parsing
_URL_RE = re.compile(r"\[url\]\s*-\s*\[(\d+)\]\s*-\s*(https?://\S+)", re.IGNORECASE)
_JS_RE = re.compile(r"\[javascript\]\s*-\s*(https?://\S+)", re.IGNORECASE)
_FORM_RE = re.compile(r"\[form\]\s*-\s*(https?://\S+)", re.IGNORECASE)
_LINKFINDER_RE = re.compile(r"\[linkfinder\]\s*-\s*\[from\]\s*-\s*(https?://\S+)\s*-\s*(https?://\S+)", re.IGNORECASE)
_ROBOTS_RE = re.compile(r"\[robots\]\s*-\s*(https?://\S+)", re.IGNORECASE)


class GospiderWrapper:
    """Wrapper for the ``gospider`` web crawler binary."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialise with optional config dict.

        Args:
            config: Optional overrides.  Recognised keys:
                ``binary``       – path to the gospider executable (default ``gospider``).
                ``concurrency``  – concurrent requests (default 5).
                ``depth``        – crawl depth (default 3).
                ``timeout``      – subprocess timeout in seconds (default 300).
                ``user_agent``   – custom User-Agent header.
                ``cookie``       – Cookie header to send with requests.
                ``blacklist``    – list of URL regex patterns to ignore.
        """
        self.config: dict[str, Any] = config or {}
        self.binary: str = self.config.get("binary", "gospider")
        self.concurrency: int = int(self.config.get("concurrency", 5))
        self.depth: int = int(self.config.get("depth", 3))
        self.timeout: int = int(self.config.get("timeout", 300))

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Crawl *target* with gospider and return structured findings.

        Args:
            target: The starting URL to spider.
            **kwargs: Runtime overrides for ``concurrency``, ``depth``.

        Returns:
            Dictionary with keys ``urls``, ``js_files``, ``forms``,
            ``endpoints``, ``findings``.
        """
        concurrency = int(kwargs.get("concurrency", self.concurrency))
        depth = int(kwargs.get("depth", self.depth))

        with tempfile.TemporaryDirectory() as output_dir:
            cmd = [
                self.binary,
                "-s", target,
                "-o", output_dir,
                "-c", str(concurrency),
                "-d", str(depth),
                "--no-redirect",
                "--json",
            ]
            user_agent = self.config.get("user_agent") or kwargs.get("user_agent")
            if user_agent:
                cmd.extend(["-a", user_agent])
            cookie = self.config.get("cookie") or kwargs.get("cookie")
            if cookie:
                cmd.extend(["--cookie", cookie])

            logger.info("Running gospider: %s", " ".join(cmd))
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                logger.error("gospider timed out after %d seconds", self.timeout)
                return {"error": "timeout", "findings": []}
            except FileNotFoundError:
                logger.error("gospider binary not found: %s", self.binary)
                return {"error": "binary_not_found", "findings": []}

            output = stdout.decode(errors="replace")
            if stderr:
                logger.debug("gospider stderr: %s", stderr.decode(errors="replace")[:500])

            # Also read any output files written to the temp dir
            extra_output: list[str] = []
            for path in Path(output_dir).rglob("*"):
                if path.is_file():
                    try:
                        extra_output.append(path.read_text(errors="replace"))
                    except OSError:
                        pass

            combined = output + "\n".join(extra_output)
            return self.parse_output(combined)

    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse gospider stdout into structured findings.

        Args:
            output: Raw text output from the gospider process.

        Returns:
            Dictionary with ``urls``, ``js_files``, ``forms``,
            ``endpoints``, and ``findings`` lists.
        """
        urls: list[dict[str, Any]] = []
        js_files: list[str] = []
        forms: list[str] = []
        endpoints: list[str] = []

        for match in _URL_RE.finditer(output):
            status_code, url = match.group(1), match.group(2)
            urls.append({"url": url, "status_code": int(status_code)})
            endpoints.append(url)

        for match in _JS_RE.finditer(output):
            js_files.append(match.group(1))

        for match in _FORM_RE.finditer(output):
            forms.append(match.group(1))

        for match in _LINKFINDER_RE.finditer(output):
            endpoints.append(match.group(2))

        for match in _ROBOTS_RE.finditer(output):
            endpoints.append(match.group(1))

        findings = [
            {
                "title": "Discovered Endpoint",
                "severity": "info",
                "description": f"gospider discovered endpoint: {ep}",
                "url": ep,
                "source": "gospider",
            }
            for ep in set(endpoints)
        ]

        return {
            "urls": urls,
            "js_files": list(set(js_files)),
            "forms": list(set(forms)),
            "endpoints": list(set(endpoints)),
            "findings": findings,
        }
