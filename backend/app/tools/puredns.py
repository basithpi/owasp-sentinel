"""PureDNS subdomain resolver/bruteforcer wrapper."""

from __future__ import annotations

import asyncio
import logging
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("owasp_sentinel.tools.puredns")


class PurednsWrapper:
    """Wrapper for the ``puredns`` DNS resolver/bruteforcer binary."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialise with optional config dict.

        Args:
            config: Optional overrides. Recognised keys:
                ``binary``          – path to puredns executable (default ``puredns``).
                ``resolvers``       – path to resolvers file.
                ``wildcard_tests``  – number of wildcard tests (default 3).
                ``timeout``         – subprocess timeout in seconds (default 600).
        """
        self.config: dict[str, Any] = config or {}
        self.binary: str = self.config.get("binary", "puredns")
        self.resolvers: str = self.config.get("resolvers", "/etc/puredns/resolvers.txt")
        self.wildcard_tests: int = int(self.config.get("wildcard_tests", 3))
        self.timeout: int = int(self.config.get("timeout", 600))

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Resolve a wordlist against *target* domain.

        Args:
            target: Target domain to resolve against.
            **kwargs: Runtime overrides – ``wordlist``, ``resolvers``.

        Returns:
            Dict with ``subdomains`` list and ``findings`` list.
        """
        wordlist: str = kwargs.get("wordlist", "")
        if not wordlist:
            return {"error": "wordlist_required", "subdomains": [], "findings": []}
        return await self._run_resolve(wordlist, target, kwargs.get("resolvers", self.resolvers))

    async def _run_resolve(self, wordlist: str, domain: str, resolvers: str) -> dict[str, Any]:
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            output_file = tmp.name

        cmd = [
            self.binary, "resolve", wordlist,
            "-r", resolvers,
            "-w", output_file,
            "--wildcard-tests", str(self.wildcard_tests),
        ]
        logger.info("Running puredns: %s", " ".join(cmd))
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            logger.error("puredns timed out after %d seconds", self.timeout)
            return {"error": "timeout", "subdomains": [], "findings": []}
        except FileNotFoundError:
            logger.error("puredns binary not found: %s", self.binary)
            return {"error": "binary_not_found", "subdomains": [], "findings": []}

        output = stdout.decode(errors="replace")
        if stderr:
            logger.debug("puredns stderr: %s", stderr.decode(errors="replace")[:500])

        try:
            file_output = Path(output_file).read_text(errors="replace")
        except OSError:
            file_output = ""

        combined = output + "\n" + file_output
        return self.parse_output(combined)

    async def bruteforce(self, domain: str, wordlist: str, **kwargs: Any) -> dict[str, Any]:
        """Bruteforce subdomains for *domain* using *wordlist*.

        Args:
            domain: Target domain.
            wordlist: Path to wordlist file.
            **kwargs: Additional runtime overrides.

        Returns:
            Dict with ``subdomains`` and ``findings`` lists.
        """
        resolvers = kwargs.get("resolvers", self.resolvers)
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            output_file = tmp.name

        cmd = [
            self.binary, "bruteforce", wordlist, domain,
            "-r", resolvers,
            "-w", output_file,
            "--wildcard-tests", str(self.wildcard_tests),
        ]
        logger.info("Running puredns bruteforce: %s", " ".join(cmd))
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            logger.error("puredns bruteforce timed out")
            return {"error": "timeout", "subdomains": [], "findings": []}
        except FileNotFoundError:
            logger.error("puredns binary not found: %s", self.binary)
            return {"error": "binary_not_found", "subdomains": [], "findings": []}

        output = stdout.decode(errors="replace")
        try:
            file_output = Path(output_file).read_text(errors="replace")
        except OSError:
            file_output = ""

        return self.parse_output(output + "\n" + file_output)

    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse puredns output into structured findings.

        Args:
            output: Raw text output from puredns.

        Returns:
            Dict with ``subdomains`` list of ``{hostname, ip}`` dicts and ``findings``.
        """
        subdomains: list[dict[str, str]] = []
        seen: set[str] = set()

        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            hostname = parts[0]
            ip = parts[1] if len(parts) > 1 else ""
            if hostname not in seen:
                seen.add(hostname)
                subdomains.append({"hostname": hostname, "ip": ip})

        findings = [
            {
                "title": "Subdomain Discovered",
                "severity": "info",
                "description": f"Resolved subdomain: {s['hostname']} -> {s['ip']}",
                "host": s["hostname"],
                "ip": s["ip"],
                "source": "puredns",
            }
            for s in subdomains
        ]
        return {"subdomains": subdomains, "findings": findings}
