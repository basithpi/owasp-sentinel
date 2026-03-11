"""DNSX DNS enumeration tool wrapper."""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("owasp_sentinel.tools.dnsx")


class DnsxWrapper:
    """Wrapper for the ``dnsx`` DNS enumeration binary."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialise with optional config dict.

        Args:
            config: Optional overrides. Recognised keys:
                ``binary``   – path to dnsx executable (default ``dnsx``).
                ``timeout``  – subprocess timeout in seconds (default 300).
                ``rate``     – requests per second (default 100).
        """
        self.config: dict[str, Any] = config or {}
        self.binary: str = self.config.get("binary", "dnsx")
        self.timeout: int = int(self.config.get("timeout", 300))
        self.rate: int = int(self.config.get("rate", 100))

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Run dnsx against *target* (file path or single host).

        Args:
            target: Path to input file containing hosts, or single hostname.
            **kwargs: Runtime overrides.

        Returns:
            Dict with all DNS record types found.
        """
        import os

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            output_file = tmp.name

        if os.path.isfile(target):
            input_arg = ["-l", target]
        else:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as inp:
                inp.write(target + "\n")
                input_file = inp.name
            input_arg = ["-l", input_file]

        cmd = [
            self.binary,
            *input_arg,
            "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt",
            "-resp", "-json",
            "-o", output_file,
            "-rate", str(self.rate),
        ]
        logger.info("Running dnsx: %s", " ".join(cmd))
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            logger.error("dnsx timed out after %d seconds", self.timeout)
            return {"error": "timeout", "records": {}, "findings": []}
        except FileNotFoundError:
            logger.error("dnsx binary not found: %s", self.binary)
            return {"error": "binary_not_found", "records": {}, "findings": []}

        if stderr:
            logger.debug("dnsx stderr: %s", stderr.decode(errors="replace")[:500])

        try:
            output = Path(output_file).read_text(errors="replace")
        except OSError:
            output = stdout.decode(errors="replace")

        return self.parse_output(output)

    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse dnsx JSON output into structured DNS records.

        Args:
            output: Raw JSON-lines output from dnsx.

        Returns:
            Dict with ``records`` mapping hostname to record types,
            and ``findings`` list.
        """
        records: dict[str, dict[str, Any]] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = entry.get("host", "")
            if not host:
                continue

            if host not in records:
                records[host] = {"host": host}

            for rtype in ("a", "aaaa", "cname", "mx", "ns", "txt"):
                if rtype in entry:
                    records[host][rtype] = entry[rtype]

            for key in ("status_code", "resolver", "timestamp"):
                if key in entry:
                    records[host][key] = entry[key]

        findings = [
            {
                "title": f"DNS Records for {host}",
                "severity": "info",
                "description": f"DNS enumeration found records for {host}",
                "host": host,
                "records": data,
                "source": "dnsx",
            }
            for host, data in records.items()
        ]
        return {"records": records, "findings": findings}
