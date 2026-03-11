"""MapCIDR tool wrapper for CIDR range expansion and manipulation."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("owasp_sentinel.tools.mapcidr")


class MapcidrWrapper:
    """Wrapper for the mapcidr CIDR range expansion tool."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self.binary = self.config.get("binary", "mapcidr")
        self.timeout = int(self.config.get("timeout", 60))

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Expand a CIDR range or list of CIDRs into individual IPs.

        Args:
            target: CIDR notation string (e.g. '192.168.1.0/24') or comma-separated list.
            **kwargs: count_only (bool) — only count IPs without listing them.

        Returns:
            Dict with 'ips', 'count', and optional 'findings'.
        """
        count_only: bool = kwargs.get("count_only", False)
        # Try native Python first (no binary needed for simple expansion)
        try:
            results = self._expand_native(target)
            if count_only:
                return {"ips": [], "count": results["count"], "findings": []}
            return results
        except ValueError:
            pass

        # Fall back to mapcidr binary
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as fh:
            out_path = fh.name

        cmd = [self.binary, "-cidr", target, "-o", out_path]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            if proc.returncode != 0:
                logger.warning("mapcidr exited %s: %s", proc.returncode, stderr.decode())
            ips = Path(out_path).read_text().splitlines()
            return {"ips": [ip.strip() for ip in ips if ip.strip()], "count": len(ips), "findings": []}
        except FileNotFoundError:
            logger.warning("mapcidr binary not found; using Python fallback")
            return self._expand_native(target)
        except asyncio.TimeoutError:
            logger.error("mapcidr timed out after %ds", self.timeout)
            return {"ips": [], "count": 0, "findings": [], "error": "timeout"}
        finally:
            Path(out_path).unlink(missing_ok=True)

    def _expand_native(self, cidr_str: str) -> dict[str, Any]:
        """Pure-Python CIDR expansion."""
        ips: list[str] = []
        for cidr in cidr_str.split(","):
            network = ipaddress.ip_network(cidr.strip(), strict=False)
            ips.extend(str(ip) for ip in network.hosts())
        return {"ips": ips, "count": len(ips), "findings": []}

    def aggregate(self, cidrs: list[str]) -> list[str]:
        """Aggregate/summarise a list of CIDR blocks."""
        networks = [ipaddress.ip_network(c.strip(), strict=False) for c in cidrs]
        return [str(n) for n in ipaddress.collapse_addresses(networks)]
