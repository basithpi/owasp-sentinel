"""ASNMap tool wrapper for ASN-to-IP-range mapping."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

logger = logging.getLogger("owasp_sentinel.tools.asnmap")


class AsnmapWrapper:
    """Wrapper for the asnmap ASN-to-IP-range mapping tool."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self.binary = self.config.get("binary", "asnmap")
        self.timeout = int(self.config.get("timeout", 60))

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Map an ASN, organisation name, or IP to CIDR ranges.

        Args:
            target: ASN (e.g. 'AS15169'), org name ('Google LLC'), or IP address.

        Returns:
            Dict with 'ranges' list and 'asn_info'.
        """
        if target.upper().startswith("AS") and target[2:].isdigit():
            args = [self.binary, "-a", target, "-json"]
        elif "." in target or ":" in target:
            # IP address — reverse lookup
            args = [self.binary, "-i", target, "-json"]
        else:
            args = [self.binary, "-org", target, "-json"]

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            if proc.returncode != 0:
                logger.warning("asnmap returned %s: %s", proc.returncode, stderr.decode())
            return self.parse_output(stdout.decode())
        except FileNotFoundError:
            logger.warning("asnmap binary not found; trying RDAP fallback")
            return await self._rdap_fallback(target)
        except asyncio.TimeoutError:
            return {"ranges": [], "asn_info": {}, "error": "timeout"}

    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse asnmap JSON output."""
        ranges: list[str] = []
        asn_info: dict[str, Any] = {}
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if "cidr" in obj:
                    ranges.append(obj["cidr"])
                if "asn" in obj and not asn_info:
                    asn_info = {"asn": obj.get("asn"), "org": obj.get("org"), "country": obj.get("country")}
            except json.JSONDecodeError:
                if "/" in line:
                    ranges.append(line)
        return {"ranges": ranges, "count": len(ranges), "asn_info": asn_info}

    async def reverse_lookup(self, ip: str) -> dict[str, Any]:
        """Get ASN information for an IP address."""
        return await self.run(ip)

    async def _rdap_fallback(self, target: str) -> dict[str, Any]:
        """Use RDAP API as fallback when binary is unavailable."""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=15) as client:
                url = f"https://rdap.arin.net/registry/ip/{target}"
                resp = await client.get(url)
                data = resp.json()
                cidrs = []
                for net in data.get("networks", []):
                    cidrs.append(net.get("startAddress", ""))
                return {
                    "ranges": cidrs,
                    "count": len(cidrs),
                    "asn_info": {"org": data.get("name", ""), "country": ""},
                    "source": "rdap_fallback",
                }
        except Exception as exc:
            logger.debug("RDAP fallback failed: %s", exc)
            return {"ranges": [], "count": 0, "asn_info": {}, "error": str(exc)}
