"""CDNCheck tool wrapper for CDN/WAF detection."""
from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("owasp_sentinel.tools.cdncheck")

# Known CDN header/response fingerprints for fallback detection
_CDN_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "Akamai": ["x-check-cacheable", "akamai", "x-akamai-transformed", "ak-cache-status"],
    "Fastly": ["x-served-by", "x-cache-hits", "fastly"],
    "CloudFront": ["x-amz-cf-id", "x-amz-cf-pop", "cloudfront"],
    "Azure CDN": ["x-azure-ref", "x-msedge-ref"],
    "Google CDN": ["x-goog-hash", "x-google-cache"],
    "Sucuri": ["x-sucuri-id", "sucuri-clientside"],
    "Incapsula": ["x-cdn", "incapsula", "visid_incap"],
    "StackPath": ["x-sp-url", "stackpath"],
}


class CdncheckWrapper:
    """Wrapper for the cdncheck CDN-detection tool."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self.binary = self.config.get("binary", "cdncheck")
        self.timeout = int(self.config.get("timeout", 60))

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Detect CDN provider for a host/IP.

        Args:
            target: Hostname or IP address (comma-separated for multiple).

        Returns:
            Dict with 'results' list of {host, cdn, confidence}.
        """
        hosts = [h.strip() for h in target.split(",") if h.strip()]

        # Try binary first
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as fh:
            fh.write("\n".join(hosts))
            in_path = fh.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            out_path = fh.name

        try:
            proc = await asyncio.create_subprocess_exec(
                self.binary, "-i", in_path, "-resp", "-json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            return self.parse_output(stdout.decode())
        except FileNotFoundError:
            logger.info("cdncheck binary not found; using HTTP header fallback")
            return await self._http_fallback(hosts)
        except asyncio.TimeoutError:
            return {"results": [], "error": "timeout"}
        finally:
            Path(in_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse cdncheck JSON-lines output."""
        results: list[dict[str, Any]] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                results.append({
                    "host": obj.get("host", ""),
                    "cdn": obj.get("cdn", "unknown"),
                    "confidence": "high",
                })
            except json.JSONDecodeError:
                # plain text: "host [CDN]"
                parts = line.split()
                if parts:
                    results.append({"host": parts[0], "cdn": parts[-1] if len(parts) > 1 else "unknown", "confidence": "medium"})
        return {"results": results, "count": len(results)}

    async def _http_fallback(self, hosts: list[str]) -> dict[str, Any]:
        """Detect CDN via HTTP response headers."""
        try:
            import httpx
        except ImportError:
            return {"results": [], "error": "httpx not available"}

        results: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            for host in hosts:
                url = host if host.startswith("http") else f"https://{host}"
                try:
                    resp = await client.get(url)
                    detected = self._detect_from_headers(dict(resp.headers))
                    results.append({"host": host, "cdn": detected or "none", "confidence": "medium" if detected else "low"})
                except Exception as exc:
                    logger.debug("CDN fallback check failed for %s: %s", host, exc)
                    results.append({"host": host, "cdn": "unknown", "confidence": "low", "error": str(exc)})
        return {"results": results, "count": len(results)}

    def _detect_from_headers(self, headers: dict[str, str]) -> str | None:
        lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
        for cdn, sigs in _CDN_SIGNATURES.items():
            for sig in sigs:
                if sig in lower_headers or any(sig in v for v in lower_headers.values()):
                    return cdn
        return None
