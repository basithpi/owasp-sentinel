"""TLSX TLS certificate inspection wrapper."""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("owasp_sentinel.tools.tlsx")

_WEAK_CIPHERS = frozenset(["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"])


class TlsxWrapper:
    """Wrapper for the ``tlsx`` TLS certificate scanner binary."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialise with optional config dict.

        Args:
            config: Optional overrides. Recognised keys:
                ``binary``  – path to tlsx executable (default ``tlsx``).
                ``timeout`` – subprocess timeout in seconds (default 120).
        """
        self.config: dict[str, Any] = config or {}
        self.binary: str = self.config.get("binary", "tlsx")
        self.timeout: int = int(self.config.get("timeout", 120))

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Scan TLS certificate info for *target*.

        Args:
            target: Host or IP to inspect (host:port or just host).
            **kwargs: Runtime overrides.

        Returns:
            Dict with certificate details and security findings.
        """
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            output_file = tmp.name

        cmd = [
            self.binary,
            "-u", target,
            "-san", "-cn", "-resp",
            "-json",
            "-o", output_file,
        ]
        logger.info("Running tlsx: %s", " ".join(cmd))
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            logger.error("tlsx timed out after %d seconds", self.timeout)
            return {"error": "timeout", "certificates": [], "findings": []}
        except FileNotFoundError:
            logger.error("tlsx binary not found: %s", self.binary)
            return {"error": "binary_not_found", "certificates": [], "findings": []}

        if stderr:
            logger.debug("tlsx stderr: %s", stderr.decode(errors="replace")[:500])

        try:
            output = Path(output_file).read_text(errors="replace")
        except OSError:
            output = stdout.decode(errors="replace")

        return self.parse_output(output)

    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse tlsx JSON output into structured certificate data.

        Args:
            output: Raw JSON-lines output from tlsx.

        Returns:
            Dict with ``certificates`` list and ``findings`` list.
        """
        certificates: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            cert: dict[str, Any] = {
                "host": entry.get("host", ""),
                "subject_cn": entry.get("subject_cn", ""),
                "sans": entry.get("subject_an", []),
                "issuer": entry.get("issuer_cn", ""),
                "issuer_org": entry.get("issuer_org", []),
                "not_before": entry.get("not_before", ""),
                "not_after": entry.get("not_after", ""),
                "tls_version": entry.get("tls_version", ""),
                "cipher_suite": entry.get("cipher", ""),
                "self_signed": bool(entry.get("self_signed", False)),
                "expired": bool(entry.get("expired", False)),
                "fingerprint": entry.get("fingerprint", ""),
            }
            certificates.append(cert)

            host = cert["host"]

            if cert["expired"]:
                findings.append({
                    "title": "Expired TLS Certificate",
                    "severity": "high",
                    "description": f"TLS certificate for {host} has expired (not_after: {cert['not_after']})",
                    "host": host,
                    "source": "tlsx",
                })

            if cert["self_signed"]:
                findings.append({
                    "title": "Self-Signed TLS Certificate",
                    "severity": "medium",
                    "description": f"TLS certificate for {host} is self-signed",
                    "host": host,
                    "source": "tlsx",
                })

            cipher = cert["cipher_suite"].upper()
            for weak in _WEAK_CIPHERS:
                if weak in cipher:
                    findings.append({
                        "title": f"Weak Cipher Suite: {weak}",
                        "severity": "high",
                        "description": f"Host {host} uses weak cipher suite containing {weak}: {cert['cipher_suite']}",
                        "host": host,
                        "source": "tlsx",
                    })
                    break

            tls_ver = cert["tls_version"].upper()
            if tls_ver in ("TLSV1", "TLSV10", "TLSV1.0", "SSLV3", "SSLV2"):
                findings.append({
                    "title": f"Deprecated TLS Version: {cert['tls_version']}",
                    "severity": "medium",
                    "description": f"Host {host} supports deprecated TLS version {cert['tls_version']}",
                    "host": host,
                    "source": "tlsx",
                })

        return {"certificates": certificates, "findings": findings}
