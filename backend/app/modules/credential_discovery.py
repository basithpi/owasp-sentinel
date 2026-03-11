"""C13 – Credential and secret discovery module.

Scans URLs and raw text for secrets using regex patterns and Shannon entropy.
Checks common exposed file paths and JavaScript source maps.
"""

from __future__ import annotations

import asyncio
import base64
import math
import re
from datetime import datetime
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.modules.base_module import BaseModule

# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE), "critical"),
    ("AWS Secret Key", re.compile(r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\s:=\"']+([A-Za-z0-9/+=]{40})", re.IGNORECASE), "critical"),
    ("GitHub Token (ghp_)", re.compile(r"ghp_[A-Za-z0-9_]{36,}", re.IGNORECASE), "critical"),
    ("GitHub Token (ghs_)", re.compile(r"ghs_[A-Za-z0-9_]{36,}", re.IGNORECASE), "critical"),
    ("GitHub Token (gho_)", re.compile(r"gho_[A-Za-z0-9_]{36,}", re.IGNORECASE), "critical"),
    ("GitHub Token (github_pat_)", re.compile(r"github_pat_[A-Za-z0-9_]{82,}", re.IGNORECASE), "critical"),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}", re.IGNORECASE), "high"),
    ("Stripe Live Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}", re.IGNORECASE), "critical"),
    ("Stripe Test Secret Key", re.compile(r"sk_test_[0-9a-zA-Z]{24,}", re.IGNORECASE), "medium"),
    ("Stripe Publishable Key", re.compile(r"pk_live_[0-9a-zA-Z]{24,}", re.IGNORECASE), "medium"),
    ("RSA Private Key", re.compile(r"-----BEGIN RSA PRIVATE KEY-----", re.IGNORECASE), "critical"),
    ("EC Private Key", re.compile(r"-----BEGIN EC PRIVATE KEY-----", re.IGNORECASE), "critical"),
    ("Private Key (generic)", re.compile(r"-----BEGIN PRIVATE KEY-----", re.IGNORECASE), "critical"),
    ("OpenSSH Private Key", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----", re.IGNORECASE), "critical"),
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", re.IGNORECASE), "high"),
    ("Base64 Password", re.compile(r"(?i)(?:password|passwd|pwd)[\"'\s:=]+([A-Za-z0-9+/=]{20,})", re.IGNORECASE), "high"),
    ("API Token in URL", re.compile(r"[?&](?:api[_-]?key|token|access_token|api_token)=([A-Za-z0-9_\-]{16,})", re.IGNORECASE), "high"),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}", re.IGNORECASE), "critical"),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", re.IGNORECASE), "high"),
    ("Twilio API Key", re.compile(r"SK[0-9a-fA-F]{32}", re.IGNORECASE), "high"),
    ("Heroku API Key", re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", re.IGNORECASE), "medium"),
    ("SendGrid API Key", re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}", re.IGNORECASE), "critical"),
    ("Mailchimp API Key", re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}", re.IGNORECASE), "high"),
    ("Password in config", re.compile(r'(?i)(?:password|passwd|secret)\s*[=:]\s*["\']([^"\']{6,})["\']', re.IGNORECASE), "high"),
    ("Database Connection String", re.compile(r"(?i)(?:mysql|postgresql|mongodb|redis)://[^@\s]+:[^@\s]+@[^\s]+", re.IGNORECASE), "critical"),
]

# Paths to probe for exposed sensitive files
_SENSITIVE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.backup",
    "/.git/config",
    "/.git/HEAD",
    "/wp-config.php",
    "/config.php",
    "/configuration.php",
    "/.travis.yml",
    "/Jenkinsfile",
    "/docker-compose.yml",
    "/.aws/credentials",
    "/web.config",
    "/.htpasswd",
    "/phpinfo.php",
    "/server-status",
    "/actuator/env",
    "/actuator/configprops",
    "/.npmrc",
    "/Makefile",
    "/composer.json",
    "/composer.lock",
    "/.bash_history",
    "/.ssh/id_rsa",
]

# HTML/JS comment patterns that might expose env vars or credentials
_COMMENT_PATTERNS = [
    re.compile(r"<!--.*?(?:password|secret|token|key|credential).*?-->", re.IGNORECASE | re.DOTALL),
    re.compile(r"/\*.*?(?:password|secret|token|key|credential).*?\*/", re.IGNORECASE | re.DOTALL),
    re.compile(r"//.*(?:password|secret|token|key|credential).*", re.IGNORECASE),
]

_ENV_VAR_PATTERN = re.compile(
    r"(?i)(?:var|let|const|window\.|self\.)\s*\w*(?:api[_\-]?key|secret|token|password)\w*\s*=\s*[\"']([^\"']{6,})[\"']"
)

# Entropy threshold for high-entropy string detection
_ENTROPY_THRESHOLD = 4.5
_ENTROPY_MIN_LENGTH = 16
_ENTROPY_MAX_LENGTH = 256
_HIGH_ENTROPY_PATTERN = re.compile(r"['\"][A-Za-z0-9+/=_\-]{%d,%d}['\"]" % (_ENTROPY_MIN_LENGTH, _ENTROPY_MAX_LENGTH))


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class CredentialDiscovery(BaseModule):
    """Discovers credentials and secrets in web responses via regex patterns
    and Shannon entropy analysis."""

    name = "credential_discovery"
    description = (
        "Scans URLs and raw text for secrets: AWS keys, GitHub tokens, "
        "API keys, private keys, JWTs, high-entropy strings, and exposed config files."
    )
    version = "1.0.0"
    category = "reconnaissance"

    async def run(self, target: str, **kwargs) -> dict[str, Any]:
        """Discover credentials on *target*.

        Args:
            target: URL to scan, or raw text when ``raw_content`` is True.
            **kwargs:
                raw_content (bool): Treat *target* as raw text, not URL.
                extra_paths (list[str]): Additional paths to probe.
                timeout (int): HTTP timeout in seconds (default: 10).
                concurrency (int): Max parallel requests (default: 15).

        Returns:
            Dict with ``findings`` and ``secrets`` list.
        """
        self.started_at = datetime.utcnow()
        raw_content: bool = bool(kwargs.get("raw_content", False))
        timeout = int(kwargs.get("timeout", 10))
        concurrency = min(int(kwargs.get("concurrency", 15)), 30)
        extra_paths: list[str] = kwargs.get("extra_paths", [])

        secrets: list[dict[str, Any]] = []

        if raw_content:
            secrets = self._scan_text(target, source="<raw_input>")
        else:
            base = _normalise_url(target)
            sem = asyncio.Semaphore(concurrency)
            async with httpx.AsyncClient(
                timeout=timeout, verify=False, follow_redirects=True
            ) as client:
                paths = list(_SENSITIVE_PATHS) + extra_paths
                tasks = [self._probe_path(client, base, path, sem) for path in paths]
                # Also scan the root page
                tasks.append(self._probe_path(client, base, "/", sem, is_main=True))
                batch = await asyncio.gather(*tasks, return_exceptions=True)
            for result in batch:
                if isinstance(result, list):
                    secrets.extend(result)

        self.completed_at = datetime.utcnow()
        return {
            "module": self.name,
            "target": target,
            "findings": self.results,
            "secrets": secrets,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
        }

    # ------------------------------------------------------------------ #
    # HTTP probing                                                         #
    # ------------------------------------------------------------------ #

    async def _probe_path(
        self,
        client: httpx.AsyncClient,
        base: str,
        path: str,
        sem: asyncio.Semaphore,
        is_main: bool = False,
    ) -> list[dict[str, Any]]:
        """Fetch *path* and scan for secrets. Also check for source maps."""
        url = base.rstrip("/") + path
        try:
            async with sem:
                resp = await client.get(url)
        except Exception:
            return []

        found: list[dict[str, Any]] = []

        if resp.status_code == 200:
            text = _safe_text(resp)
            found += self._scan_text(text, source=url)
            # Check for source map references
            if is_main or path.endswith(".js"):
                found += await self._check_source_maps(client, url, text, sem)
            # Alert on exposed sensitive files
            if path != "/" and resp.status_code == 200 and text.strip():
                self.add_finding(
                    title=f"Sensitive file exposed: {path}",
                    severity="high",
                    description=f"The file {path} is publicly accessible and may contain sensitive data.",
                    evidence=text[:500],
                    url=url,
                )
        return found

    async def _check_source_maps(
        self,
        client: httpx.AsyncClient,
        js_url: str,
        js_content: str,
        sem: asyncio.Semaphore,
    ) -> list[dict[str, Any]]:
        """Detect `//# sourceMappingURL=` references and download the source map."""
        found: list[dict[str, Any]] = []
        pattern = re.compile(r"//[#@]\s*sourceMappingURL=([^\s]+)")
        for m in pattern.finditer(js_content):
            map_url = m.group(1).strip()
            if not map_url.startswith("http"):
                base = js_url.rsplit("/", 1)[0]
                map_url = f"{base}/{map_url}"
            try:
                async with sem:
                    resp = await client.get(map_url)
                if resp.status_code == 200:
                    text = _safe_text(resp)
                    found += self._scan_text(text, source=map_url)
                    self.add_finding(
                        title="JavaScript source map exposed",
                        severity="medium",
                        description=(
                            f"A JavaScript source map is publicly accessible at {map_url}. "
                            "Source maps can reveal original source code."
                        ),
                        evidence=f"Source map URL: {map_url}",
                        url=map_url,
                    )
            except Exception:
                continue
        return found

    # ------------------------------------------------------------------ #
    # Text scanning                                                        #
    # ------------------------------------------------------------------ #

    def _scan_text(self, text: str, source: str) -> list[dict[str, Any]]:
        """Run all secret detection strategies against *text*."""
        found: list[dict[str, Any]] = []
        found += self._regex_scan(text, source)
        found += self._entropy_scan(text, source)
        found += self._comment_scan(text, source)
        found += self._env_var_scan(text, source)
        return found

    def _regex_scan(self, text: str, source: str) -> list[dict[str, Any]]:
        """Apply all regex patterns to *text*."""
        found: list[dict[str, Any]] = []
        for name, pattern, severity in _SECRET_PATTERNS:
            for m in pattern.finditer(text):
                matched = m.group(0)
                redacted = _redact(matched)
                self.add_finding(
                    title=f"Secret detected: {name}",
                    severity=severity,
                    description=f"A {name} was found in the response from {source}.",
                    evidence=redacted,
                    url=source,
                    secret_type=name,
                )
                found.append({"type": name, "source": source, "evidence": redacted, "severity": severity})
        return found

    def _entropy_scan(self, text: str, source: str) -> list[dict[str, Any]]:
        """Detect high-entropy strings that may be secrets."""
        found: list[dict[str, Any]] = []
        for m in _HIGH_ENTROPY_PATTERN.finditer(text):
            candidate = m.group(0).strip("'\"")
            entropy = _shannon_entropy(candidate)
            if entropy >= _ENTROPY_THRESHOLD:
                redacted = _redact(candidate)
                self.add_finding(
                    title="High-entropy string detected",
                    severity="medium",
                    description=(
                        f"A high-entropy string (entropy={entropy:.2f}) was found near "
                        f"position {m.start()} in {source}. This may be a secret or key."
                    ),
                    evidence=redacted,
                    url=source,
                    entropy=round(entropy, 3),
                )
                found.append({
                    "type": "high_entropy",
                    "source": source,
                    "evidence": redacted,
                    "entropy": round(entropy, 3),
                    "severity": "medium",
                })
        return found

    def _comment_scan(self, text: str, source: str) -> list[dict[str, Any]]:
        """Look for credentials in HTML/JS comments."""
        found: list[dict[str, Any]] = []
        for pattern in _COMMENT_PATTERNS:
            for m in pattern.finditer(text):
                snippet = m.group(0)[:300]
                self.add_finding(
                    title="Credential in comment",
                    severity="high",
                    description=f"A comment containing a potential credential was found in {source}.",
                    evidence=snippet,
                    url=source,
                )
                found.append({"type": "comment", "source": source, "evidence": snippet, "severity": "high"})
        return found

    def _env_var_scan(self, text: str, source: str) -> list[dict[str, Any]]:
        """Detect environment variable assignments in JavaScript source."""
        found: list[dict[str, Any]] = []
        for m in _ENV_VAR_PATTERN.finditer(text):
            val = m.group(1)
            redacted = _redact(val)
            self.add_finding(
                title="Environment variable exposure in JS source",
                severity="high",
                description=(
                    f"A JavaScript environment variable containing a potential secret "
                    f"was found in {source}."
                ),
                evidence=f"{m.group(0)[:100].replace(val, redacted)}",
                url=source,
            )
            found.append({"type": "env_var", "source": source, "evidence": redacted, "severity": "high"})
        return found


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of string *s*."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _redact(value: str, visible: int = 4) -> str:
    """Redact a secret, keeping only the first *visible* characters."""
    if len(value) <= visible:
        return "***"
    return value[:visible] + "..." + "*" * min(8, len(value) - visible)


def _normalise_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target.rstrip("/")


def _safe_text(resp: httpx.Response) -> str:
    try:
        return resp.text
    except Exception:
        return ""
