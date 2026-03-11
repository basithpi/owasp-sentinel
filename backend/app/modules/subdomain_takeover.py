"""C9 – Subdomain takeover detector.

Resolves CNAME/NS/MX records, checks for dangling references, matches
response bodies against cloud-provider error fingerprints, and reports
exploitable takeover opportunities.
"""

from __future__ import annotations

import asyncio
import socket
from datetime import datetime
from typing import Any

import httpx

from app.modules.base_module import BaseModule

# ---------------------------------------------------------------------------
# Optional dnspython
# ---------------------------------------------------------------------------

try:
    import dns.exception  # type: ignore
    import dns.resolver  # type: ignore
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False


# ---------------------------------------------------------------------------
# Cloud provider fingerprint database
# ---------------------------------------------------------------------------

# Each entry: (provider_name, CNAME_suffix_patterns, body_error_patterns, severity)
_PROVIDER_FINGERPRINTS: list[dict[str, Any]] = [
    {
        "provider": "AWS S3",
        "cname_suffixes": [".s3.amazonaws.com", ".s3-website"],
        "body_patterns": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "severity": "high",
    },
    {
        "provider": "Azure",
        "cname_suffixes": [
            ".azurewebsites.net", ".cloudapp.azure.com",
            ".blob.core.windows.net", ".azureedge.net",
        ],
        "body_patterns": [
            "404 Web Site not found",
            "ErrorDocument",
            "The resource you are looking for has been removed",
        ],
        "severity": "high",
    },
    {
        "provider": "GCP / Firebase",
        "cname_suffixes": [
            ".appspot.com", ".firebaseapp.com",
            ".storage.googleapis.com", ".cloudfunctions.net",
        ],
        "body_patterns": [
            "404. That's an error.",
            "No such app",
            "The specified bucket does not exist",
        ],
        "severity": "high",
    },
    {
        "provider": "Heroku",
        "cname_suffixes": [".herokuapp.com", ".herokussl.com"],
        "body_patterns": [
            "No such app",
            "herokucdn.com/error-pages/no-such-app.html",
        ],
        "severity": "high",
    },
    {
        "provider": "GitHub Pages",
        "cname_suffixes": [".github.io"],
        "body_patterns": [
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        "severity": "high",
    },
    {
        "provider": "Netlify",
        "cname_suffixes": [".netlify.app", ".netlify.com"],
        "body_patterns": ["Not Found - Request ID", "netlify"],
        "severity": "high",
    },
    {
        "provider": "Vercel",
        "cname_suffixes": [".vercel.app", ".now.sh"],
        "body_patterns": ["The deployment you are trying to access does not exist"],
        "severity": "high",
    },
    {
        "provider": "Fastly",
        "cname_suffixes": [".fastly.net", ".fastlylb.net"],
        "body_patterns": ["Fastly error: unknown domain"],
        "severity": "medium",
    },
    {
        "provider": "Shopify",
        "cname_suffixes": [".myshopify.com", ".shopify.com"],
        "body_patterns": [
            "Sorry, this shop is currently unavailable.",
            "Only one step away from your own online store",
        ],
        "severity": "high",
    },
    {
        "provider": "Squarespace",
        "cname_suffixes": [".squarespace.com"],
        "body_patterns": [
            "No Such Account",
            "squarespace.com/no-such-site",
        ],
        "severity": "medium",
    },
    {
        "provider": "WordPress.com",
        "cname_suffixes": [".wordpress.com"],
        "body_patterns": [
            "Do you want to register",
            "doesn't exist",
        ],
        "severity": "medium",
    },
    {
        "provider": "Tumblr",
        "cname_suffixes": [".tumblr.com"],
        "body_patterns": ["Whatever you were looking for doesn't live here"],
        "severity": "medium",
    },
    {
        "provider": "Zendesk",
        "cname_suffixes": [".zendesk.com"],
        "body_patterns": ["Help Center Closed"],
        "severity": "medium",
    },
    {
        "provider": "Intercom",
        "cname_suffixes": [".custom.intercom.help"],
        "body_patterns": ["This page is reserved for artistic works"],
        "severity": "medium",
    },
]


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class SubdomainTakeover(BaseModule):
    """Subdomain takeover detector with cloud-provider fingerprint database."""

    name = "subdomain_takeover"
    description = (
        "Detect dangling CNAME/NS/MX records and verify takeover possibility "
        "against 14 cloud providers via response body fingerprinting."
    )
    version = "1.0.0"
    category = "recon"

    # ------------------------------------------------------------------ #
    # Public entry-point                                                   #
    # ------------------------------------------------------------------ #

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Scan *target* and any supplied subdomains for takeover vulnerabilities.

        Args:
            target: Root domain (e.g. "example.com") or a URL.
            **kwargs:
                - subdomains (List[str]): Additional subdomains to test.
                - timeout (int): HTTP timeout in seconds (default 10).
                - dns_timeout (float): DNS resolution timeout (default 5.0).
        """
        self.started_at = datetime.utcnow()

        # Normalise domain
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        extra_subs: list[str] = kwargs.get("subdomains", [])
        timeout: int = int(kwargs.get("timeout", 10))
        dns_timeout: float = float(kwargs.get("dns_timeout", 5.0))

        # Build list of fully-qualified hostnames to test
        subjects: list[str] = [domain] + [
            s if "." in s else f"{s}.{domain}" for s in extra_subs
        ]

        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=False
        ) as client:
            tasks = [
                self._check_host(client, host, dns_timeout)
                for host in subjects
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        self.completed_at = datetime.utcnow()
        return self.to_dict()

    # ------------------------------------------------------------------ #
    # Per-host check                                                       #
    # ------------------------------------------------------------------ #

    async def _check_host(
        self,
        client: httpx.AsyncClient,
        host: str,
        dns_timeout: float,
    ) -> None:
        """Resolve DNS records and check for takeover conditions."""
        cname_target = await self._resolve_cname(host, dns_timeout)
        ns_records = await self._resolve_ns(host, dns_timeout)
        mx_records = await self._resolve_mx(host, dns_timeout)

        # Check CNAME for dangling references
        if cname_target:
            await self._check_cname_takeover(client, host, cname_target)

        # Check NS delegation for orphaned zones
        if ns_records:
            await self._check_ns_takeover(client, host, ns_records)

        # Check MX for non-resolving mail servers
        if mx_records:
            await self._check_mx_takeover(host, mx_records)

        # If no CNAME points elsewhere, still probe HTTP for provider errors
        if not cname_target:
            await self._probe_http_fingerprint(client, host)

    # ------------------------------------------------------------------ #
    # CNAME resolution and dangling check                                  #
    # ------------------------------------------------------------------ #

    async def _resolve_cname(self, host: str, dns_timeout: float) -> str | None:
        """Return the CNAME target for *host*, or None."""
        if _DNS_AVAILABLE:
            try:
                resolver = dns.resolver.Resolver()
                resolver.lifetime = dns_timeout
                answers = resolver.resolve(host, "CNAME")
                return str(answers[0].target).rstrip(".")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                return None
            except Exception as exc:
                self.logger.debug("CNAME resolve %s: %s", host, exc)
                return None
        else:
            # Fallback: attempt socket lookup (no CNAME chain)
            try:
                socket.gethostbyname(host)
                return None  # Host resolves but we can't read CNAME without dnspython
            except socket.gaierror:
                return None

    async def _check_cname_takeover(
        self,
        client: httpx.AsyncClient,
        host: str,
        cname_target: str,
    ) -> None:
        """Check if the CNAME target resolves and matches a known provider fingerprint."""
        # Check whether cname_target itself resolves
        target_resolves = await self._host_resolves(cname_target)

        for fp in _PROVIDER_FINGERPRINTS:
            matched_suffix = any(
                cname_target.endswith(suffix)
                for suffix in fp["cname_suffixes"]
            )
            if not matched_suffix:
                continue

            if not target_resolves:
                self.add_finding(
                    title=f"Dangling CNAME → {fp['provider']} (Potential Takeover)",
                    severity=fp["severity"],
                    description=(
                        f"{host} has a CNAME record pointing to {cname_target!r} "
                        f"which does not resolve. This is a {fp['provider']} endpoint "
                        "that can likely be claimed by an attacker, enabling subdomain "
                        "takeover."
                    ),
                    evidence=(
                        f"CNAME: {host} → {cname_target}\n"
                        f"Target resolves: {target_resolves}"
                    ),
                    url=f"https://{host}",
                    owasp_category="A05",
                    provider=fp["provider"],
                )
                return

            # Target resolves – probe HTTP body for provider error messages
            await self._verify_takeover_body(client, host, fp)
            return

        # No known provider match, but CNAME target doesn't resolve = dangling
        if not target_resolves:
            self.add_finding(
                title=f"Dangling CNAME – {host} → {cname_target}",
                severity="medium",
                description=(
                    f"{host} CNAME points to {cname_target!r}, which does not resolve. "
                    "Depending on the registrar, this domain may be claimable."
                ),
                evidence=f"CNAME: {host} → {cname_target}",
                url=f"https://{host}",
                owasp_category="A05",
            )

    # ------------------------------------------------------------------ #
    # HTTP body fingerprint verification                                   #
    # ------------------------------------------------------------------ #

    async def _verify_takeover_body(
        self,
        client: httpx.AsyncClient,
        host: str,
        fingerprint: dict[str, Any],
    ) -> None:
        """Probe the HTTP response body for provider-specific error patterns."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                r = await client.get(url)
                body = r.text
                for pattern in fingerprint["body_patterns"]:
                    if pattern.lower() in body.lower():
                        self.add_finding(
                            title=(
                                f"Subdomain Takeover Confirmed – "
                                f"{host} ({fingerprint['provider']})"
                            ),
                            severity="critical",
                            description=(
                                f"The host {host} returns a response body containing "
                                f"the {fingerprint['provider']} unclaimed-resource error "
                                f"pattern: '{pattern}'. An attacker can register this "
                                f"{fingerprint['provider']} resource and serve arbitrary "
                                "content under the victim's subdomain."
                            ),
                            evidence=(
                                f"Pattern matched: '{pattern}'\n"
                                f"Status: {r.status_code}\n"
                                f"Body excerpt: {body[:300]}"
                            ),
                            url=url,
                            owasp_category="A05",
                            provider=fingerprint["provider"],
                            body_pattern=pattern,
                        )
                        self.logger.warning(
                            "Takeover confirmed: %s → %s (pattern: %r)",
                            host, fingerprint["provider"], pattern
                        )
                        return
            except Exception as exc:
                self.logger.debug("Body fingerprint probe %s: %s", url, exc)

    # ------------------------------------------------------------------ #
    # NS takeover                                                          #
    # ------------------------------------------------------------------ #

    async def _resolve_ns(self, host: str, dns_timeout: float) -> list[str]:
        """Return NS records for *host*."""
        if not _DNS_AVAILABLE:
            return []
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = dns_timeout
            answers = resolver.resolve(host, "NS")
            return [str(r.target).rstrip(".") for r in answers]
        except Exception:
            return []

    async def _check_ns_takeover(
        self,
        client: httpx.AsyncClient,
        host: str,
        ns_records: list[str],
    ) -> None:
        """Check whether NS records point to non-resolving name servers."""
        for ns in ns_records:
            resolves = await self._host_resolves(ns)
            if not resolves:
                self.add_finding(
                    title=f"Dangling NS Record – {host} → {ns}",
                    severity="high",
                    description=(
                        f"The NS record for {host} points to {ns!r}, which does not "
                        "resolve. If the name server domain is available for registration, "
                        "an attacker can take control of the entire DNS zone for {host}, "
                        "enabling phishing, email interception, and subdomain takeover."
                    ),
                    evidence=f"NS: {host} → {ns}  resolves={resolves}",
                    url=f"https://{host}",
                    owasp_category="A05",
                )

    # ------------------------------------------------------------------ #
    # MX takeover                                                          #
    # ------------------------------------------------------------------ #

    async def _resolve_mx(self, host: str, dns_timeout: float) -> list[str]:
        """Return MX record hostnames for *host*."""
        if not _DNS_AVAILABLE:
            return []
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = dns_timeout
            answers = resolver.resolve(host, "MX")
            return [str(r.exchange).rstrip(".") for r in answers]
        except Exception:
            return []

    async def _check_mx_takeover(
        self, host: str, mx_records: list[str]
    ) -> None:
        """Check whether MX records point to non-resolving mail servers."""
        for mx in mx_records:
            resolves = await self._host_resolves(mx)
            if not resolves:
                self.add_finding(
                    title=f"Dangling MX Record – {host} → {mx}",
                    severity="high",
                    description=(
                        f"The MX record for {host} points to {mx!r}, which does not "
                        "resolve. If the mail server domain is claimable, an attacker "
                        "can intercept all inbound email for the domain, enabling "
                        "password reset capture and account takeover."
                    ),
                    evidence=f"MX: {host} → {mx}  resolves={resolves}",
                    url=f"https://{host}",
                    owasp_category="A05",
                )

    # ------------------------------------------------------------------ #
    # HTTP fingerprint probe (no known CNAME)                             #
    # ------------------------------------------------------------------ #

    async def _probe_http_fingerprint(
        self, client: httpx.AsyncClient, host: str
    ) -> None:
        """Directly probe HTTP response for known provider error strings."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                r = await client.get(url)
                body = r.text.lower()
                for fp in _PROVIDER_FINGERPRINTS:
                    for pattern in fp["body_patterns"]:
                        if pattern.lower() in body:
                            self.add_finding(
                                title=f"Provider Error Page Detected – {fp['provider']}",
                                severity=fp["severity"],
                                description=(
                                    f"{url} returns a {fp['provider']} unclaimed-resource "
                                    f"error page (pattern: '{pattern}'). This may indicate "
                                    "a subdomain takeover opportunity."
                                ),
                                evidence=f"Pattern: '{pattern}'\nBody: {r.text[:200]}",
                                url=url,
                                provider=fp["provider"],
                            )
                            return
                return  # Stop after first successful HTTP response
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    async def _host_resolves(self, host: str) -> bool:
        """Return True if *host* resolves to at least one IP address."""
        if _DNS_AVAILABLE:
            try:
                resolver = dns.resolver.Resolver()
                resolver.lifetime = 3.0
                resolver.resolve(host, "A")
                return True
            except Exception:
                pass
            try:
                resolver.resolve(host, "AAAA")
                return True
            except Exception:
                return False
        else:
            try:
                socket.gethostbyname(host)
                return True
            except socket.gaierror:
                return False
