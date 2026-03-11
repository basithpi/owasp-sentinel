"""C14 – DNS security tester.

Tests AXFR zone transfer, enumerates DNS records, validates DNSSEC,
performs cache snooping, detects wildcard DNS, and brute-forces common
subdomains.
"""

from __future__ import annotations

import asyncio
import random
import socket
import string
from datetime import datetime
from typing import Any

import httpx

try:
    import dns.exception  # type: ignore
    import dns.flags  # type: ignore
    import dns.name  # type: ignore
    import dns.query  # type: ignore
    import dns.rdatatype  # type: ignore
    import dns.resolver  # type: ignore
    import dns.zone  # type: ignore
    _DNSPYTHON_AVAILABLE = True
except ImportError:
    _DNSPYTHON_AVAILABLE = False

from app.modules.base_module import BaseModule

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SRV", "SOA", "PTR"]
_DNSSEC_TYPES = ["DS", "DNSKEY", "RRSIG", "NSEC", "NSEC3"]

_COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging",
    "test", "vpn", "cdn", "app", "portal", "remote", "blog",
    "shop", "secure", "login", "beta", "smtp", "pop", "imap",
    "ns1", "ns2", "mx", "webmail", "gateway", "intranet",
]

# Common cache-snooping targets (domains likely cached by well-known resolvers)
_CACHE_SNOOP_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "github.com",
    "twitter.com", "youtube.com", "cloudflare.com",
]

_DEFAULT_DNS_SERVERS = ["8.8.8.8", "1.1.1.1"]


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class DNSZoneTester(BaseModule):
    """DNS security tester: AXFR, record enumeration, DNSSEC, cache snooping,
    wildcard detection, and subdomain brute force."""

    name = "dns_zone_tester"
    description = (
        "Tests DNS zone transfer (AXFR), enumerates records, validates DNSSEC, "
        "detects wildcard DNS and performs subdomain brute force."
    )
    version = "1.0.0"
    category = "reconnaissance"

    async def run(self, target: str, **kwargs) -> dict[str, Any]:
        """Run DNS security tests against *target* domain.

        Args:
            target: Domain name (e.g. ``example.com``) or URL.
            **kwargs:
                dns_server (str): Resolver IP to use (default: 8.8.8.8).
                timeout (int): Per-query timeout in seconds (default: 5).
                brute_force (bool): Whether to run subdomain brute force (default: True).

        Returns:
            Dict with ``findings``, ``records``, ``subdomains``, and metadata.
        """
        self.started_at = datetime.utcnow()
        domain = _extract_domain(target)
        dns_server: str = kwargs.get("dns_server", "8.8.8.8")
        timeout = int(kwargs.get("timeout", 5))
        do_brute: bool = bool(kwargs.get("brute_force", True))

        records: dict[str, list[str]] = {}
        subdomains: list[dict[str, Any]] = []

        # 1. AXFR zone transfer
        axfr_results = await asyncio.to_thread(self._try_axfr, domain, timeout)

        # 2. DNS record enumeration
        records = await asyncio.to_thread(self._enumerate_records, domain, dns_server, timeout)

        # 3. DNSSEC validation
        await asyncio.to_thread(self._check_dnssec, domain, dns_server, timeout)

        # 4. Cache snooping
        await asyncio.to_thread(self._cache_snoop, dns_server, timeout)

        # 5. Wildcard detection
        await asyncio.to_thread(self._detect_wildcard, domain, dns_server, timeout)

        # 6. Subdomain brute force
        if do_brute:
            subdomains = await asyncio.to_thread(
                self._brute_force_subdomains, domain, dns_server, timeout
            )

        # 7. DNS rebinding detection
        await asyncio.to_thread(self._detect_rebinding, domain, records)

        self.completed_at = datetime.utcnow()
        return {
            "module": self.name,
            "target": domain,
            "findings": self.results,
            "records": records,
            "subdomains": subdomains,
            "axfr_results": axfr_results,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
        }

    # ------------------------------------------------------------------ #
    # AXFR                                                                 #
    # ------------------------------------------------------------------ #

    def _try_axfr(self, domain: str, timeout: int) -> list[str]:
        """Attempt an AXFR zone transfer against all name servers."""
        axfr_records: list[str] = []
        if not _DNSPYTHON_AVAILABLE:
            axfr_records = self._axfr_socket_fallback(domain, timeout)
            return axfr_records

        try:
            ns_answers = dns.resolver.resolve(domain, "NS", lifetime=timeout)
            ns_list = [str(rdata) for rdata in ns_answers]
        except Exception:
            ns_list = []

        for ns in ns_list:
            ns_ip = ""
            try:
                ns_ip = socket.gethostbyname(ns)
            except Exception:
                continue
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=timeout, lifetime=timeout))
                for name, node in z.nodes.items():
                    axfr_records.append(str(name))
                self.add_finding(
                    title="DNS AXFR zone transfer succeeded",
                    severity="critical",
                    description=(
                        f"The name server {ns} ({ns_ip}) allowed a full AXFR zone transfer "
                        f"for domain '{domain}'. This exposes all DNS records."
                    ),
                    evidence=f"Retrieved {len(axfr_records)} records from {ns}",
                    url=f"dns://{domain}",
                    nameserver=ns,
                )
            except Exception:
                continue
        return axfr_records

    def _axfr_socket_fallback(self, domain: str, timeout: int) -> list[str]:
        """Basic AXFR attempt via raw TCP socket (no dnspython)."""
        # Build a minimal DNS AXFR request
        records: list[str] = []
        try:
            name_parts = domain.encode().split(b".")
            qname = b"".join(len(p).to_bytes(1, "big") + p for p in name_parts) + b"\x00"
            header = b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            question = qname + b"\x00\xfc\x00\x01"  # QTYPE=AXFR, QCLASS=IN
            msg = header + question
            length_prefix = len(msg).to_bytes(2, "big")
            with socket.create_connection(("8.8.8.8", 53), timeout=timeout) as sock:
                sock.sendall(length_prefix + msg)
                data = sock.recv(4096)
                if len(data) > 12:
                    # Got a response; minimal parsing not attempted without dnspython
                    self.add_finding(
                        title="DNS AXFR zone transfer: response received (manual probe)",
                        severity="medium",
                        description=(
                            f"An AXFR TCP request to 8.8.8.8 for '{domain}' received a "
                            "response. Install dnspython for full parsing."
                        ),
                        evidence=f"Response length: {len(data)} bytes",
                        url=f"dns://{domain}",
                    )
        except Exception:
            pass
        return records

    # ------------------------------------------------------------------ #
    # Record enumeration                                                   #
    # ------------------------------------------------------------------ #

    def _enumerate_records(
        self, domain: str, dns_server: str, timeout: int
    ) -> dict[str, list[str]]:
        """Query all common DNS record types."""
        records: dict[str, list[str]] = {}
        if not _DNSPYTHON_AVAILABLE:
            return self._enumerate_socket_fallback(domain)

        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        resolver.timeout = timeout
        resolver.lifetime = timeout

        for rtype in _RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                records[rtype] = []
            except Exception:
                records[rtype] = []
        return records

    def _enumerate_socket_fallback(self, domain: str) -> dict[str, list[str]]:
        """Minimal record enumeration via stdlib."""
        records: dict[str, list[str]] = {}
        try:
            info = socket.getaddrinfo(domain, None)
            records["A"] = list({ai[4][0] for ai in info if ai[0] == socket.AF_INET})
            records["AAAA"] = list({ai[4][0] for ai in info if ai[0] == socket.AF_INET6})
        except Exception:
            pass
        return records

    # ------------------------------------------------------------------ #
    # DNSSEC                                                               #
    # ------------------------------------------------------------------ #

    def _check_dnssec(self, domain: str, dns_server: str, timeout: int) -> None:
        """Check for DNSSEC records (DS, DNSKEY, RRSIG)."""
        if not _DNSPYTHON_AVAILABLE:
            return

        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        resolver.timeout = timeout
        resolver.lifetime = timeout

        found_types: list[str] = []
        for rtype in _DNSSEC_TYPES:
            try:
                resolver.resolve(domain, rtype)
                found_types.append(rtype)
            except Exception:
                continue

        if not found_types:
            self.add_finding(
                title="DNSSEC not configured",
                severity="medium",
                description=(
                    f"No DNSSEC records (DS, DNSKEY, RRSIG) found for '{domain}'. "
                    "DNSSEC prevents DNS spoofing/cache poisoning attacks."
                ),
                evidence="No DNSSEC records found",
                url=f"dns://{domain}",
            )
        else:
            # Presence is good; check for RRSIG (signed records)
            if "RRSIG" not in found_types:
                self.add_finding(
                    title="DNSSEC partially configured (missing RRSIG)",
                    severity="low",
                    description=(
                        f"DNSSEC is partially configured for '{domain}': "
                        f"found {found_types} but no RRSIG records."
                    ),
                    evidence=f"Found: {found_types}",
                    url=f"dns://{domain}",
                )

    # ------------------------------------------------------------------ #
    # Cache snooping                                                       #
    # ------------------------------------------------------------------ #

    def _cache_snoop(self, dns_server: str, timeout: int) -> None:
        """Test if the resolver has cached well-known domains (cache snooping)."""
        if not _DNSPYTHON_AVAILABLE:
            return

        cached: list[str] = []
        try:
            msg = dns.message.make_query(
                _CACHE_SNOOP_DOMAINS[0],
                dns.rdatatype.A,
                flags=0,  # No RD bit = cache-only (non-recursive)
            )
            response = dns.query.udp(msg, dns_server, timeout=timeout)
            if response.answer:
                cached.append(_CACHE_SNOOP_DOMAINS[0])
        except Exception:
            pass

        if cached:
            self.add_finding(
                title="DNS resolver susceptible to cache snooping",
                severity="low",
                description=(
                    f"The DNS resolver {dns_server} returned cached results for "
                    "non-recursive queries. This may allow cache snooping to "
                    "infer recently visited domains."
                ),
                evidence=f"Cached domains: {cached}",
                url=f"dns://{dns_server}",
            )

    # ------------------------------------------------------------------ #
    # Wildcard detection                                                   #
    # ------------------------------------------------------------------ #

    def _detect_wildcard(self, domain: str, dns_server: str, timeout: int) -> None:
        """Check if a random subdomain resolves (wildcard DNS)."""
        random_label = "".join(random.choices(string.ascii_lowercase, k=16))
        test_domain = f"{random_label}.{domain}"

        if _DNSPYTHON_AVAILABLE:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]
            resolver.timeout = timeout
            resolver.lifetime = timeout
            try:
                answers = resolver.resolve(test_domain, "A")
                ips = [str(r) for r in answers]
                self.add_finding(
                    title="Wildcard DNS detected",
                    severity="medium",
                    description=(
                        f"A random subdomain '{test_domain}' resolved successfully, "
                        f"indicating wildcard DNS (*.{domain}). This may mask "
                        "subdomain takeover risks."
                    ),
                    evidence=f"Resolved to: {ips}",
                    url=f"dns://{domain}",
                    wildcard_ips=ips,
                )
            except Exception:
                pass
        else:
            try:
                ip = socket.gethostbyname(test_domain)
                self.add_finding(
                    title="Wildcard DNS detected",
                    severity="medium",
                    description=f"Random subdomain '{test_domain}' resolved to {ip}.",
                    evidence=f"Resolved to: {ip}",
                    url=f"dns://{domain}",
                )
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # Subdomain brute force                                                #
    # ------------------------------------------------------------------ #

    def _brute_force_subdomains(
        self, domain: str, dns_server: str, timeout: int
    ) -> list[dict[str, Any]]:
        """Check each entry in _COMMON_SUBDOMAINS for valid DNS records."""
        found: list[dict[str, Any]] = []
        for sub in _COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{domain}"
            ips: list[str] = []
            if _DNSPYTHON_AVAILABLE:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.timeout = timeout
                resolver.lifetime = timeout
                try:
                    answers = resolver.resolve(fqdn, "A")
                    ips = [str(r) for r in answers]
                except Exception:
                    pass
            else:
                try:
                    ips = [socket.gethostbyname(fqdn)]
                except Exception:
                    pass
            if ips:
                found.append({"subdomain": fqdn, "ips": ips})
        return found

    # ------------------------------------------------------------------ #
    # DNS rebinding detection                                              #
    # ------------------------------------------------------------------ #

    def _detect_rebinding(self, domain: str, records: dict[str, list[str]]) -> None:
        """Flag if A records contain private/loopback IPs (rebinding indicator)."""
        private_prefixes = ("10.", "172.16.", "172.17.", "192.168.", "127.", "169.254.")
        for ip in records.get("A", []):
            if any(ip.startswith(p) for p in private_prefixes):
                self.add_finding(
                    title="Possible DNS rebinding risk",
                    severity="high",
                    description=(
                        f"The domain '{domain}' has an A record pointing to a private/loopback "
                        f"IP address ({ip}). This could be exploited for DNS rebinding attacks."
                    ),
                    evidence=f"A record: {ip}",
                    url=f"dns://{domain}",
                    private_ip=ip,
                )


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _extract_domain(target: str) -> str:
    """Extract bare domain name from a URL or return *target* as-is."""
    if target.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        return urlparse(target).hostname or target
    return target.lstrip("www.") if target.startswith("www.") else target
