"""C4 – AI-powered vulnerability scorer.

Implements CVSS v4.0 calculation, EPSS estimation via CWE lookup table,
business-impact mapping, exploitability assessment, auto-remediation
recommendations, and a priority queue builder.
"""

from __future__ import annotations

import heapq
from datetime import datetime
from typing import Any

from app.modules.base_module import BaseModule

# ---------------------------------------------------------------------------
# CVSS v4.0 metric definitions
# ---------------------------------------------------------------------------

# Base score lookup (simplified AV/AC/PR/UI/VC/VI/VA/SC/SI/SA)
# Values are mean contribution weights derived from CVSS v4.0 specification.
_AV_WEIGHT: dict[str, float] = {
    "N": 0.85,   # Network
    "A": 0.62,   # Adjacent
    "L": 0.55,   # Local
    "P": 0.20,   # Physical
}
_AC_WEIGHT: dict[str, float] = {"L": 0.77, "H": 0.44}
_AT_WEIGHT: dict[str, float] = {"N": 0.85, "P": 0.44}   # Attack Requirements (v4.0)
_PR_WEIGHT: dict[str, float] = {"N": 0.85, "L": 0.62, "H": 0.27}
_UI_WEIGHT: dict[str, float] = {"N": 0.85, "P": 0.62, "A": 0.43}  # v4.0: None/Passive/Active
_VC_WEIGHT: dict[str, float] = {"H": 0.56, "L": 0.22, "N": 0.0}
_VI_WEIGHT: dict[str, float] = {"H": 0.56, "L": 0.22, "N": 0.0}
_VA_WEIGHT: dict[str, float] = {"H": 0.56, "L": 0.22, "N": 0.0}
_SC_WEIGHT: dict[str, float] = {"H": 0.56, "L": 0.22, "N": 0.0}
_SI_WEIGHT: dict[str, float] = {"H": 0.56, "L": 0.22, "N": 0.0}
_SA_WEIGHT: dict[str, float] = {"H": 0.56, "L": 0.22, "N": 0.0}


# EPSS estimation lookup table keyed by CWE-ID (approximate base rates)
_EPSS_BY_CWE: dict[str, float] = {
    "CWE-79":   0.0042,   # XSS
    "CWE-89":   0.0156,   # SQL Injection
    "CWE-22":   0.0198,   # Path Traversal
    "CWE-78":   0.0321,   # OS Command Injection
    "CWE-918":  0.0267,   # SSRF
    "CWE-611":  0.0089,   # XXE
    "CWE-287":  0.0445,   # Improper Authentication
    "CWE-639":  0.0134,   # IDOR / Auth Reference
    "CWE-94":   0.0178,   # Code Injection
    "CWE-502":  0.0231,   # Deserialization
    "CWE-352":  0.0028,   # CSRF
    "CWE-307":  0.0061,   # Brute Force
    "CWE-295":  0.0073,   # Certificate Validation
    "CWE-200":  0.0019,   # Information Exposure
    "CWE-285":  0.0112,   # Improper Authorization
}

# Business function → OWASP mapping
_BUSINESS_FUNCTION_MAP: dict[str, list[str]] = {
    "authentication": ["A07", "CWE-287", "CWE-307", "CWE-295"],
    "payments": ["A01", "A02", "CWE-89", "CWE-639"],
    "data_storage": ["A02", "A03", "CWE-89", "CWE-22"],
    "admin_panel": ["A01", "A05", "CWE-285", "CWE-639"],
    "api": ["A01", "A03", "A10", "CWE-918", "CWE-639"],
    "file_upload": ["A03", "A05", "CWE-22", "CWE-78"],
}

# Remediation templates per CWE / title keyword
_REMEDIATION_TEMPLATES: dict[str, str] = {
    "xss": (
        "1. Encode all user-supplied output using context-specific encoding "
        "(HTML, JS, CSS, URL).\n"
        "2. Implement a Content Security Policy (CSP) header.\n"
        "3. Use a templating engine with auto-escaping enabled.\n"
        "4. Validate input server-side with an allowlist."
    ),
    "sqli": (
        "1. Use parameterised queries / prepared statements exclusively.\n"
        "2. Apply an ORM that abstracts raw SQL.\n"
        "3. Enforce least-privilege DB accounts.\n"
        "4. Enable WAF rules for SQL injection patterns."
    ),
    "ssrf": (
        "1. Validate and allowlist target URLs/IPs before making outbound requests.\n"
        "2. Block access to internal IP ranges (169.254.x.x, 10.x, 172.16-31.x, 192.168.x).\n"
        "3. Use a dedicated egress proxy that enforces allowlist policies.\n"
        "4. Disable unused URL schemes (file://, gopher://, dict://)."
    ),
    "idor": (
        "1. Implement server-side authorisation checks on every object access.\n"
        "2. Use indirect references (UUIDs or HMAC-signed tokens) instead of "
        "sequential integer IDs.\n"
        "3. Audit access control logic in code review.\n"
        "4. Add automated BOLA tests to the CI/CD pipeline."
    ),
    "lfi": (
        "1. Avoid using user input to construct file paths.\n"
        "2. Resolve and validate the canonical path against an allowlist directory.\n"
        "3. Use chroot jails or container isolation.\n"
        "4. Disable PHP wrappers (allow_url_fopen, allow_url_include)."
    ),
    "xxe": (
        "1. Disable external entity processing in the XML parser.\n"
        "2. Use a less complex data format (JSON) where possible.\n"
        "3. Patch and update XML processing libraries.\n"
        "4. Implement input validation and XML schema validation."
    ),
    "cmd_injection": (
        "1. Avoid invoking OS commands with user-supplied input.\n"
        "2. Use language APIs instead of shell commands where possible.\n"
        "3. Sanitise input with a strict allowlist.\n"
        "4. Run application processes with minimal OS privileges."
    ),
    "default": (
        "1. Review the affected code for improper input handling.\n"
        "2. Apply the principle of least privilege.\n"
        "3. Patch and update affected dependencies.\n"
        "4. Add regression tests for this vulnerability class."
    ),
}


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class AIScorer(BaseModule):
    """AI-powered vulnerability scoring: CVSS v4.0, EPSS, business impact, priority queue."""

    name = "ai_scorer"
    description = (
        "Calculate CVSS v4.0 scores, estimate EPSS probability, assess business impact, "
        "generate remediation recommendations, and build a prioritised remediation queue."
    )
    version = "1.0.0"
    category = "scoring"

    # ------------------------------------------------------------------ #
    # Public entry-point                                                   #
    # ------------------------------------------------------------------ #

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Score and prioritise a list of findings.

        Args:
            target: Target URL (for context).
            **kwargs:
                - findings (List[Dict]): Findings to score.
                - business_functions (List[str]): Active business functions on target.
        """
        self.started_at = datetime.utcnow()

        findings: list[dict[str, Any]] = kwargs.get("findings", [])
        business_functions: list[str] = kwargs.get("business_functions", list(_BUSINESS_FUNCTION_MAP.keys()))

        scored: list[dict[str, Any]] = []
        for f in findings:
            enriched = self.score_finding(f, business_functions)
            scored.append(enriched)

        priority_queue = self.build_priority_queue(scored)

        self.add_finding(
            title="Scoring Complete",
            severity="info",
            description=(
                f"Scored {len(scored)} findings. "
                f"Top priority: {priority_queue[0]['title'] if priority_queue else 'N/A'}."
            ),
            url=target,
            scored_findings=scored,
            priority_queue=[p["title"] for p in priority_queue],
        )

        self.completed_at = datetime.utcnow()
        return {**self.to_dict(), "scored_findings": scored, "priority_queue": priority_queue}

    # ------------------------------------------------------------------ #
    # Per-finding scoring                                                  #
    # ------------------------------------------------------------------ #

    def score_finding(
        self,
        finding: dict[str, Any],
        business_functions: list[str] | None = None,
    ) -> dict[str, Any]:
        """Enrich a single finding with CVSS v4.0, EPSS, impact, and remediation.

        Args:
            finding: Raw finding dictionary.
            business_functions: Business functions active on the target.

        Returns:
            A copy of *finding* with extra scoring fields.
        """
        enriched = dict(finding)
        metrics = self._infer_cvss_metrics(finding)
        cvss_score, cvss_vector = self.calculate_cvss_v4(metrics)
        epss = self.estimate_epss(finding)
        impact = self.assess_business_impact(finding, business_functions or [])
        exploitability = self.assess_exploitability(finding, metrics)
        remediation = self.generate_remediation(finding)

        enriched.update(
            {
                "cvss_v4_score": cvss_score,
                "cvss_v4_vector": cvss_vector,
                "cvss_v4_severity": self._cvss_severity(cvss_score),
                "cvss_v4_metrics": metrics,
                "epss_score": epss,
                "business_impact": impact,
                "exploitability": exploitability,
                "remediation": remediation,
                "priority_score": self._priority_score(cvss_score, epss, impact),
            }
        )
        return enriched

    # ------------------------------------------------------------------ #
    # CVSS v4.0 calculator                                                 #
    # ------------------------------------------------------------------ #

    def calculate_cvss_v4(
        self, metrics: dict[str, str]
    ) -> tuple[float, str]:
        """Compute a CVSS v4.0 base score from metric abbreviations.

        Args:
            metrics: Dict with keys AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA.

        Returns:
            Tuple of (score: float 0–10, vector_string: str).
        """
        av = _AV_WEIGHT.get(metrics.get("AV", "N"), 0.85)
        ac = _AC_WEIGHT.get(metrics.get("AC", "L"), 0.77)
        at = _AT_WEIGHT.get(metrics.get("AT", "N"), 0.85)
        pr = _PR_WEIGHT.get(metrics.get("PR", "N"), 0.85)
        ui = _UI_WEIGHT.get(metrics.get("UI", "N"), 0.85)
        vc = _VC_WEIGHT.get(metrics.get("VC", "N"), 0.0)
        vi = _VI_WEIGHT.get(metrics.get("VI", "N"), 0.0)
        va = _VA_WEIGHT.get(metrics.get("VA", "N"), 0.0)
        sc = _SC_WEIGHT.get(metrics.get("SC", "N"), 0.0)
        si = _SI_WEIGHT.get(metrics.get("SI", "N"), 0.0)
        sa = _SA_WEIGHT.get(metrics.get("SA", "N"), 0.0)

        # Exploitability sub-score
        exploitability = 8.22 * av * ac * at * pr * ui

        # Vulnerable-system impact
        isc_v = 1 - (1 - vc) * (1 - vi) * (1 - va)
        # Subsequent-system impact
        isc_s = 1 - (1 - sc) * (1 - si) * (1 - sa)

        # Base score formula (CVSS v4.0 approximation)
        if isc_v == 0 and isc_s == 0:
            base_score = 0.0
        else:
            impact = 6.42 * isc_v + 7.52 * isc_s - 0.029 * isc_v * isc_s
            base_score = min(round((impact + exploitability) / 10.0, 1), 10.0)

        vector = (
            f"CVSS:4.0/AV:{metrics.get('AV','N')}/AC:{metrics.get('AC','L')}"
            f"/AT:{metrics.get('AT','N')}/PR:{metrics.get('PR','N')}"
            f"/UI:{metrics.get('UI','N')}/VC:{metrics.get('VC','N')}"
            f"/VI:{metrics.get('VI','N')}/VA:{metrics.get('VA','N')}"
            f"/SC:{metrics.get('SC','N')}/SI:{metrics.get('SI','N')}"
            f"/SA:{metrics.get('SA','N')}"
        )
        return base_score, vector

    # ------------------------------------------------------------------ #
    # EPSS estimation                                                      #
    # ------------------------------------------------------------------ #

    def estimate_epss(self, finding: dict[str, Any]) -> float:
        """Estimate EPSS (Exploit Prediction Scoring System) score.

        Uses a CWE-keyed lookup table. If the CWE is unknown, derives a
        heuristic from the severity.

        Returns:
            Float in [0, 1] representing 30-day exploitation probability.
        """
        cwe = finding.get("cwe", "")
        if cwe in _EPSS_BY_CWE:
            base = _EPSS_BY_CWE[cwe]
        else:
            # Heuristic fallback based on severity
            severity_epss = {
                "critical": 0.08,
                "high": 0.04,
                "medium": 0.02,
                "low": 0.005,
                "info": 0.001,
            }
            base = severity_epss.get(finding.get("severity", "info"), 0.001)

        # Apply a multiplier if evidence of active exploitation is mentioned
        desc = (finding.get("description", "") + finding.get("evidence", "")).lower()
        multiplier = 1.5 if any(kw in desc for kw in ["poc", "exploit", "metasploit", "cve-"]) else 1.0
        return round(min(base * multiplier, 1.0), 4)

    # ------------------------------------------------------------------ #
    # Business impact                                                      #
    # ------------------------------------------------------------------ #

    def assess_business_impact(
        self,
        finding: dict[str, Any],
        business_functions: list[str],
    ) -> dict[str, Any]:
        """Map a finding to affected business functions and compute an impact level.

        Returns:
            Dict with keys: affected_functions, impact_level, impact_description.
        """
        affected: list[str] = []
        owasp_cat = finding.get("owasp_category", "")
        cwe = finding.get("cwe", "")

        for func, identifiers in _BUSINESS_FUNCTION_MAP.items():
            if func not in business_functions:
                continue
            if owasp_cat in identifiers or cwe in identifiers:
                affected.append(func)

        # Severity → impact level
        sev_level = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "negligible",
        }.get(finding.get("severity", "info"), "negligible")

        descriptions = {
            "critical": "Likely to cause immediate business disruption, data breach, or financial loss.",
            "high": "Significant risk of data exposure or service compromise.",
            "medium": "Moderate risk; exploitation requires additional conditions.",
            "low": "Limited impact; informational value to an attacker.",
            "negligible": "No direct business impact.",
        }

        return {
            "affected_functions": affected,
            "impact_level": sev_level,
            "impact_description": descriptions[sev_level],
        }

    # ------------------------------------------------------------------ #
    # Exploitability assessment                                            #
    # ------------------------------------------------------------------ #

    def assess_exploitability(
        self,
        finding: dict[str, Any],
        metrics: dict[str, str],
    ) -> dict[str, Any]:
        """Assess how easily the vulnerability can be exploited.

        Returns:
            Dict with keys: level (easy/medium/hard), rationale.
        """
        av = metrics.get("AV", "N")
        pr = metrics.get("PR", "N")
        ui = metrics.get("UI", "N")
        ac = metrics.get("AC", "L")

        score = 0
        if av == "N":
            score += 3  # Remote
        elif av == "A":
            score += 2
        elif av == "L":
            score += 1
        if pr == "N":
            score += 2
        elif pr == "L":
            score += 1
        if ui == "N":
            score += 2
        elif ui == "P":
            score += 1
        if ac == "L":
            score += 1

        level = "easy" if score >= 7 else "medium" if score >= 4 else "hard"
        rationale_parts = [
            f"Attack vector: {'remote' if av == 'N' else 'adjacent' if av == 'A' else 'local'}",
            f"Privileges required: {'none' if pr == 'N' else 'low' if pr == 'L' else 'high'}",
            f"User interaction: {'none' if ui == 'N' else 'required'}",
            f"Attack complexity: {'low' if ac == 'L' else 'high'}",
        ]
        return {"level": level, "rationale": "; ".join(rationale_parts), "score": score}

    # ------------------------------------------------------------------ #
    # Remediation recommendations                                         #
    # ------------------------------------------------------------------ #

    def generate_remediation(self, finding: dict[str, Any]) -> str:
        """Generate remediation steps based on vulnerability type."""
        title = finding.get("title", "").lower()
        desc = finding.get("description", "").lower()
        combined = title + " " + desc

        for keyword, steps in _REMEDIATION_TEMPLATES.items():
            if keyword in combined:
                return steps
        return _REMEDIATION_TEMPLATES["default"]

    # ------------------------------------------------------------------ #
    # Priority queue                                                       #
    # ------------------------------------------------------------------ #

    def build_priority_queue(
        self, scored_findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Return findings sorted by composite priority score (highest first).

        Priority = 0.5 * CVSS_v4 + 3.0 * EPSS + 0.3 * business_impact_weight
        """
        heap: list[tuple[float, int, dict[str, Any]]] = []
        for i, f in enumerate(scored_findings):
            priority = f.get("priority_score", 0.0)
            # Use negative for max-heap via heapq (min-heap)
            heapq.heappush(heap, (-priority, i, f))

        return [heapq.heappop(heap)[2] for _ in range(len(heap))]

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _infer_cvss_metrics(self, finding: dict[str, Any]) -> dict[str, str]:
        """Infer CVSS v4.0 metrics from finding fields when not explicitly provided."""
        if "cvss_metrics" in finding:
            return finding["cvss_metrics"]

        severity = finding.get("severity", "info").lower()
        title = finding.get("title", "").lower()
        desc = (finding.get("description", "") + title).lower()

        # Default all metrics to conservative values
        metrics: dict[str, str] = {
            "AV": "N", "AC": "L", "AT": "N",
            "PR": "N", "UI": "N",
            "VC": "N", "VI": "N", "VA": "N",
            "SC": "N", "SI": "N", "SA": "N",
        }

        # Heuristic overrides based on description keywords
        if any(k in desc for k in ["local", "file", "path traversal", "lfi"]):
            metrics["AV"] = "L"
        if any(k in desc for k in ["authenticated", "requires login", "low privilege"]):
            metrics["PR"] = "L"
        if any(k in desc for k in ["admin", "high privilege", "root"]):
            metrics["PR"] = "H"
        if "user interaction" in desc or "click" in desc or "phishing" in desc:
            metrics["UI"] = "P"

        # Impact heuristics
        if severity in ("critical", "high"):
            metrics.update({"VC": "H", "VI": "H", "VA": "H"})
        elif severity == "medium":
            metrics.update({"VC": "L", "VI": "L"})

        if any(k in desc for k in ["rce", "remote code", "command injection", "exec"]):
            metrics.update({"VC": "H", "VI": "H", "VA": "H", "SC": "H", "SI": "H"})
        if any(k in desc for k in ["sql", "database", "data exfil"]):
            metrics.update({"VC": "H", "VI": "H"})
        if any(k in desc for k in ["dos", "denial", "availability"]):
            metrics["VA"] = "H"

        return metrics

    @staticmethod
    def _cvss_severity(score: float) -> str:
        if score == 0.0:
            return "none"
        if score < 4.0:
            return "low"
        if score < 7.0:
            return "medium"
        if score < 9.0:
            return "high"
        return "critical"

    @staticmethod
    def _priority_score(cvss: float, epss: float, impact: dict[str, Any]) -> float:
        impact_weight = {
            "critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "negligible": 0.0
        }.get(impact.get("impact_level", "negligible"), 0.0)
        return round(0.5 * cvss + 3.0 * epss * 10 + 0.3 * impact_weight * 10, 3)
