"""C3 – Report correlation and deduplication.

Provides fuzzy-match deduplication, cosine-similarity scoring, attack chain
construction, confidence scoring, cross-tool evidence merging, and k-means
clustering on severity+category features.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from datetime import datetime
from difflib import SequenceMatcher
from typing import Any

from app.modules.base_module import BaseModule

# ---------------------------------------------------------------------------
# Optional Levenshtein (graceful degradation)
# ---------------------------------------------------------------------------
try:
    from Levenshtein import distance as _lev_distance  # type: ignore

    def levenshtein(a: str, b: str) -> int:
        return _lev_distance(a, b)

except ImportError:
    def levenshtein(a: str, b: str) -> int:
        """Pure-Python Levenshtein distance (fallback)."""
        if a == b:
            return 0
        if len(a) < len(b):
            a, b = b, a
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a):
            curr = [i + 1]
            for j, cb in enumerate(b):
                curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
            prev = curr
        return prev[-1]


# ---------------------------------------------------------------------------
# OWASP attack chain definitions
# ---------------------------------------------------------------------------

_OWASP_CHAINS: list[dict[str, Any]] = [
    {
        "name": "Authentication Bypass → Privilege Escalation",
        "steps": ["A07", "A01"],
        "description": (
            "An authentication bypass (OWASP A07) can be combined with broken "
            "access control (A01) to escalate privileges."
        ),
    },
    {
        "name": "SSRF → Internal Service Compromise",
        "steps": ["A10", "A05"],
        "description": (
            "Server-Side Request Forgery (A10) allows reaching internal services "
            "that may have misconfigurations (A05) or exposed metadata endpoints."
        ),
    },
    {
        "name": "XSS → CSRF → Account Takeover",
        "steps": ["A03", "A01"],
        "description": (
            "Stored XSS (A03) can be used to deliver a CSRF payload, leading to "
            "account takeover via broken access control (A01)."
        ),
    },
    {
        "name": "Injection → Data Exfiltration",
        "steps": ["A03", "A02"],
        "description": (
            "SQL/Command injection (A03) exposes cryptographic failures (A02) "
            "such as plaintext passwords in exfiltrated data."
        ),
    },
    {
        "name": "Misconfiguration → Sensitive Data Exposure",
        "steps": ["A05", "A02"],
        "description": (
            "Security misconfiguration (A05) can expose sensitive data (A02) via "
            "debug endpoints, directory listings, or default credentials."
        ),
    },
]

_SEVERITY_SCORE: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

_CATEGORY_INDEX: dict[str, int] = {
    "A01": 0,
    "A02": 1,
    "A03": 2,
    "A04": 3,
    "A05": 4,
    "A06": 5,
    "A07": 6,
    "A08": 7,
    "A09": 8,
    "A10": 9,
}


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class ReportCorrelator(BaseModule):
    """Correlate, deduplicate, and enrich findings from multiple scanning tools."""

    name = "report_correlator"
    description = (
        "Deduplicate findings via fuzzy matching, build attack chains, compute "
        "confidence scores, merge cross-tool evidence, and cluster findings."
    )
    version = "1.0.0"
    category = "reporting"

    _SIMILARITY_THRESHOLD = 0.75  # SequenceMatcher ratio above which findings are dupes

    # ------------------------------------------------------------------ #
    # Public entry-point                                                   #
    # ------------------------------------------------------------------ #

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Correlate findings supplied via *findings* kwarg.

        Args:
            target: Target URL (for context).
            **kwargs:
                - findings (List[Dict]): Raw findings from multiple tools.
                - similarity_threshold (float): Dedup threshold (default 0.75).
        """
        self.started_at = datetime.utcnow()

        raw: list[dict[str, Any]] = kwargs.get("findings", [])
        threshold: float = float(
            kwargs.get("similarity_threshold", self._SIMILARITY_THRESHOLD)
        )

        deduplicated = self.deduplicate(raw, threshold)
        with_confidence = self.score_confidence(deduplicated)
        chains = self.build_attack_chains(with_confidence)
        clusters = self.cluster(with_confidence)

        summary = {
            "original_count": len(raw),
            "deduplicated_count": len(deduplicated),
            "attack_chains": chains,
            "clusters": clusters,
            "findings": with_confidence,
        }

        self.add_finding(
            title="Correlation Report",
            severity="info",
            description=(
                f"Reduced {len(raw)} raw findings to {len(deduplicated)} unique findings "
                f"across {len(clusters)} clusters with {len(chains)} attack chains identified."
            ),
            url=target,
            summary=summary,
        )

        self.completed_at = datetime.utcnow()
        return {**self.to_dict(), "correlation": summary}

    # ------------------------------------------------------------------ #
    # Deduplication                                                        #
    # ------------------------------------------------------------------ #

    def deduplicate(
        self,
        findings: list[dict[str, Any]],
        threshold: float = 0.75,
    ) -> list[dict[str, Any]]:
        """Remove near-duplicate findings using SequenceMatcher + Levenshtein.

        Two findings are considered duplicates when both their title similarity
        ratio AND description similarity ratio exceed *threshold*.  When
        duplicates are found, the evidence from all copies is merged into the
        surviving finding and a ``tools`` list records which tools detected it.
        """
        if not findings:
            return []

        unique: list[dict[str, Any]] = []
        used: list[bool] = [False] * len(findings)

        for i, f in enumerate(findings):
            if used[i]:
                continue
            group: list[dict[str, Any]] = [f]
            used[i] = True

            for j in range(i + 1, len(findings)):
                if used[j]:
                    continue
                if self._are_duplicates(f, findings[j], threshold):
                    group.append(findings[j])
                    used[j] = True

            merged = self._merge_group(group)
            unique.append(merged)

        self.logger.info(
            "Dedup: %d → %d findings (threshold=%.2f)", len(findings), len(unique), threshold
        )
        return unique

    def _are_duplicates(
        self,
        a: dict[str, Any],
        b: dict[str, Any],
        threshold: float,
    ) -> bool:
        title_ratio = SequenceMatcher(
            None, a.get("title", ""), b.get("title", "")
        ).ratio()
        if title_ratio < threshold:
            return False

        # Additional check: cosine similarity on description tokens
        desc_sim = self._cosine_similarity(
            a.get("description", ""), b.get("description", "")
        )
        return desc_sim >= threshold

    def _merge_group(self, group: list[dict[str, Any]]) -> dict[str, Any]:
        """Merge a group of duplicate findings into one enriched finding."""
        base = dict(group[0])

        # Collect all tool sources
        tools: list[str] = []
        evidences: list[str] = []
        for f in group:
            tool = f.get("module") or f.get("tool", "unknown")
            if tool not in tools:
                tools.append(tool)
            ev = f.get("evidence", "")
            if ev and ev not in evidences:
                evidences.append(ev)

        base["tools"] = tools
        base["evidence"] = " | ".join(evidences)
        base["occurrence_count"] = len(group)
        return base

    # ------------------------------------------------------------------ #
    # Cosine similarity                                                    #
    # ------------------------------------------------------------------ #

    def _cosine_similarity(self, text_a: str, text_b: str) -> float:
        """Compute cosine similarity between two text strings (bag-of-words)."""
        tokens_a = Counter(re.findall(r"\w+", text_a.lower()))
        tokens_b = Counter(re.findall(r"\w+", text_b.lower()))

        all_tokens = set(tokens_a) | set(tokens_b)
        if not all_tokens:
            return 0.0

        dot = sum(tokens_a[t] * tokens_b[t] for t in all_tokens)
        mag_a = math.sqrt(sum(v ** 2 for v in tokens_a.values()))
        mag_b = math.sqrt(sum(v ** 2 for v in tokens_b.values()))

        if mag_a == 0 or mag_b == 0:
            return 0.0
        return dot / (mag_a * mag_b)

    # ------------------------------------------------------------------ #
    # Confidence scoring                                                   #
    # ------------------------------------------------------------------ #

    def score_confidence(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Add a ``confidence`` score (0–1) to each finding.

        Confidence increases with:
        - Number of tools that independently detected it.
        - Quality/length of evidence.
        - Severity level.
        """
        scored: list[dict[str, Any]] = []
        for f in findings:
            tool_count = len(f.get("tools", [f.get("module", "unknown")]))
            ev_quality = min(len(f.get("evidence", "")) / 500.0, 1.0)
            severity_weight = _SEVERITY_SCORE.get(f.get("severity", "info"), 1) / 5.0

            # Weighted formula
            confidence = min(
                0.3 * min(tool_count / 3.0, 1.0)
                + 0.4 * ev_quality
                + 0.3 * severity_weight,
                1.0,
            )
            enriched = dict(f)
            enriched["confidence"] = round(confidence, 3)
            scored.append(enriched)
        return scored

    # ------------------------------------------------------------------ #
    # Attack chain builder                                                 #
    # ------------------------------------------------------------------ #

    def build_attack_chains(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Link findings into exploitation chains based on OWASP categories."""
        present_cats: set = {
            f.get("owasp_category", "").upper() for f in findings
        }
        chains: list[dict[str, Any]] = []

        for chain in _OWASP_CHAINS:
            steps_present = [s for s in chain["steps"] if s in present_cats]
            if len(steps_present) >= 2:
                related_findings = [
                    f for f in findings
                    if f.get("owasp_category", "").upper() in chain["steps"]
                ]
                chains.append(
                    {
                        "chain_name": chain["name"],
                        "description": chain["description"],
                        "steps_present": steps_present,
                        "related_findings": [
                            rf.get("title", "Unknown") for rf in related_findings
                        ],
                        "exploitability": "high"
                        if len(steps_present) == len(chain["steps"])
                        else "medium",
                    }
                )
        return chains

    # ------------------------------------------------------------------ #
    # K-means clustering                                                   #
    # ------------------------------------------------------------------ #

    def cluster(
        self,
        findings: list[dict[str, Any]],
        k: int = 4,
    ) -> list[dict[str, Any]]:
        """Cluster findings into *k* groups using severity + category features.

        Each finding is encoded as a 2-dimensional vector:
          [severity_score (1–5), category_index (0–9)]

        Returns a list of cluster dicts with centroid, size, and member titles.
        """
        if not findings:
            return []

        k = min(k, len(findings))
        vectors = [self._feature_vector(f) for f in findings]

        # Initialise centroids to the first k distinct vectors
        centroids: list[list[float]] = [list(v) for v in vectors[:k]]
        assignments: list[int] = [0] * len(vectors)

        for _ in range(20):  # max iterations
            # Assign step
            new_assignments = [
                min(range(k), key=lambda ci: self._euclidean(vectors[i], centroids[ci]))
                for i in range(len(vectors))
            ]
            if new_assignments == assignments:
                break
            assignments = new_assignments

            # Update centroids
            for ci in range(k):
                members = [vectors[i] for i, a in enumerate(assignments) if a == ci]
                if members:
                    centroids[ci] = [
                        sum(m[d] for m in members) / len(members)
                        for d in range(len(members[0]))
                    ]

        # Build output clusters
        cluster_map: dict[int, list[int]] = defaultdict(list)
        for i, a in enumerate(assignments):
            cluster_map[a].append(i)

        clusters: list[dict[str, Any]] = []
        for ci, indices in cluster_map.items():
            members = [findings[i] for i in indices]
            dominant_severity = Counter(
                f.get("severity", "info") for f in members
            ).most_common(1)[0][0]
            clusters.append(
                {
                    "cluster_id": ci,
                    "size": len(members),
                    "dominant_severity": dominant_severity,
                    "centroid": {
                        "severity_score": round(centroids[ci][0], 2),
                        "category_index": round(centroids[ci][1], 2),
                    },
                    "members": [f.get("title", "Unknown") for f in members],
                }
            )
        return sorted(clusters, key=lambda c: -c["size"])

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _feature_vector(self, finding: dict[str, Any]) -> list[float]:
        severity = _SEVERITY_SCORE.get(finding.get("severity", "info"), 1)
        cat = _CATEGORY_INDEX.get(
            finding.get("owasp_category", "").upper(), 5
        )
        return [float(severity), float(cat)]

    @staticmethod
    def _euclidean(a: list[float], b: list[float]) -> float:
        return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b, strict=False)))
