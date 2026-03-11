"""Base class for all OWASP Sentinel custom security modules."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any


class BaseModule(ABC):
    """Base class for all OWASP Sentinel custom security modules."""

    name: str = ""
    description: str = ""
    version: str = "1.0.0"
    category: str = ""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.logger = logging.getLogger(f"owasp_sentinel.modules.{self.name}")
        self.results: list[dict[str, Any]] = []
        self.started_at: datetime | None = None
        self.completed_at: datetime | None = None

    @abstractmethod
    async def run(self, target: str, **kwargs) -> dict[str, Any]:
        """Execute the module against a target. Returns dict with findings."""
        ...

    def get_results(self) -> list[dict[str, Any]]:
        """Return all findings collected during the run."""
        return self.results

    def add_finding(
        self,
        title: str,
        severity: str,
        description: str,
        evidence: str = "",
        url: str = "",
        **extra: Any,
    ) -> None:
        """Append a structured finding to the results list.

        Args:
            title: Short finding title.
            severity: One of critical/high/medium/low/info.
            description: Full description of the finding.
            evidence: Raw evidence (response headers, body excerpt, etc.).
            url: Affected URL.
            **extra: Any additional key/value pairs to include.
        """
        self.results.append(
            {
                "title": title,
                "severity": severity,
                "description": description,
                "evidence": evidence,
                "url": url,
                "module": self.name,
                "timestamp": datetime.utcnow().isoformat(),
                **extra,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise module metadata and results to a plain dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "category": self.category,
            "results": self.results,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
