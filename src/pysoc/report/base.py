"""
Base class for reporters and the shared :class:`ReportSummary` dataclass.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Union

from ..models import Alert, Event, Severity


@dataclass
class ReportSummary:
    """Aggregate statistics computed across all alerts.

    Used both by :class:`JSONReporter` and :class:`HTMLReporter` so the two
    reports always agree on the headline numbers.
    """

    generated_at: datetime
    total_alerts: int = 0
    by_severity: Counter = field(default_factory=Counter)
    by_rule: Counter = field(default_factory=Counter)
    by_source_type: Counter = field(default_factory=Counter)
    true_positive_estimates: dict = field(default_factory=dict)  # rule_id → estimated TPR
    false_positive_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at.isoformat(),
            "total_alerts": self.total_alerts,
            "by_severity": dict(self.by_severity),
            "by_rule": dict(self.by_rule),
            "by_source_type": dict(self.by_source_type),
            "true_positive_estimates": self.true_positive_estimates,
            "false_positive_notes": self.false_positive_notes,
        }


class BaseReporter(ABC):
    """Abstract reporter: takes alerts (and optionally events) and renders."""

    def __init__(self, output_path: Union[str, Path]) -> None:
        self.output_path = Path(output_path)

    def render(
        self,
        alerts: Iterable[Alert],
        events: Optional[Iterable[Event]] = None,
        summary: Optional[ReportSummary] = None,
    ) -> Path:
        """Render the report to disk and return the path written."""
        alerts = list(alerts)
        events = list(events or [])
        if summary is None:
            summary = self._compute_summary(alerts, events)
        return self._render(alerts, events, summary)

    @abstractmethod
    def _render(
        self,
        alerts: List[Alert],
        events: List[Event],
        summary: ReportSummary,
    ) -> Path:
        """Subclasses implement the actual rendering."""

    # ------------------------------------------------------------------
    # Shared summary computation
    # ------------------------------------------------------------------
    @staticmethod
    def _compute_summary(alerts: List[Alert], events: List[Event]) -> ReportSummary:
        summary = ReportSummary(generated_at=datetime.now(timezone.utc))
        summary.total_alerts = len(alerts)
        for a in alerts:
            summary.by_severity[a.severity.value] += 1
            summary.by_rule[a.rule_id] += 1
        for e in events:
            summary.by_source_type[e.source_type] += 1
        # Estimated true-positive rate per rule, derived from internal FP
        # notes (see docs/FALSE_POSITIVES.md). These are documented priors,
        # not measured from this run.
        summary.true_positive_estimates = {
            "BF-001": 0.85,
            "SP-001": 0.95,
            "WA-001": 0.80,
            "IT-001": 0.70,
        }
        summary.false_positive_notes = [
            "BF-001: load balancer / health-check probes; scripts using expired passwords.",
            "SP-001: legitimate admin use of encoded PowerShell; signed vendor installers.",
            "WA-001: security scanners; aggressive WAF probes; legacy app false negatives.",
            "IT-001: corporate VPN egressing through multiple POPs; mobile network hand-off.",
        ]
        return summary
