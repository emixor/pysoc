"""
JSON reporter — writes a single JSON file with summary + alerts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from ..models import Alert, Event
from .base import BaseReporter, ReportSummary


class JSONReporter(BaseReporter):
    """Render alerts as a JSON file."""

    def _render(
        self,
        alerts: List[Alert],
        events: List[Event],
        summary: ReportSummary,
    ) -> Path:
        payload = {
            "summary": summary.to_dict(),
            "alerts": [a.to_dict() for a in alerts],
            "event_count": len(events),
        }
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_text(
            json.dumps(payload, indent=2, default=str),
            encoding="utf-8",
        )
        return self.output_path
