"""
High-level pipeline orchestrator.

``run_pipeline`` ties together ingestion, detection, and reporting. It is the
single entry point used by the CLI and by the integration tests.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Optional, Union

from .detect import all_detectors
from .detect.base import BaseDetector
from .ingest import ingest_paths
from .models import Alert, Event
from .report import HTMLReporter, JSONReporter
from .report.base import BaseReporter, ReportSummary


def run_pipeline(
    paths: Iterable[Union[str, Path]],
    detectors: Optional[Iterable[BaseDetector]] = None,
    json_out: Optional[Union[str, Path]] = None,
    html_out: Optional[Union[str, Path]] = None,
    parser_name: Optional[str] = None,
) -> dict:
    """End-to-end PySOC run.

    Parameters
    ----------
    paths:
        Iterable of log file paths.
    detectors:
        Iterable of detector instances. Defaults to ``all_detectors()``.
    json_out:
        If set, write a JSON report to this path.
    html_out:
        If set, write an HTML report to this path.
    parser_name:
        Force a specific parser. ``None`` = auto-detect.

    Returns
    -------
    dict
        ``{"events": [...], "alerts": [...], "summary": {...}}``
    """
    events: List[Event] = list(ingest_paths(paths, parser_name=parser_name))
    if detectors is None:
        detectors = all_detectors()

    alerts: List[Alert] = []
    for d in detectors:
        alerts.extend(d.analyze(events))
        # Detectors that buffer state can flush any remaining alerts.
        alerts.extend(d.finalize())

    # Sort alerts by timestamp (descending) so the report shows newest first.
    alerts.sort(key=lambda a: a.timestamp, reverse=True)

    summary = BaseReporter._compute_summary(alerts, events)

    if json_out:
        JSONReporter(json_out).render(alerts, events, summary)
    if html_out:
        HTMLReporter(html_out).render(alerts, events, summary)

    return {
        "events": events,
        "alerts": alerts,
        "summary": summary.to_dict(),
    }
