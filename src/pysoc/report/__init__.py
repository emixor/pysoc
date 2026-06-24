"""
Reporters.

A reporter takes a list of :class:`~pysoc.models.Alert` objects (and
optionally the underlying events) and renders a deliverable:

* :class:`JSONReporter` — machine-readable JSON file (default).
* :class:`HTMLReporter` — static, self-contained HTML dashboard.

Both reporters share a common :class:`BaseReporter` interface so that the
pipeline can swap them at runtime.
"""

from __future__ import annotations

from collections import Counter
from html import escape
from pathlib import Path
import json

from ..models import Finding
from .base import BaseReporter, ReportSummary  # noqa: F401
from .json_reporter import JSONReporter
from .html_reporter import HTMLReporter

__all__ = ["BaseReporter", "ReportSummary", "JSONReporter", "HTMLReporter"]


# ---------------------------------------------------------------------------
# Legacy compatibility report helpers (smaller repo API)
# ---------------------------------------------------------------------------


def findings_summary(findings: list[Finding]) -> dict[str, object]:
    severity_counts = Counter(f.severity for f in findings)
    rule_counts = Counter(f.rule_id for f in findings)
    return {
        "total_findings": len(findings),
        "severity_counts": dict(severity_counts),
        "rule_counts": dict(rule_counts),
        "impact_note": "Prioritize high and critical findings first; measure repeat offenders and recurring patterns.",
    }


def write_json_report(findings: list[Finding], output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "summary": findings_summary(findings),
        "findings": [f.to_dict() for f in findings],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_html_report(findings: list[Finding], output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    summary = findings_summary(findings)
    rows = "\n".join(
        f"<tr><td>{escape(f.rule_id)}</td><td>{escape(f.severity)}</td><td>{escape(f.title)}</td><td>{f.confidence:.2f}</td></tr>"
        for f in findings
    )
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PySOC Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; background: #0b1020; color: #e8eefc; }}
    .card {{ background: #131a33; padding: 1rem 1.25rem; border-radius: 16px; margin-bottom: 1rem; }}
    table {{ width: 100%; border-collapse: collapse; background: #11172b; }}
    th, td {{ border-bottom: 1px solid #253055; padding: 0.75rem; text-align: left; }}
    th {{ background: #18203a; }}
    .muted {{ color: #aab4d6; }}
  </style>
</head>
<body>
  <h1>PySOC Static Report</h1>
  <div class="card">
    <div><strong>Total findings:</strong> {summary["total_findings"]}</div>
    <div class="muted">{escape(str(summary["impact_note"]))}</div>
  </div>
  <div class="card">
    <h2>Findings</h2>
    <table>
      <thead>
        <tr><th>Rule</th><th>Severity</th><th>Title</th><th>Confidence</th></tr>
      </thead>
      <tbody>
        {rows or '<tr><td colspan="4">No findings</td></tr>'}
      </tbody>
    </table>
  </div>
</body>
</html>"""
    path.write_text(html, encoding="utf-8")
    return path
