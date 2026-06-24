"""Unit tests for the reporters."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from pysoc.models import Alert, Event, Severity
from pysoc.report import HTMLReporter, JSONReporter, write_html_report
from pysoc.report.base import BaseReporter


def _sample_alerts():
    return [
        Alert(
            rule_id="BF-001",
            rule_name="Brute-force login",
            severity=Severity.HIGH,
            description="6 failed logins for root from 203.0.113.5",
            timestamp=datetime(2026, 3, 7, 14, 11, 0, tzinfo=timezone.utc),
            source_events=("abc", "def"),
            context={"source_ip": "203.0.113.5", "user": "root"},
        ),
        Alert(
            rule_id="WA-001",
            rule_name="Web attack",
            severity=Severity.HIGH,
            description="SQLi probe",
            timestamp=datetime(2026, 3, 7, 14, 5, 0, tzinfo=timezone.utc),
            source_events=("ghi",),
            context={"source_ip": "203.0.113.7"},
        ),
    ]


def _sample_events():
    return [
        Event(timestamp=datetime(2026, 3, 7, 14, 0, 0, tzinfo=timezone.utc),
              source_type="linux_auth", raw={}),
        Event(timestamp=datetime(2026, 3, 7, 14, 0, 5, tzinfo=timezone.utc),
              source_type="nginx", raw={}),
    ]


def test_json_reporter_writes_valid_json(tmp_path: Path):
    out = tmp_path / "report.json"
    JSONReporter(out).render(_sample_alerts(), _sample_events())
    assert out.exists()
    payload = json.loads(out.read_text())
    assert "summary" in payload
    assert "alerts" in payload
    assert payload["summary"]["total_alerts"] == 2
    assert payload["summary"]["by_severity"]["high"] == 2
    assert payload["summary"]["by_rule"]["BF-001"] == 1
    assert payload["summary"]["by_source_type"]["linux_auth"] == 1
    assert len(payload["alerts"]) == 2
    # True-positive estimates are documented priors.
    assert "BF-001" in payload["summary"]["true_positive_estimates"]


def test_html_reporter_writes_html(tmp_path: Path):
    out = tmp_path / "report.html"
    HTMLReporter(out).render(_sample_alerts(), _sample_events())
    assert out.exists()
    html = out.read_text()
    assert "<!doctype html>" in html.lower()
    assert "PySOC" in html
    assert "BF-001" in html
    assert "WA-001" in html
    # KPI tiles should be present.
    assert "Critical" in html
    assert "High" in html
    # False-positive notes section.
    assert "False-Positive" in html or "false-positive" in html


def test_html_reporter_handles_empty_alerts(tmp_path: Path):
    out = tmp_path / "empty.html"
    HTMLReporter(out).render([], [])
    assert out.exists()
    html = out.read_text()
    assert "No alerts" in html


def test_summary_computation_includes_estimates():
    summary = BaseReporter._compute_summary(_sample_alerts(), _sample_events())
    assert summary.total_alerts == 2
    assert summary.by_severity["high"] == 2
    assert summary.by_rule["BF-001"] == 1
    # Estimated TPR priors should be present for every bundled rule.
    for rid in ("BF-001", "SP-001", "WA-001", "IT-001"):
        assert rid in summary.true_positive_estimates


def test_json_reporter_creates_parent_dirs(tmp_path: Path):
    out = tmp_path / "nested" / "deeper" / "report.json"
    JSONReporter(out).render(_sample_alerts(), _sample_events())
    assert out.exists()


def test_legacy_html_report_escapes(tmp_path: Path):
    from pysoc.models import Finding

    out = tmp_path / "report.html"
    write_html_report(
        [Finding(rule_id="<script>", severity="high", title="<b>Injected</b>", description="x", confidence=0.5, evidence=[])],
        out,
    )
    html = out.read_text()
    assert "&lt;script&gt;" in html
    assert "&lt;b&gt;Injected&lt;/b&gt;" in html
