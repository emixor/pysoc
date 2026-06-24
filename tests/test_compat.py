"""Compatibility tests for the legacy PySOC API."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from pysoc.cli import main
from pysoc.detect import DetectionEngine, DetectionConfig
from pysoc.ingest import ingest_logs
from pysoc.models import NormalizedEvent
from pysoc.parser import is_encoded_powershell, parse_line
from pysoc.report import findings_summary, write_html_report, write_json_report


def test_legacy_parser_marks_web_attacks():
    event = parse_line('203.0.113.10 - - [24/Jun/2026:01:02:03 +0000] "GET /?q=../../etc/passwd HTTP/1.1" 200 123')
    assert event is not None
    assert event.event_type == "web_request"
    assert event.metadata["path_traversal"] is True


def test_legacy_detection_engine_fires_expected_findings():
    events = [
        NormalizedEvent(
            timestamp=datetime(2026, 6, 24, 1, 0, tzinfo=timezone.utc),
            event_type="login_success",
            source="windows",
            user="alice",
            ip="198.51.100.1",
            raw_message="success",
        ),
        NormalizedEvent(
            timestamp=datetime(2026, 6, 24, 1, 20, tzinfo=timezone.utc),
            event_type="login_success",
            source="windows",
            user="alice",
            ip="203.0.113.20",
            raw_message="success",
        ),
        NormalizedEvent(
            timestamp=datetime(2026, 6, 24, 1, 1, tzinfo=timezone.utc),
            event_type="process_creation",
            source="windows",
            user="alice",
            ip="198.51.100.1",
            raw_message="powershell.exe -EncodedCommand SQBFAFgA",
        ),
    ]
    findings = DetectionEngine(DetectionConfig()).detect(events)
    rule_ids = {f.rule_id for f in findings}
    assert "encoded_powershell" in rule_ids
    assert "impossible_travel" in rule_ids
    assert findings_summary(findings)["total_findings"] == len(findings)


def test_legacy_reporters_write_files(tmp_path: Path):
    events = ingest_logs(tmp_path) if tmp_path.exists() else []
    sample = tmp_path / "sample.log"
    sample.write_text(
        '{"timestamp":"2026-06-24T01:00:00Z","event_type":"process_creation","source":"windows","host":"ws1","user":"alice","ip":"198.51.100.1","message":"powershell.exe -EncodedCommand SQBFAFgA"}\n',
        encoding="utf-8",
    )
    events = ingest_logs(sample)
    findings = DetectionEngine().detect(events)
    json_path = write_json_report(findings, tmp_path / "out" / "findings.json")
    html_path = write_html_report(findings, tmp_path / "out" / "report.html")
    assert json_path.exists()
    assert html_path.exists()


def test_legacy_cli_mode(tmp_path: Path):
    sample = tmp_path / "sample.log"
    sample.write_text(
        '{"timestamp":"2026-06-24T01:00:00Z","event_type":"process_creation","source":"windows","host":"ws1","user":"alice","ip":"198.51.100.1","message":"powershell.exe -EncodedCommand SQBFAFgA"}\n'
        '{"timestamp":"2026-06-24T01:20:00Z","event_type":"login_success","source":"windows","host":"ws1","user":"alice","ip":"203.0.113.20","message":"success"}\n',
        encoding="utf-8",
    )
    rc = main(["--input", str(sample), "--output", str(tmp_path / "out")])
    assert rc == 0
    assert (tmp_path / "out" / "findings.json").exists()
    assert (tmp_path / "out" / "report.html").exists()


def test_encoded_powershell_helper():
    assert is_encoded_powershell("powershell.exe -EncodedCommand AAAA")
