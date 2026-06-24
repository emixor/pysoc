"""End-to-end integration: generate data → run pipeline → assert alerts."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from pysoc.pipeline import run_pipeline


REPO_ROOT = Path(__file__).resolve().parents[2]
GEN_SCRIPT = REPO_ROOT / "data" / "generator" / "generate_logs.py"


@pytest.fixture(scope="module")
def generated_data(tmp_path_factory):
    """Generate the mock dataset once for the whole module."""
    out = tmp_path_factory.mktemp("pysoc_data") / "raw"
    subprocess.run(
        [sys.executable, str(GEN_SCRIPT), "--out", str(out), "--seed", "42"],
        check=True, capture_output=True,
    )
    return out


def test_end_to_end_pipeline_fires_expected_alerts(generated_data, tmp_path):
    json_out = tmp_path / "report.json"
    html_out = tmp_path / "report.html"

    result = run_pipeline(
        [
            generated_data / "auth.log",
            generated_data / "nginx_access.log",
            generated_data / "apache_access.log",
            generated_data / "windows_events.json",
            generated_data / "impossible_travel.jsonl",
        ],
        json_out=json_out,
        html_out=html_out,
    )

    # Summary-level assertions.
    assert result["summary"]["total_alerts"] > 0
    assert "high" in result["summary"]["by_severity"]
    assert "BF-001" in result["summary"]["by_rule"]
    assert "SP-001" in result["summary"]["by_rule"]
    assert "WA-001" in result["summary"]["by_rule"]
    assert "IT-001" in result["summary"]["by_rule"]

    # Per-rule smoke checks.
    rule_ids = {a.rule_id for a in result["alerts"]}
    assert rule_ids == {"BF-001", "SP-001", "WA-001", "IT-001"}

    # Both reports must have been written.
    assert json_out.exists()
    assert html_out.exists()

    # JSON report must be valid JSON.
    payload = json.loads(json_out.read_text())
    assert payload["summary"]["total_alerts"] == result["summary"]["total_alerts"]

    # HTML report must contain the rule IDs.
    html = html_out.read_text()
    for rid in ("BF-001", "SP-001", "WA-001", "IT-001"):
        assert rid in html


def test_brute_force_detector_catches_root_burst(generated_data):
    """The 8-failure burst for root should produce a BF-001 alert."""
    result = run_pipeline([generated_data / "auth.log"])
    bf_alerts = [a for a in result["alerts"] if a.rule_id == "BF-001"]
    assert any(a.context["user"] == "root" for a in bf_alerts)
    root_alert = next(a for a in bf_alerts if a.context["user"] == "root")
    assert root_alert.context["failed_attempts"] >= 5


def test_brute_force_detector_catches_admin_burst(generated_data):
    """The 6-failure burst for admin from 203.0.113.6 should also fire."""
    result = run_pipeline([generated_data / "auth.log"])
    bf_alerts = [a for a in result["alerts"] if a.rule_id == "BF-001"]
    assert any(a.context["user"] == "admin" for a in bf_alerts)


def test_web_attacks_detected_in_nginx(generated_data):
    result = run_pipeline([generated_data / "nginx_access.log"])
    wa_alerts = [a for a in result["alerts"] if a.rule_id == "WA-001"]
    assert len(wa_alerts) >= 3  # SQLi, XSS, path traversal at minimum
    families_seen = set()
    for a in wa_alerts:
        # Detector stores family as the first underscore-separated token
        # (e.g. "path_traversal_dotdot" → "path"). Map back to full family
        # names so the assertion is readable.
        for fam in a.context["families_matched"]:
            if fam.startswith("sqli"):
                families_seen.add("sqli")
            elif fam.startswith("xss"):
                families_seen.add("xss")
            elif fam.startswith("path"):
                families_seen.add("path_traversal")
            else:
                families_seen.add(fam)
    # Should see at least sqli, xss, path_traversal, ssrf.
    assert {"sqli", "xss", "path_traversal"}.issubset(families_seen)


def test_suspicious_processes_detected_in_windows_events(generated_data):
    result = run_pipeline([generated_data / "windows_events.json"])
    sp_alerts = [a for a in result["alerts"] if a.rule_id == "SP-001"]
    patterns_seen = set()
    for a in sp_alerts:
        patterns_seen.update(a.context["matched_patterns"])
    assert "encoded_powershell" in patterns_seen
    assert "mimikatz" in patterns_seen
    # Word → PowerShell macro-malware pattern.
    assert any("suspicious_parent_child" in p for p in patterns_seen)


def test_windows_brute_force_detected(generated_data):
    """The 7-failure burst against Administrator should fire BF-001."""
    result = run_pipeline([generated_data / "windows_events.json"])
    bf_alerts = [a for a in result["alerts"] if a.rule_id == "BF-001"]
    assert any(a.context["user"] == "Administrator" for a in bf_alerts)


def test_impossible_travel_detected(generated_data):
    result = run_pipeline([generated_data / "impossible_travel.jsonl"])
    it_alerts = [a for a in result["alerts"] if a.rule_id == "IT-001"]
    assert len(it_alerts) == 1
    a = it_alerts[0]
    assert a.context["user"] == "alice"
    assert {a.context["from_country"], a.context["to_country"]} == {"US", "CN"}


def test_pipeline_is_idempotent(generated_data):
    """Running the pipeline twice must produce the same alert count."""
    r1 = run_pipeline([generated_data / "auth.log"])
    r2 = run_pipeline([generated_data / "auth.log"])
    assert len(r1["alerts"]) == len(r2["alerts"])
