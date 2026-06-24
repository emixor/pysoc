"""Unit tests for the web-attack detector (rule WA-001)."""
from __future__ import annotations

from pysoc.detect import WebAttackDetector
from pysoc.models import Severity


def test_detects_sqli(sqli_request):
    alerts = WebAttackDetector().analyze([sqli_request])
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "WA-001"
    assert any(p.startswith("sqli_") for p in a.context["matched_patterns"])
    assert "T1190" in a.context["mitre_attack_ids"]
    assert a.severity in (Severity.HIGH, Severity.CRITICAL)


def test_detects_xss(xss_request):
    alerts = WebAttackDetector().analyze([xss_request])
    assert len(alerts) == 1
    a = alerts[0]
    assert any(p.startswith("xss_") for p in a.context["matched_patterns"])
    assert "T1059.007" in a.context["mitre_attack_ids"]


def test_detects_path_traversal(path_traversal_request):
    alerts = WebAttackDetector().analyze([path_traversal_request])
    assert len(alerts) == 1
    a = alerts[0]
    assert any(p.startswith("path_traversal_") for p in a.context["matched_patterns"])
    assert "T1083" in a.context["mitre_attack_ids"]
    # The fixture URL is "/../../etc/passwd" which matches BOTH
    # path_traversal_dotdot (HIGH) and path_traversal_etc_passwd (CRITICAL)
    # → the overall severity is CRITICAL.
    assert a.severity == Severity.CRITICAL


def test_no_alert_for_benign_request(benign_web_request):
    alerts = WebAttackDetector().analyze([benign_web_request])
    assert alerts == []


def test_multiple_families_bump_severity():
    """A request that hits both SQLi and path-traversal (etc/passwd) should be CRITICAL."""
    from tests.conftest import E
    evt = E(
        source_type="nginx",
        source_ip="1.2.3.4",
        event_action="http_request",
        event_outcome="success",
        http_method="GET",
        http_url="/search?q=1' OR '1'='1/../../etc/passwd",
        http_status_code=200,
        http_user_agent="curl/8.4.0",
    )
    alerts = WebAttackDetector().analyze([evt])
    assert len(alerts) == 1
    a = alerts[0]
    # path_traversal_etc_passwd is CRITICAL → overall alert is CRITICAL.
    assert a.severity == Severity.CRITICAL
    families = a.context["families_matched"]
    assert len(families) >= 2


def test_detects_ssrf_metadata_endpoint():
    from tests.conftest import E
    evt = E(
        source_type="nginx",
        source_ip="1.2.3.4",
        event_action="http_request",
        event_outcome="success",
        http_method="GET",
        http_url="/fetch?url=http://169.254.169.254/latest/meta-data/",
        http_status_code=200,
        http_user_agent="curl/8.4.0",
    )
    alerts = WebAttackDetector().analyze([evt])
    assert len(alerts) == 1
    assert "ssrf_metadata" in alerts[0].context["matched_patterns"]
    assert alerts[0].severity == Severity.CRITICAL


def test_detects_etc_passwd_in_url():
    from tests.conftest import E
    evt = E(
        source_type="nginx",
        source_ip="1.2.3.4",
        event_action="http_request",
        event_outcome="success",
        http_method="GET",
        http_url="/page?file=/etc/passwd",
        http_status_code=200,
        http_user_agent="curl/8.4.0",
    )
    alerts = WebAttackDetector().analyze([evt])
    assert len(alerts) == 1
    assert "path_traversal_etc_passwd" in alerts[0].context["matched_patterns"]
    assert alerts[0].severity == Severity.CRITICAL


def test_no_alert_for_non_http_events(brute_force_events):
    alerts = WebAttackDetector().analyze(brute_force_events)
    assert alerts == []


def test_url_encoded_traversal():
    from tests.conftest import E
    evt = E(
        source_type="nginx",
        source_ip="1.2.3.4",
        event_action="http_request",
        event_outcome="success",
        http_method="GET",
        http_url="/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        http_status_code=200,
        http_user_agent="curl/8.4.0",
    )
    alerts = WebAttackDetector().analyze([evt])
    assert len(alerts) == 1
    assert "path_traversal_encoded" in alerts[0].context["matched_patterns"]
