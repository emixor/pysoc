"""Unit tests for the brute-force detector (rule BF-001)."""
from __future__ import annotations

from pysoc.detect import BruteForceDetector
from pysoc.models import Severity


def test_brute_force_fires_above_threshold(brute_force_events):
    det = BruteForceDetector(threshold=5, window_seconds=600)
    alerts = det.analyze(brute_force_events)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "BF-001"
    assert a.severity == Severity.HIGH
    assert a.context["failed_attempts"] == 6
    assert a.context["source_ip"] == "203.0.113.5"
    assert a.context["user"] == "root"
    assert len(a.source_events) == 6


def test_brute_force_does_not_fire_below_threshold(benign_failed_logins):
    det = BruteForceDetector(threshold=5, window_seconds=600)
    alerts = det.analyze(benign_failed_logins)
    assert alerts == []


def test_brute_force_separates_bursts_by_user(brute_force_events, benign_failed_logins):
    # Combine alice's brute-force (6 failures for 'root') with bob's 3 failures.
    all_events = brute_force_events + benign_failed_logins
    det = BruteForceDetector(threshold=5, window_seconds=600)
    alerts = det.analyze(all_events)
    assert len(alerts) == 1  # only 'root' burst fires
    assert alerts[0].context["user"] == "root"


def test_brute_force_separates_bursts_by_ip(brute_force_events):
    # Same user but different IPs → two buckets.
    from datetime import timedelta
    from tests.conftest import E  # noqa: PLC0415
    other_ip = [
        E(
            source_type="linux_auth",
            user_name="root",
            source_ip="198.51.100.42",
            event_action="login",
            event_outcome="failure",
            auth_method="ssh",
            timestamp=brute_force_events[0].timestamp + timedelta(seconds=i * 7),
        )
        for i in range(5)
    ]
    det = BruteForceDetector(threshold=5, window_seconds=600)
    alerts = det.analyze(brute_force_events + other_ip)
    assert len(alerts) == 2
    ips = {a.context["source_ip"] for a in alerts}
    assert ips == {"203.0.113.5", "198.51.100.42"}


def test_brute_force_window_respected():
    """Failures spread across > window should NOT fire."""
    from datetime import timedelta
    from tests.conftest import E  # noqa: PLC0415
    from datetime import datetime, timezone
    base = datetime(2026, 3, 7, 14, 0, 0, tzinfo=timezone.utc)
    events = [
        E(
            source_type="linux_auth",
            user_name="root",
            source_ip="1.2.3.4",
            event_action="login",
            event_outcome="failure",
            timestamp=base + timedelta(minutes=i * 20),  # 20 minutes apart
        )
        for i in range(6)
    ]
    det = BruteForceDetector(threshold=5, window_seconds=600)  # 10-min window
    alerts = det.analyze(events)
    assert alerts == []


def test_brute_force_includes_auth_methods_in_context(brute_force_events):
    det = BruteForceDetector(threshold=5, window_seconds=600)
    alerts = det.analyze(brute_force_events)
    assert "ssh" in alerts[0].context["auth_methods"]
    assert "linux_auth" in alerts[0].context["source_types"]
