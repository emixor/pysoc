"""Unit tests for Event/Alert models and the geo helper."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from pysoc.geo import country_coords, lookup_country
from pysoc.models import Alert, Event, Severity


def test_event_is_frozen():
    e = Event(timestamp=datetime(2026, 3, 7, tzinfo=timezone.utc), source_type="t", raw={})
    try:
        e.user_name = "alice"  # type: ignore[misc]
        raised = False
    except Exception:
        raised = True
    assert raised, "Event should be immutable"


def test_event_fingerprint_is_stable():
    e1 = Event(timestamp=datetime(2026, 3, 7, tzinfo=timezone.utc), source_type="t", raw={})
    e2 = Event(timestamp=datetime(2026, 3, 7, tzinfo=timezone.utc), source_type="t", raw={})
    assert e1.fingerprint() == e2.fingerprint()


def test_event_fingerprint_changes_with_data():
    e1 = Event(timestamp=datetime(2026, 3, 7, tzinfo=timezone.utc), source_type="t", raw={}, user_name="alice")
    e2 = Event(timestamp=datetime(2026, 3, 7, tzinfo=timezone.utc), source_type="t", raw={}, user_name="bob")
    assert e1.fingerprint() != e2.fingerprint()


def test_event_to_dict_serialises_timestamp():
    e = Event(timestamp=datetime(2026, 3, 7, 14, 0, 0, tzinfo=timezone.utc), source_type="t", raw={})
    d = e.to_dict()
    assert d["timestamp"] == "2026-03-07T14:00:00+00:00"
    # Must be JSON-serialisable.
    json.dumps(d)


def test_severity_from_score():
    assert Severity.from_score(95) == Severity.CRITICAL
    assert Severity.from_score(75) == Severity.HIGH
    assert Severity.from_score(50) == Severity.MEDIUM
    assert Severity.from_score(20) == Severity.LOW
    assert Severity.from_score(5) == Severity.INFO
    # Clamping
    assert Severity.from_score(-10) == Severity.INFO
    assert Severity.from_score(200) == Severity.CRITICAL


def test_alert_to_dict_roundtrip():
    a = Alert(
        rule_id="BF-001",
        rule_name="Brute force",
        severity=Severity.HIGH,
        description="test",
        timestamp=datetime(2026, 3, 7, 14, 0, 0, tzinfo=timezone.utc),
        source_events=("abc", "def"),
        context={"foo": "bar"},
    )
    d = a.to_dict()
    assert d["rule_id"] == "BF-001"
    assert d["severity"] == "high"
    assert d["source_events"] == ["abc", "def"]
    assert d["context"] == {"foo": "bar"}
    json.dumps(d)  # must be JSON-serialisable


def test_geo_lookup_public_ip():
    # First-octet 1 → US
    assert lookup_country("1.2.3.4") == "US"
    # First-octet 5 → CN
    assert lookup_country("5.6.7.8") == "CN"


def test_geo_lookup_private_ip_returns_internal():
    assert lookup_country("10.0.0.5") == "ZZ"  # internal sentinel
    assert lookup_country("127.0.0.1") == "ZZ"
    assert lookup_country("192.168.1.1") == "ZZ"


def test_geo_lookup_invalid_returns_none():
    assert lookup_country("not-an-ip") is None
    assert lookup_country("") is None
    assert lookup_country(None) is None


def test_country_coords_known():
    assert country_coords("US") is not None
    assert country_coords("us") == country_coords("US")
    assert country_coords("XX") is not None  # unknown sentinel
    assert country_coords(None) is None
