"""Unit tests for the impossible-travel detector (rule IT-001)."""
from __future__ import annotations

from pysoc.detect import ImpossibleTravelDetector
from pysoc.models import Severity


def test_fires_on_impossible_travel(impossible_travel_pair):
    alerts = ImpossibleTravelDetector().analyze(impossible_travel_pair)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "IT-001"
    assert a.severity == Severity.MEDIUM
    assert a.context["from_country"] == "US"
    assert a.context["to_country"] == "CN"
    assert a.context["distance_km"] > 5000  # US ↔ CN is ~11,000 km
    assert a.context["implied_speed_kmh"] > 900


def test_does_not_fire_on_same_country(same_country_logins):
    alerts = ImpossibleTravelDetector().analyze(same_country_logins)
    assert alerts == []


def test_does_not_fire_on_internal_ips():
    """Two logins from RFC1918 addresses should not fire."""
    from tests.conftest import E
    events = [
        E(source_type="json", user_name="alice", source_ip="10.0.0.1",
          event_action="login", event_outcome="success",
          timestamp=__import__("datetime").datetime(2026, 3, 7, 14, 0, 0, tzinfo=__import__("datetime").timezone.utc)),
        E(source_type="json", user_name="alice", source_ip="10.0.0.2",
          event_action="login", event_outcome="success",
          timestamp=__import__("datetime").datetime(2026, 3, 7, 14, 5, 0, tzinfo=__import__("datetime").timezone.utc)),
    ]
    alerts = ImpossibleTravelDetector().analyze(events)
    assert alerts == []


def test_falls_back_to_geo_lookup_when_country_missing():
    """If source_geo_country is None, the detector should look up the IP."""
    from datetime import datetime, timezone
    from tests.conftest import E
    events = [
        E(source_type="json", user_name="alice", source_ip="1.2.3.4",
          event_action="login", event_outcome="success",
          timestamp=datetime(2026, 3, 7, 14, 0, 0, tzinfo=timezone.utc)),
        E(source_type="json", user_name="alice", source_ip="5.6.7.8",
          event_action="login", event_outcome="success",
          timestamp=datetime(2026, 3, 7, 14, 30, 0, tzinfo=timezone.utc)),
    ]
    alerts = ImpossibleTravelDetector().analyze(events)
    assert len(alerts) == 1
    assert alerts[0].context["from_country"] == "US"
    assert alerts[0].context["to_country"] == "CN"


def test_does_not_fire_when_speed_below_threshold():
    """User logs in from US then CN 24 hours later — physically possible."""
    from datetime import datetime, timedelta, timezone
    from tests.conftest import E
    base = datetime(2026, 3, 7, 14, 0, 0, tzinfo=timezone.utc)
    events = [
        E(source_type="json", user_name="alice", source_ip="1.2.3.4",
          source_geo_country="US",
          event_action="login", event_outcome="success",
          timestamp=base),
        E(source_type="json", user_name="alice", source_ip="5.6.7.8",
          source_geo_country="CN",
          event_action="login", event_outcome="success",
          timestamp=base + timedelta(hours=24)),
    ]
    alerts = ImpossibleTravelDetector().analyze(events)
    assert alerts == []


def test_only_success_logins_considered(brute_force_events):
    """Failed logins must not trigger impossible-travel."""
    alerts = ImpossibleTravelDetector().analyze(brute_force_events)
    assert alerts == []
