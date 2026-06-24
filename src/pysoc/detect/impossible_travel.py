"""
Impossible-travel detector (rule ``IT-001``).

Strategy
--------
For each user, sort successful-login events chronologically. For each
*consecutive* pair ``(a, b)``:

* Compute the great-circle distance between ``a.source_geo_country`` and
  ``b.source_geo_country``.
* Compute the time delta ``b.timestamp - a.timestamp``.
* Compute the implied ground speed = distance / delta_hours.
* If the implied speed exceeds ``max_speed_kmh`` (default 900 km/h — roughly
  the cruising speed of a commercial airliner) **and** the distance is
  non-trivial (>= ``min_distance_km``, default 500 km), emit a ``MEDIUM``
  alert.

Rationale
---------
The detector answers the question: *"Could the same human being have logged
in from country A at 14:00 and from country B at 14:30?"* If not, the second
login is suspicious — possibly stolen credentials.

Caveats
-------
* VPNs / corporate proxies can cause false positives when an employee's
  traffic egresses from different POPs. The detector emits the alert with
  context so the analyst can correlate.
* Country-level resolution is intentionally coarse; the same detector at
  city-level would have a much tighter max-speed threshold.
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import timedelta
from typing import Dict, Iterable, List, Tuple

from ..geo import country_coords, lookup_country
from ..models import Alert, Event, Severity
from .base import BaseDetector


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in km between two ``(lat, lon)`` pairs."""
    R = 6371.0  # Earth radius, km
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


class ImpossibleTravelDetector(BaseDetector):
    """Detect impossible-travel login patterns."""

    rule_id = "IT-001"
    rule_name = "Impossible travel (anomalous geo-velocity)"
    default_severity = Severity.MEDIUM
    description = (
        "Fires when the same user logs in successfully from two locations "
        "that are too far apart to be physically traversed in the time "
        "elapsed between the two logins."
    )

    def __init__(
        self,
        max_speed_kmh: int = 900,
        min_distance_km: int = 500,
        severity: Severity | None = None,
    ) -> None:
        super().__init__(severity=severity)
        self.max_speed_kmh = max_speed_kmh
        self.min_distance_km = min_distance_km

    def analyze(self, events: Iterable[Event]) -> List[Alert]:
        # Bucket successful logins by user_name. We exclude logins whose
        # source IP resolves to an internal/unknown country (e.g. 127.0.0.1
        # or RFC1918) because they would otherwise sit between two
        # geo-distant logins and break the consecutive-pair analysis.
        buckets: Dict[str, List[Event]] = defaultdict(list)
        for e in events:
            if e.event_action != "login":
                continue
            if e.event_outcome != "success":
                continue
            if not e.user_name or not e.source_ip:
                continue
            c = e.source_geo_country or lookup_country(e.source_ip)
            if not c or c in ("ZZ", "XX"):
                continue
            buckets[e.user_name].append(e)

        alerts: List[Alert] = []
        for user, evs in buckets.items():
            evs.sort(key=lambda x: x.timestamp)
            for a, b in zip(evs, evs[1:]):
                # Resolve country for each side. Prefer pre-resolved
                # source_geo_country; fall back to lookup_country().
                c_a = a.source_geo_country or lookup_country(a.source_ip)
                c_b = b.source_geo_country or lookup_country(b.source_ip)
                if not c_a or not c_b:
                    continue
                # Skip if either side is "internal" / "unknown".
                if c_a in ("ZZ", "XX") or c_b in ("ZZ", "XX"):
                    continue
                if c_a == c_b:
                    continue
                coord_a = country_coords(c_a)
                coord_b = country_coords(c_b)
                if not coord_a or not coord_b:
                    continue
                distance = _haversine_km(*coord_a, *coord_b)
                if distance < self.min_distance_km:
                    continue
                delta = b.timestamp - a.timestamp
                delta_h = delta.total_seconds() / 3600.0
                if delta_h <= 0:
                    continue
                implied_speed = distance / delta_h
                if implied_speed <= self.max_speed_kmh:
                    continue
                alerts.append(Alert(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    description=(
                        f"Impossible travel for user '{user}': login from "
                        f"{c_a} at {a.timestamp.isoformat()} then from "
                        f"{c_b} at {b.timestamp.isoformat()} "
                        f"({distance:.0f} km in {delta})."
                    ),
                    timestamp=b.timestamp,
                    source_events=(a.fingerprint(), b.fingerprint()),
                    context={
                        "user": user,
                        "from_country": c_a,
                        "to_country": c_b,
                        "from_ip": a.source_ip,
                        "to_ip": b.source_ip,
                        "distance_km": round(distance, 1),
                        "time_delta_seconds": int(delta.total_seconds()),
                        "implied_speed_kmh": round(implied_speed, 1),
                        "max_speed_kmh": self.max_speed_kmh,
                        "first_login_at": a.timestamp.isoformat(),
                        "second_login_at": b.timestamp.isoformat(),
                        "note": (
                            "Possible false positives: corporate VPN that "
                            "egresses through different POPs, mobile device "
                            "switching between cell tower and Wi-Fi. "
                            "Correlate with MFA challenge response."
                        ),
                    },
                ))
        return alerts
