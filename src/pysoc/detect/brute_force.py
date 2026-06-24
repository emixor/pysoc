"""
Brute-force login detector (rule ``BF-001``).

Strategy
--------
Group failed-login events by ``(source_ip, user_name)`` and apply a sliding
window:

* If **>= ``threshold``** failed logins occur within **``window_seconds`**
  seconds** from the same source IP targeting the same user → emit a
  ``HIGH`` alert.

Tuning
------
Defaults (5 failures / 600 s) follow the SANS threshold for SSH brute-force.
For Windows 4625 events, the same defaults work well; the field
``auth_method`` lets the analyst tell SSH-vs-Windows apart at report time.

False positives
---------------
See ``docs/FALSE_POSITIVES.md`` for the full list and how PySOC suppresses
them. The most common are:

* Load balancers / health-check probes that use the wrong credentials.
* A script that retries with an expired password.

PySOC emits the alert but tags the context with ``note`` so the analyst can
triage quickly.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Tuple

from ..models import Alert, Event, Severity
from .base import BaseDetector


class BruteForceDetector(BaseDetector):
    """Detect brute-force login attempts.

    Parameters
    ----------
    threshold:
        Number of failed logins within ``window_seconds`` required to fire.
    window_seconds:
        Size of the sliding window, in seconds.
    severity:
        Override the default severity.
    """

    rule_id = "BF-001"
    rule_name = "Brute-force login (SSH/Windows)"
    default_severity = Severity.HIGH
    description = (
        "Fires when >= threshold failed login attempts occur from the same "
        "source IP against the same user within a sliding time window."
    )

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 600,
        severity: Severity | None = None,
    ) -> None:
        super().__init__(severity=severity)
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

    def analyze(self, events: Iterable[Event]) -> List[Alert]:
        # Bucket failures by (source_ip, user_name).
        buckets: Dict[Tuple[str, str], List[Event]] = defaultdict(list)
        for e in events:
            if e.event_action != "login":
                continue
            if e.event_outcome != "failure":
                continue
            if not e.source_ip or not e.user_name:
                continue
            buckets[(e.source_ip, e.user_name)].append(e)

        alerts: List[Alert] = []
        for (ip, user), evs in buckets.items():
            evs.sort(key=lambda x: x.timestamp)
            # Sliding window: for each event, count failures in the trailing
            # window. As soon as the count crosses the threshold, emit one
            # alert summarising the burst and skip ahead.
            i = 0
            while i < len(evs):
                j = i
                while j < len(evs) and evs[j].timestamp - evs[i].timestamp <= self.window:
                    j += 1
                burst = evs[i:j]
                if len(burst) >= self.threshold:
                    last = burst[-1]
                    alerts.append(Alert(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        description=(
                            f"{len(burst)} failed logins for user '{user}' "
                            f"from {ip} within "
                            f"{int((burst[-1].timestamp - burst[0].timestamp).total_seconds())}s"
                        ),
                        timestamp=last.timestamp,
                        source_events=tuple(e.fingerprint() for e in burst),
                        context={
                            "source_ip": ip,
                            "user": user,
                            "failed_attempts": len(burst),
                            "window_seconds": int(self.window.total_seconds()),
                            "first_seen": burst[0].timestamp.isoformat(),
                            "last_seen": burst[-1].timestamp.isoformat(),
                            "auth_methods": sorted({e.auth_method or "unknown" for e in burst}),
                            "source_types": sorted({e.source_type for e in burst}),
                            "note": (
                                "Possible false positives: load-balancer health "
                                "checks, scripts with expired password. "
                                "Correlate with successful login from same IP."
                            ),
                        },
                    ))
                    # Skip past this burst so we don't emit overlapping alerts.
                    i = j
                else:
                    i += 1
        return alerts
