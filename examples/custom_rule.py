"""
Example: How to add a custom detector to PySOC.

This script defines a *new* detector (not shipped with PySOC) and runs it
against the generated mock data. The detector fires when the same source
IP appears in **both** a failed login AND a successful login within 5
minutes — a classic credential-stuffing success indicator.

Run::

    python examples/custom_rule.py
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Iterable, List

# Make pysoc importable.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysoc.detect.base import BaseDetector  # noqa: E402
from pysoc.models import Alert, Event, Severity  # noqa: E402
from pysoc.pipeline import run_pipeline  # noqa: E402


class CredentialStuffingSuccessDetector(BaseDetector):
    """Rule CS-001 — failed login followed by success from same IP within 5 min."""

    rule_id = "CS-001"
    rule_name = "Credential-stuffing success (failed then success from same IP)"
    default_severity = Severity.CRITICAL
    description = (
        "Fires when a source IP first produces one or more failed logins "
        "and then a successful login within 5 minutes. This is a strong "
        "indicator that a brute-force/credential-stuffing attack succeeded."
    )

    def __init__(self, window_seconds: int = 300) -> None:
        super().__init__()
        self.window = timedelta(seconds=window_seconds)

    def analyze(self, events: Iterable[Event]) -> List[Alert]:
        by_ip: dict[str, List[Event]] = defaultdict(list)
        for e in events:
            if e.event_action != "login":
                continue
            if not e.source_ip:
                continue
            by_ip[e.source_ip].append(e)

        alerts: List[Alert] = []
        for ip, evs in by_ip.items():
            evs.sort(key=lambda x: x.timestamp)
            for i, e in enumerate(evs):
                if e.event_outcome != "success":
                    continue
                # Look back for any failure from this IP within the window.
                prior_failures = [
                    p for p in evs[:i]
                    if p.event_outcome == "failure"
                    and e.timestamp - p.timestamp <= self.window
                ]
                if prior_failures:
                    alerts.append(Alert(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        description=(
                            f"Successful login for '{e.user_name}' from {ip} "
                            f"followed {len(prior_failures)} failed login(s) "
                            f"within {int(self.window.total_seconds())}s"
                        ),
                        timestamp=e.timestamp,
                        source_events=(e.fingerprint(),)
                                     + tuple(p.fingerprint() for p in prior_failures),
                        context={
                            "source_ip": ip,
                            "user": e.user_name,
                            "failed_attempts": len(prior_failures),
                            "first_failure_at": prior_failures[0].timestamp.isoformat(),
                            "success_at": e.timestamp.isoformat(),
                            "mitre_attack_ids": ["T1110.004"],  # Credential Stuffing
                            "note": (
                                "FP: a user fat-fingering their password then "
                                "succeeding. Check if the user_name matches the "
                                "IP's normal pattern."
                            ),
                        },
                    ))
        return alerts


def main() -> int:
    # Generate mock data
    data_dir = Path(tempfile.mkdtemp()) / "raw"
    repo_root = Path(__file__).resolve().parents[1]
    subprocess.run(
        [sys.executable, str(repo_root / "data" / "generator" / "generate_logs.py"),
         "--out", str(data_dir), "--seed", "42"],
        check=True,
    )

    # Run the pipeline with the standard detectors PLUS our custom one.
    # We pass an explicit `detectors` list so the pipeline does not invoke
    # the default registry.
    result = run_pipeline(
        [data_dir / "auth.log"],
        detectors=[CredentialStuffingSuccessDetector()],
    )

    print(f"\nCustom detector produced {len(result['alerts'])} alert(s):\n")
    for a in result["alerts"]:
        print(f"  [{a.severity.value}] {a.rule_id}  {a.description}")
        for k, v in a.context.items():
            print(f"      {k}: {v}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
