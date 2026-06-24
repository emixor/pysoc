# Development Guide

This document explains how to add a new detector, parser, or reporter to
PySOC — following the same Test-Driven Development (TDD) workflow used to
build the core.

## Prerequisites

```bash
pip install -e ".[dev]"
```

This installs `pytest` and `pytest-cov`. PySOC has **zero runtime
dependencies**, and we'd like to keep it that way — please discuss before
adding any.

## TDD workflow

The rule is simple: **write the test first, watch it fail, then implement
until it passes.**

```bash
# 1. Run all tests — they should be green.
pytest

# 2. Write your new test (see recipe below). Watch it fail.
pytest tests/unit/test_my_new_detector.py

# 3. Implement the detector. Watch the test pass.
pytest tests/unit/test_my_new_detector.py

# 4. Run the full suite to check for regressions.
pytest
```

## Recipe: Adding a new detector

Let's say we want to add a detector for "user added to local
administrators group" (Windows EventID 4732).

### Step 1 — Write the test

Create `tests/unit/test_detect_admin_group_add.py`:

```python
"""Unit tests for rule AG-001 — user added to local admins."""
from datetime import datetime, timezone

from pysoc.detect import AdminGroupAddDetector
from pysoc.models import Severity


def test_fires_on_4732_event():
    evt = Event(
        timestamp=datetime(2026, 3, 7, 14, 0, 0, tzinfo=timezone.utc),
        source_type="windows_json",
        raw={},
        user_name="newadmin",
        event_action="group_member_add",
        event_outcome="success",
        labels={"event_id": "4732", "group": "Administrators"},
    )
    alerts = AdminGroupAddDetector().analyze([evt])
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "AG-001"
    assert a.severity == Severity.HIGH
    assert a.context["user"] == "newadmin"
    assert a.context["group"] == "Administrators"


def test_does_not_fire_on_non_admin_group():
    evt = Event(
        timestamp=datetime(2026, 3, 7, 14, 0, 0, tzinfo=timezone.utc),
        source_type="windows_json",
        raw={},
        user_name="newuser",
        event_action="group_member_add",
        event_outcome="success",
        labels={"event_id": "4732", "group": "Remote Desktop Users"},
    )
    alerts = AdminGroupAddDetector().analyze([evt])
    assert alerts == []
```

Run it — it should fail with `ImportError` (the detector doesn't exist yet).

### Step 2 — Implement the detector

Create `src/pysoc/detect/admin_group_add.py`:

```python
"""
Detector for rule AG-001 — user added to local administrators group.

Fires on Windows EventID 4732 (A member was added to a security-enabled
local group) when the target group is "Administrators".
"""

from __future__ import annotations
from typing import Iterable, List

from ..models import Alert, Event, Severity
from .base import BaseDetector

_ADMIN_GROUPS = {"administrators", "admins", "sudo", "wheel"}


class AdminGroupAddDetector(BaseDetector):
    rule_id = "AG-001"
    rule_name = "User added to local administrators group"
    default_severity = Severity.HIGH
    description = (
        "Fires on Windows EventID 4732 when a user is added to a local "
        "administrators group. This is a classic privilege-escalation "
        "indicator."
    )

    def analyze(self, events: Iterable[Event]) -> List[Alert]:
        alerts: List[Alert] = []
        for e in events:
            if e.event_action != "group_member_add":
                continue
            group = (e.labels.get("group") or "").lower()
            if group not in _ADMIN_GROUPS:
                continue
            alerts.append(Alert(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                description=(
                    f"User '{e.user_name}' added to local admins group "
                    f"'{e.labels.get('group')}'"
                ),
                timestamp=e.timestamp,
                source_events=(e.fingerprint(),),
                context={
                    "user": e.user_name,
                    "group": e.labels.get("group"),
                    "event_id": e.labels.get("event_id"),
                    "mitre_attack_ids": ["T1098"],
                    "note": (
                        "FP: legitimate helpdesk escalation. Check if "
                        "user_name matches a helpdesk ticket."
                    ),
                },
            ))
        return alerts
```

### Step 3 — Register the detector

Edit `src/pysoc/detect/__init__.py`:

```python
from .admin_group_add import AdminGroupAddDetector

DETECTORS = {
    "BF-001": BruteForceDetector,
    "SP-001": SuspiciousProcessDetector,
    "WA-001": WebAttackDetector,
    "IT-001": ImpossibleTravelDetector,
    "AG-001": AdminGroupAddDetector,   # ← new
}
```

### Step 4 — Run the tests

```bash
pytest tests/unit/test_detect_admin_group_add.py -v
pytest                          # full suite must stay green
```

### Step 5 — Document the rule

Add a section to [`docs/DETECTION_RULES.md`](DETECTION_RULES.md) following
the existing format (rule ID, source, MITRE ATT&CK, severity, tuning,
trigger, sample alert, test coverage).

### Step 6 — Update the data generator (optional)

If your rule needs mock data to fire in the integration test, edit
[`data/generator/generate_logs.py`](../data/generator/generate_logs.py)
to produce a record that triggers it.

### Step 7 — Update the changelog

Add an entry to [`CHANGELOG.md`](../CHANGELOG.md) under `[Unreleased]`:

```markdown
### Added
- AG-001: detector for user-added-to-local-administrators-group (Windows 4732).
```

## Recipe: Adding a new parser

The process is identical, except:

1. Subclass `BaseParser` from `src/pysoc/parsers/base.py`.
2. Implement `parse_line` (line-oriented) or `parse_record` (JSON).
3. Register in `src/pysoc/parsers/__init__.py` (`PARSERS` + `EXTENSION_MAP`).
4. Add at least one happy-path test and one negative test.

## Recipe: Adding a new reporter

1. Subclass `BaseReporter` from `src/pysoc/report/base.py`.
2. Implement `_render(alerts, events, summary) -> Path`.
3. Reuse `BaseReporter._compute_summary` to ensure your reporter agrees
   with the JSON/HTML reporters on headline numbers.
4. Add a test that round-trips a small fixture through your reporter.

## Code style

- PEP 8, 100-char line length.
- Type hints on every public function.
- Docstrings on every module, class, and public function (Google style).
- `from __future__ import annotations` at the top of every module.
- No `print()` in library code — use `logging`. `print()` is OK in CLI.
- Imports: stdlib → third-party → `pysoc.*`, separated by blank lines.

## Running the validation locally

```bash
pytest                                  # full suite
pytest tests/unit                       # unit only
pytest tests/integration                # integration only
pytest --cov=pysoc --cov-report=term-missing   # with coverage
pytest -k brute_force                   # by name pattern
pytest -x                               # stop on first failure
```

The full suite runs in under 1 second on a modern laptop — there is no
excuse for skipping tests.
