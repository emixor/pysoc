"""
Base class for all detectors.

A detector is a stateful object that consumes a stream of
:class:`~pysoc.models.Event` instances and emits
:class:`~pysoc.models.Alert` instances. The detector is allowed to maintain
internal state across calls to :meth:`analyze` (e.g., a sliding window of
failed logins), but it MUST be deterministic: feeding the same event stream
twice must produce the same alerts.

Subclasses MUST override:

* :attr:`rule_id`
* :attr:`rule_name`
* :attr:`default_severity`
* :meth:`analyze`

Subclasses MAY override :meth:`finalize` to emit any pending state at the end
of a stream (e.g., a trailing alert whose threshold was not yet crossed).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, List

from ..models import Alert, Event, Severity


class BaseDetector(ABC):
    """Abstract base class for all PySOC detectors."""

    rule_id: str = "BASE-000"
    rule_name: str = "Base detector"
    default_severity: Severity = Severity.MEDIUM
    description: str = ""

    def __init__(self, severity: Severity | None = None) -> None:
        self.severity = severity or self.default_severity

    @abstractmethod
    def analyze(self, events: Iterable[Event]) -> List[Alert]:
        """Inspect ``events`` and return any alerts that fire.

        Implementations may either:
        * consume the entire stream and emit alerts at the end, or
        * stream events one-by-one and emit alerts as soon as they trigger.

        Either is acceptable; tests must not assume one style or the other.
        """
        raise NotImplementedError

    def finalize(self) -> List[Alert]:
        """Emit any pending state at end-of-stream.

        Default implementation returns an empty list. Detectors that buffer
        events (e.g., sliding-window brute-force) should override this.
        """
        return []

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{self.__class__.__name__} rule_id={self.rule_id!r}>"
