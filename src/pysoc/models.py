"""Canonical data models for PySOC, including legacy compatibility types."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


class Severity(str, Enum):
    """Enumeration of alert severities, ordered low → critical."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: "Severity") -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: "Severity") -> bool:
        return self < other or self == other

    def __gt__(self, other: "Severity") -> bool:
        return not self <= other

    def __ge__(self, other: "Severity") -> bool:
        return not self < other

    @classmethod
    def from_score(cls, score: int) -> "Severity":
        score = max(0, min(100, int(score)))
        if score >= 90:
            return cls.CRITICAL
        if score >= 70:
            return cls.HIGH
        if score >= 40:
            return cls.MEDIUM
        if score >= 10:
            return cls.LOW
        return cls.INFO


@dataclass(frozen=True)
class Event:
    """A single normalised log record used by the richer PySOC pipeline."""

    timestamp: datetime
    source_type: str
    raw: Dict[str, Any]

    user_name: Optional[str] = None
    user_id: Optional[str] = None

    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    source_geo_country: Optional[str] = None

    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    destination_host: Optional[str] = None

    event_action: Optional[str] = None
    event_outcome: Optional[str] = None
    event_reason: Optional[str] = None

    process_name: Optional[str] = None
    process_command_line: Optional[str] = None
    process_parent_name: Optional[str] = None
    process_pid: Optional[int] = None

    http_method: Optional[str] = None
    http_url: Optional[str] = None
    http_status_code: Optional[int] = None
    http_user_agent: Optional[str] = None

    auth_method: Optional[str] = None
    labels: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d

    def fingerprint(self) -> str:
        payload = json.dumps(self.to_dict(), sort_keys=True, default=str)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Alert:
    """A detection finding emitted by a detector in the richer pipeline."""

    rule_id: str
    rule_name: str
    severity: Severity
    description: str
    timestamp: datetime
    source_events: tuple = field(default_factory=tuple)
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "source_events": list(self.source_events),
            "context": self.context,
        }


@dataclass
class NormalizedEvent:
    """Legacy compatibility event model used by the smaller repo."""

    timestamp: datetime
    event_type: str
    source: str
    host: str | None = None
    user: str | None = None
    ip: str | None = None
    raw_message: str = ""
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data


@dataclass
class Finding:
    """Legacy compatibility finding model used by the smaller repo."""

    rule_id: str
    severity: str
    title: str
    description: str
    confidence: float
    evidence: list[dict[str, Any]]
    first_seen: str | None = None
    last_seen: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
