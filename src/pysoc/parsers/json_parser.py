"""
Generic JSON-lines parser.

A JSON-lines file has one JSON object per line::

    {"timestamp": "2026-03-07T14:32:01Z", "event": {"action": "login", ...}}
    {"timestamp": "2026-03-07T14:32:05Z", "event": {"action": "http_request", ...}}

This parser is intentionally generic: it expects a flat dict whose keys map
*directly* to :class:`~pysoc.models.Event` field names (snake_case). It is
useful for ingesting logs that have already been pre-normalised (e.g., from a
Filebeat/Logstash pipeline).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from ..models import Event
from .base import BaseParser


def _parse_iso_ts(value: str) -> datetime:
    """Parse an ISO-8601 timestamp into a UTC-aware datetime.

    Accepts both ``"...Z"`` and ``"...+00:00"`` suffixes.
    """
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# Fields we attempt to lift from the JSON object into the Event dataclass.
_KNOWN_FIELDS = {
    "user_name", "user_id",
    "source_ip", "source_port", "source_geo_country",
    "destination_ip", "destination_port", "destination_host",
    "event_action", "event_outcome", "event_reason",
    "process_name", "process_command_line", "process_parent_name", "process_pid",
    "http_method", "http_url", "http_status_code", "http_user_agent",
    "auth_method",
}


class JSONLinesParser(BaseParser):
    """Parse JSON-lines files where each line is one event."""

    name = "json"
    source_type = "json"

    def parse_line(self, line: str) -> Optional[Event]:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(obj, dict):
            return None
        ts_value = obj.get("timestamp")
        if not ts_value:
            return None
        ts = _parse_iso_ts(ts_value) if isinstance(ts_value, str) else ts_value

        kwargs = {"raw": obj}
        for f in _KNOWN_FIELDS:
            if f in obj and obj[f] is not None:
                kwargs[f] = obj[f]
        # Labels: any unknown keys are stashed in ``labels``.
        labels = {k: str(v) for k, v in obj.items() if k not in _KNOWN_FIELDS and k != "timestamp"}
        if labels:
            kwargs["labels"] = labels
        try:
            return Event(timestamp=ts, source_type=obj.get("source_type", "json"), **kwargs)
        except TypeError:
            return None
