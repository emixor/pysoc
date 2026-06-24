"""
Parser for Windows Security Event Log exports (JSON).

Two flavours are supported:

1. **PowerShell ``Get-WinEvent | ConvertTo-Json``** — used by sysadmins who
   want to ship Windows logs to a non-Windows SOC. We focus on the two
   events most useful for detection:

   * **Event ID 4625** — Failed logon (account/credential brute-force).
   * **Event ID 4624** — Successful logon.
   * **Event ID 4688** — Process creation (used by the suspicious-process
     detector for encoded-PowerShell detection).

2. **JSON Lines with a flat schema** (``{event_id, user, source_ip, ...}``)
   — produced by ``pysoc.data.generator.generate_windows_logs``.

The parser is intentionally tolerant: any record that does not match either
schema is silently dropped (counted in :attr:`BaseParser.skipped`).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from ..models import Event
from .base import BaseParser


# PowerShell ConvertTo-Json places properties in a nested "Properties" array
# of ``{Key, Value}`` pairs. We index them by name for the events we care
# about. The "Message" field often contains a friendlier textual rendering.
_WIN_EVENT_ID_RE = re.compile(r"\bEventID\s*[:=]?\s*(\d+)", re.IGNORECASE)


class WindowsJsonParser(BaseParser):
    """Parse Windows Security Event Log JSON exports."""

    name = "windows_json"
    source_type = "windows_json"

    def parse_record(self, record: dict) -> Optional[Event]:
        # Both flavours carry an EventID (or "event_id").
        event_id = record.get("EventID") or record.get("event_id")
        if event_id is None:
            # Try to extract from the textual "Message" field.
            msg = record.get("Message", "") or record.get("message", "")
            m = _WIN_EVENT_ID_RE.search(msg)
            if not m:
                return None
            event_id = int(m.group(1))
        event_id = int(event_id)

        ts = self._extract_timestamp(record)
        if ts is None:
            return None

        if event_id == 4624:
            return self._build_logon(record, ts, success=True)
        if event_id == 4625:
            return self._build_logon(record, ts, success=False)
        if event_id == 4688:
            return self._build_process(record, ts)
        return None

    # The BaseParser text-mode path is not used for JSON parsers; we still
    # implement parse_line so the parser is callable in tests.
    def parse_line(self, line: str) -> Optional[Event]:  # pragma: no cover
        import json
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None
        return self.parse_record(obj)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_timestamp(record: dict) -> Optional[datetime]:
        """Extract a UTC datetime from a Windows event record."""
        for key in ("TimeCreated", "time_created", "TimeGenerated", "timestamp", "@timestamp"):
            v = record.get(key)
            if isinstance(v, datetime):
                return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
            if isinstance(v, str):
                if v.endswith("Z"):
                    v = v[:-1] + "+00:00"
                try:
                    dt = datetime.fromisoformat(v)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt.astimezone(timezone.utc)
                except ValueError:
                    continue
        return None

    @staticmethod
    def _props(record: dict) -> dict:
        """Collapse a Windows ``Properties`` array of ``{Key, Value}`` into a dict."""
        props = {}
        # PowerShell ConvertTo-Json shape:
        #   "Properties": [{"Key": "SubjectUserSid", "Value": "S-1-5-18"}, ...]
        raw_props = record.get("Properties") or record.get("properties") or []
        if isinstance(raw_props, list):
            for item in raw_props:
                if isinstance(item, dict) and "Key" in item and "Value" in item:
                    props[item["Key"]] = item["Value"]
                elif isinstance(item, dict) and "key" in item and "value" in item:
                    props[item["key"]] = item["value"]
        return props

    def _build_logon(self, record: dict, ts: datetime, success: bool) -> Event:
        props = self._props(record)
        user = (props.get("TargetUserName")
                or record.get("TargetUserName")
                or record.get("user_name"))
        ip = (props.get("IpAddress")
              or record.get("IpAddress")
              or record.get("source_ip")
              or "::1")
        # Windows often logs "::1" or "::" for local logons — normalise.
        if ip in ("::1", "::"):
            ip = "127.0.0.1"
        logon_type = props.get("LogonType") or record.get("LogonType")
        return Event(
            timestamp=ts,
            source_type="windows_json",
            raw=record,
            user_name=user,
            source_ip=ip,
            event_action="login",
            event_outcome="success" if success else "failure",
            auth_method=f"windows_logon_type_{logon_type}" if logon_type else "windows",
            labels={"event_id": str(record.get("EventID", record.get("event_id", 0)))},
        )

    def _build_process(self, record: dict, ts: datetime) -> Event:
        props = self._props(record)
        cmd = (props.get("CommandLine")
               or record.get("CommandLine")
               or record.get("process_command_line"))
        name = (props.get("NewProcessName")
                or record.get("NewProcessName")
                or record.get("process_name"))
        parent = (props.get("ParentProcessName")
                  or record.get("ParentProcessName")
                  or record.get("process_parent_name"))
        user = (props.get("SubjectUserName")
                or record.get("SubjectUserName")
                or record.get("user_name"))
        return Event(
            timestamp=ts,
            source_type="windows_json",
            raw=record,
            user_name=user,
            event_action="process_create",
            event_outcome="success",
            process_name=name,
            process_command_line=cmd,
            process_parent_name=parent,
            labels={"event_id": "4688"},
        )
