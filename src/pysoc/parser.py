"""Legacy parsing helpers compatible with the smaller PySOC API."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from .models import NormalizedEvent

_WINDOWS_DATE_RE = re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?)")
_SSH_RE = re.compile(
    r"(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for "
    r"(?:invalid user\s+)?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
_WEB_RE = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+[^\[]+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>GET|POST|PUT|DELETE|PATCH)\s+(?P<path>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
)
_POWERSHELL_RE = re.compile(r"powershell(?:\.exe)?\b.*-enc(?:odedcommand)?\b|encodedcommand", re.I)
_SQLI_RE = re.compile(r"(?:'\s*or\s*'1'='1|union\s+select|sleep\s*\()", re.I)
_XSS_RE = re.compile(r"(<script|javascript:|onerror=|onload=)", re.I)
_PATH_TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\)", re.I)


def parse_timestamp(value: str) -> datetime:
    if value.endswith("Z"):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return datetime.fromisoformat(value)


def parse_json_event(line: str) -> NormalizedEvent | None:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    if not isinstance(obj, dict):
        return None

    ts_raw = obj.get("timestamp")
    if not isinstance(ts_raw, str):
        return None

    try:
        ts = parse_timestamp(ts_raw)
    except (TypeError, ValueError):
        return None

    return NormalizedEvent(
        timestamp=ts,
        event_type=obj.get("event_type", "unknown"),
        source=obj.get("source", "json"),
        host=obj.get("host"),
        user=obj.get("user"),
        ip=obj.get("ip"),
        raw_message=obj.get("message", ""),
        metadata={k: v for k, v in obj.items() if k not in {"timestamp", "event_type", "source", "host", "user", "ip", "message"}},
    )


def parse_linux_auth(line: str) -> NormalizedEvent | None:
    match = _SSH_RE.search(line)
    if not match:
        return None

    current_year = datetime.now(timezone.utc).year
    ts = datetime.strptime(
        f"{current_year} {match.group('mon')} {match.group('day')} {match.group('time')}",
        "%Y %b %d %H:%M:%S",
    ).replace(tzinfo=timezone.utc)

    return NormalizedEvent(
        timestamp=ts,
        event_type="auth_failure",
        source="linux_auth",
        host=match.group("host"),
        user=match.group("user"),
        ip=match.group("ip"),
        raw_message=line.strip(),
    )


def parse_web_log(line: str) -> NormalizedEvent | None:
    match = _WEB_RE.search(line)
    if not match:
        return None

    ts = datetime.strptime(match.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
    path = match.group("path")
    metadata = {
        "method": match.group("method"),
        "path": path,
        "status": int(match.group("status")),
        "size": match.group("size"),
        "sqli": bool(_SQLI_RE.search(path)),
        "xss": bool(_XSS_RE.search(path)),
        "path_traversal": bool(_PATH_TRAVERSAL_RE.search(path)),
    }
    return NormalizedEvent(
        timestamp=ts,
        event_type="web_request",
        source="web",
        ip=match.group("ip"),
        raw_message=line.strip(),
        metadata=metadata,
    )


def parse_windows_event(line: str) -> NormalizedEvent | None:
    event = parse_json_event(line)
    if event is None or event.source != "windows":
        return None
    return event


def parse_line(line: str) -> NormalizedEvent | None:
    line = line.strip()
    if not line:
        return None

    for parser in (parse_json_event, parse_windows_event, parse_linux_auth, parse_web_log):
        event = parser(line)
        if event is not None:
            return event

    return None


def is_encoded_powershell(message: str) -> bool:
    return bool(_POWERSHELL_RE.search(message))
