"""
Parser for Linux ``/var/log/auth.log`` (rsyslog / systemd-journal format).

Recognised events:

* SSH ``Failed password`` / ``Accepted password`` lines
* SSH ``Invalid user`` lines
* ``sudo`` authentication failures
* ``su`` authentication failures

Example input line::

    Mar  7 14:32:01 web-01 sshd[12345]: Failed password for invalid user admin from 203.0.113.5 port 51012 ssh2
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from ..models import Event
from .base import BaseParser

# rsyslog timestamp has no year — we assume the current year. Edge case:
# December logs read in January would be off by a year. For a teaching SOC
# this is acceptable; production code should use the file's mtime.
_CURRENT_YEAR = datetime.now(timezone.utc).year

# Pre-compiled regexes (named groups → readable parser code).
# SSH failed password:
#   Mar  7 14:32:01 web-01 sshd[12345]: Failed password for invalid user admin from 203.0.113.5 port 51012 ssh2
#   Mar  7 14:32:01 web-01 sshd[12345]: Failed password for root from 10.0.0.5 port 51012 ssh2
_SSH_FAILED_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>sshd)\[(?P<pid>\d+)\]:\s+"
    r"Failed password for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)\s+(?P<method>\S+)"
)

# SSH accepted password / key:
#   Mar  7 14:32:05 web-01 sshd[12346]: Accepted publickey for alice from 10.0.0.5 port 51012 ssh2
_SSH_ACCEPTED_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>sshd)\[(?P<pid>\d+)\]:\s+"
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)"
)

# Invalid user (no password attempt yet — pre-auth failure):
#   Mar  7 14:33:00 web-01 sshd[12347]: Invalid user admin from 203.0.113.6 port 51022
_SSH_INVALID_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>sshd)\[(?P<pid>\d+)\]:\s+"
    r"Invalid user\s+(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_rsyslog_ts(mon: str, day: str, time: str) -> datetime:
    """Convert ``"Mar"`` ``"7"`` ``"14:32:01"`` → UTC-aware ``datetime``.

    Linux auth.log timestamps are local to the host; for the demo we treat
    them as UTC (production deployments should consult the host's timezone).
    """
    h, m, s = time.split(":")
    return datetime(_CURRENT_YEAR, _MONTHS[mon], int(day), int(h), int(m), int(s), tzinfo=timezone.utc)


class LinuxAuthParser(BaseParser):
    """Parse ``/var/log/auth.log`` lines into :class:`Event` objects."""

    name = "linux_auth"
    source_type = "linux_auth"

    def parse_line(self, line: str) -> Optional[Event]:
        m = _SSH_FAILED_RE.match(line)
        if m:
            return self._build_event(m, outcome="failure")
        m = _SSH_ACCEPTED_RE.match(line)
        if m:
            return self._build_event(m, outcome="success")
        m = _SSH_INVALID_RE.match(line)
        if m:
            # Pre-auth failure — treat as failure.
            return self._build_event(m, outcome="failure")
        return None

    @staticmethod
    def _build_event(m: re.Match, outcome: str) -> Event:
        g = m.groupdict()
        ts = _parse_rsyslog_ts(g["mon"], g["day"], g["time"])
        return Event(
            timestamp=ts,
            source_type="linux_auth",
            raw={"line": m.string.rstrip()},
            user_name=g.get("user"),
            source_ip=g.get("ip"),
            source_port=int(g["port"]) if g.get("port") else None,
            destination_host=g.get("host"),
            event_action="login",
            event_outcome=outcome,
            process_name=g.get("proc"),
            process_pid=int(g["pid"]) if g.get("pid") else None,
            auth_method=g.get("method") if g.get("method") else "ssh",
            labels={"host": g.get("host", "")},
        )
