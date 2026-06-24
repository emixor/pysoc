"""
Parser for Nginx access logs (combined log format).

Default Nginx ``log_format combined``::

    $remote_addr - $remote_user [$time_local] "$request"
    $status $body_bytes_sent "$http_referer" "$http_user_agent"

Example::

    203.0.113.5 - - [07/Mar/2026:14:32:01 +0000] "GET /search?q=1' OR '1'='1 HTTP/1.1"
    200 5316 "-" "Mozilla/5.0 (X11; Linux x86_64)"
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from ..models import Event
from .base import BaseParser

# Combined log format regex.
_NGINX_RE = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+'            # remote_addr
    r'-\s+'                                            # ident (always "-")
    r'(?P<user>\S+)\s+'                                # remote_user (often "-")
    r'\[(?P<ts>[^\]]+)\]\s+'                           # time_local
    r'"(?P<request>[^"]*)"\s+'                         # request line
    r'(?P<status>\d{3})\s+'                            # status
    r'(?P<bytes>\d+)\s+'                               # body_bytes_sent
    r'"(?P<referer>[^"]*)"\s+'                         # referer
    r'"(?P<ua>[^"]*)"'                                 # user_agent
)


def _parse_nginx_ts(ts: str) -> datetime:
    """Parse ``"07/Mar/2026:14:32:01 +0000"`` → UTC-aware datetime.

    Nginx timestamps include an offset; we normalise to UTC.
    """
    # Example: 07/Mar/2026:14:32:01 +0000
    # strptime %z handles "+0000"
    dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
    return dt.astimezone(timezone.utc)


class NginxParser(BaseParser):
    """Parse Nginx access-log lines into :class:`Event` objects."""

    name = "nginx"
    source_type = "nginx"

    def parse_line(self, line: str) -> Optional[Event]:
        m = _NGINX_RE.match(line)
        if not m:
            return None
        g = m.groupdict()
        ts = _parse_nginx_ts(g["ts"])
        # Split "GET /path?query HTTP/1.1" into method + url.
        # Note: the URL may itself contain spaces (real-world attackers
        # frequently submit un-encoded payloads like "1' OR '1'='1"). We
        # therefore split off the method at the front and the trailing
        # " HTTP/x.x" at the back, treating everything in between as URL.
        request = g["request"]
        method = url = None
        if request:
            # First token = HTTP method.
            sp = request.find(" ")
            if sp != -1:
                method = request[:sp]
                rest = request[sp + 1:]
                # Strip trailing protocol token, e.g. " HTTP/1.1".
                http_idx = rest.rfind(" HTTP/")
                if http_idx != -1:
                    url = rest[:http_idx]
                else:
                    url = rest
            else:
                method = request
        user = g.get("user")
        if user == "-":
            user = None
        return Event(
            timestamp=ts,
            source_type=self.source_type,
            raw={"line": line},
            user_name=user,
            source_ip=g.get("ip"),
            destination_host=None,
            event_action="http_request",
            event_outcome="success" if int(g["status"]) < 400 else "failure",
            http_method=method,
            http_url=url,
            http_status_code=int(g["status"]),
            http_user_agent=g.get("ua"),
        )
