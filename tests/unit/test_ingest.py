"""Unit tests for the ingestor."""
from __future__ import annotations

from pathlib import Path

import pytest

from pysoc.ingest import ingest_file, ingest_to_list, sniff_parser
from pysoc.parsers import PARSERS


def test_sniff_linux_auth(tmp_path: Path):
    p = tmp_path / "test.log"
    p.write_text("Mar  7 14:32:01 web-01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\n")
    assert sniff_parser(p) == "linux_auth"


def test_sniff_nginx(tmp_path: Path):
    p = tmp_path / "test.log"
    p.write_text('1.2.3.4 - - [07/Mar/2026:14:32:01 +0000] "GET / HTTP/1.1" 200 64 "-" "Mozilla"\n')
    # The combined heuristic should pick nginx.
    assert sniff_parser(p) == "nginx"


def test_sniff_nginx_post(tmp_path: Path):
    p = tmp_path / "test.log"
    p.write_text('1.2.3.4 - - [07/Mar/2026:14:32:01 +0000] "POST /submit HTTP/1.1" 200 64 "-" "Mozilla"\n')
    assert sniff_parser(p) == "nginx"


def test_sniff_skips_blank_leading_lines(tmp_path: Path):
    p = tmp_path / "test.log"
    p.write_text("\n\n{\"timestamp\": \"2026-03-07T14:00:00Z\", \"event_action\": \"login\"}\n")
    assert sniff_parser(p) == "json"


def test_sniff_json(tmp_path: Path):
    p = tmp_path / "test.log"
    p.write_text('{"timestamp": "2026-03-07T14:00:00Z", "event_action": "login"}\n')
    assert sniff_parser(p) == "json"


def test_sniff_returns_none_for_unknown(tmp_path: Path):
    p = tmp_path / "test.log"
    p.write_text("some random text without recognisable structure\n")
    assert sniff_parser(p) is None


def test_ingest_file_with_explicit_parser(tmp_path: Path):
    p = tmp_path / "auth.log"
    p.write_text(
        "Mar  7 14:32:01 web-01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\n"
        "Mar  7 14:32:05 web-01 sshd[2]: Accepted publickey for alice from 5.6.7.8 port 2 ssh2\n"
    )
    events = list(ingest_file(p, parser_name="linux_auth"))
    assert len(events) == 2
    assert events[0].event_outcome == "failure"
    assert events[1].event_outcome == "success"


def test_ingest_file_auto_detects_by_extension(tmp_path: Path):
    p = tmp_path / "events.jsonl"
    p.write_text('{"timestamp": "2026-03-07T14:00:00Z", "user_name": "alice", "event_action": "login", "event_outcome": "success"}\n')
    events = list(ingest_file(p))
    assert len(events) == 1
    assert events[0].user_name == "alice"


def test_ingest_file_raises_on_unknown(tmp_path: Path):
    p = tmp_path / "weird.xyz"
    p.write_text("hello\n")
    with pytest.raises(ValueError):
        list(ingest_file(p))


def test_ingest_to_list(tmp_path: Path):
    p1 = tmp_path / "auth.log"
    p1.write_text("Mar  7 14:32:01 web-01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\n")
    p2 = tmp_path / "auth2.log"
    p2.write_text("Mar  7 14:33:01 web-01 sshd[2]: Failed password for bob from 5.6.7.8 port 1 ssh2\n")
    events = ingest_to_list([p1, p2], parser_name="linux_auth")
    assert len(events) == 2
