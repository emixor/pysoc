"""Unit tests for parsers."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from pysoc.parsers import (
    ApacheParser,
    LinuxAuthParser,
    NginxParser,
    WindowsJsonParser,
    JSONLinesParser,
)


# ---------------------------------------------------------------------------
# Linux auth.log parser
# ---------------------------------------------------------------------------
class TestLinuxAuthParser:
    def setup_method(self):
        self.parser = LinuxAuthParser()

    def test_parses_failed_password(self):
        line = (
            "Mar  7 14:32:01 web-01 sshd[12345]: Failed password for invalid user admin "
            "from 203.0.113.5 port 51012 ssh2"
        )
        evt = self.parser.parse_line(line)
        assert evt is not None
        assert evt.event_action == "login"
        assert evt.event_outcome == "failure"
        assert evt.user_name == "admin"
        assert evt.source_ip == "203.0.113.5"
        assert evt.source_port == 51012
        assert evt.auth_method == "ssh2"
        assert evt.destination_host == "web-01"
        assert evt.process_name == "sshd"
        assert evt.process_pid == 12345

    def test_parses_accepted_password(self):
        line = (
            "Mar  7 14:32:05 web-01 sshd[12346]: Accepted publickey for alice "
            "from 10.0.0.5 port 51012 ssh2"
        )
        evt = self.parser.parse_line(line)
        assert evt is not None
        assert evt.event_outcome == "success"
        assert evt.user_name == "alice"
        assert evt.auth_method == "publickey"

    def test_parses_invalid_user(self):
        line = (
            "Mar  7 14:33:00 web-01 sshd[12347]: Invalid user admin "
            "from 203.0.113.6 port 51022"
        )
        evt = self.parser.parse_line(line)
        assert evt is not None
        assert evt.event_outcome == "failure"
        assert evt.user_name == "admin"
        assert evt.source_ip == "203.0.113.6"

    def test_returns_none_for_unrelated_line(self):
        line = "Mar  7 14:33:00 web-01 systemd[1]: Started Session 1 of user root."
        assert self.parser.parse_line(line) is None

    def test_parse_text_yields_events(self):
        text = (
            "Mar  7 14:32:01 web-01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\n"
            "Mar  7 14:32:05 web-01 sshd[2]: Accepted publickey for alice from 5.6.7.8 port 2 ssh2\n"
        )
        events = list(self.parser.parse_text(text))
        assert len(events) == 2
        assert events[0].event_outcome == "failure"
        assert events[1].event_outcome == "success"


# ---------------------------------------------------------------------------
# Nginx parser
# ---------------------------------------------------------------------------
class TestNginxParser:
    def setup_method(self):
        self.parser = NginxParser()

    def test_parses_combined_log_line(self):
        line = (
            '203.0.113.5 - - [07/Mar/2026:14:32:01 +0000] "GET /search?q=test HTTP/1.1" '
            '200 5316 "-" "Mozilla/5.0"'
        )
        evt = self.parser.parse_line(line)
        assert evt is not None
        assert evt.source_ip == "203.0.113.5"
        assert evt.http_method == "GET"
        assert evt.http_url == "/search?q=test"
        assert evt.http_status_code == 200
        assert evt.http_user_agent == "Mozilla/5.0"
        assert evt.event_action == "http_request"
        assert evt.event_outcome == "success"

    def test_returns_failure_outcome_for_4xx(self):
        line = (
            '203.0.113.5 - - [07/Mar/2026:14:32:01 +0000] "GET /missing HTTP/1.1" '
            '404 64 "-" "curl/8.4.0"'
        )
        evt = self.parser.parse_line(line)
        assert evt is not None
        assert evt.event_outcome == "failure"
        assert evt.http_status_code == 404

    def test_returns_none_for_malformed_line(self):
        assert self.parser.parse_line("garbage line") is None

    def test_handles_remote_user(self):
        line = (
            '10.0.0.5 - alice [07/Mar/2026:14:32:01 +0000] "GET / HTTP/1.1" '
            '200 64 "-" "Mozilla/5.0"'
        )
        evt = self.parser.parse_line(line)
        assert evt is not None
        assert evt.user_name == "alice"


# ---------------------------------------------------------------------------
# Apache parser (delegates to Nginx)
# ---------------------------------------------------------------------------
class TestApacheParser:
    def test_parses_apache_combined_format(self):
        line = (
            '203.0.113.5 - - [07/Mar/2026:14:32:01 +0000] "GET / HTTP/1.1" '
            '200 64 "-" "Apache-HttpClient/4.5"'
        )
        evt = ApacheParser().parse_line(line)
        assert evt is not None
        assert evt.source_type == "apache"
        assert evt.http_status_code == 200


# ---------------------------------------------------------------------------
# Windows JSON parser
# ---------------------------------------------------------------------------
class TestWindowsJsonParser:
    def setup_method(self):
        self.parser = WindowsJsonParser()

    def test_parses_4625_failed_logon(self):
        record = {
            "EventID": 4625,
            "TimeCreated": "2026-03-07T14:10:00+00:00",
            "Properties": [
                {"Key": "TargetUserName", "Value": "Administrator"},
                {"Key": "IpAddress", "Value": "203.0.113.5"},
                {"Key": "LogonType", "Value": 3},
            ],
        }
        evt = self.parser.parse_record(record)
        assert evt is not None
        assert evt.event_action == "login"
        assert evt.event_outcome == "failure"
        assert evt.user_name == "Administrator"
        assert evt.source_ip == "203.0.113.5"
        # auth_method is formatted as "windows_logon_type_<N>".
        assert "logon_type_3" in (evt.auth_method or "")

    def test_parses_4624_success_logon(self):
        record = {
            "EventID": 4624,
            "TimeCreated": "2026-03-07T14:00:00+00:00",
            "Properties": [
                {"Key": "TargetUserName", "Value": "alice"},
                {"Key": "IpAddress", "Value": "::1"},
                {"Key": "LogonType", "Value": 2},
            ],
        }
        evt = self.parser.parse_record(record)
        assert evt is not None
        assert evt.event_outcome == "success"
        assert evt.user_name == "alice"
        # ::1 is normalised to 127.0.0.1
        assert evt.source_ip == "127.0.0.1"

    def test_parses_4688_process_create(self):
        record = {
            "EventID": 4688,
            "TimeCreated": "2026-03-07T14:15:00+00:00",
            "Properties": [
                {"Key": "SubjectUserName", "Value": "admin"},
                {"Key": "NewProcessName", "Value": "C:\\Windows\\System32\\powershell.exe"},
                {"Key": "ParentProcessName", "Value": "C:\\Windows\\System32\\cmd.exe"},
                {"Key": "CommandLine", "Value": "powershell.exe -nop -w hidden"},
            ],
        }
        evt = self.parser.parse_record(record)
        assert evt is not None
        assert evt.event_action == "process_create"
        assert evt.user_name == "admin"
        assert evt.process_name.endswith("powershell.exe")
        assert evt.process_parent_name.endswith("cmd.exe")
        assert evt.process_command_line == "powershell.exe -nop -w hidden"

    def test_returns_none_for_irrelevant_event_id(self):
        record = {
            "EventID": 4674,
            "TimeCreated": "2026-03-07T14:00:00+00:00",
            "Properties": [],
        }
        assert self.parser.parse_record(record) is None

    def test_returns_none_for_missing_timestamp(self):
        record = {"EventID": 4624, "Properties": []}
        assert self.parser.parse_record(record) is None


# ---------------------------------------------------------------------------
# JSON-lines parser
# ---------------------------------------------------------------------------
class TestJSONLinesParser:
    def setup_method(self):
        self.parser = JSONLinesParser()

    def test_parses_flat_record(self):
        line = '{"timestamp": "2026-03-07T14:00:00Z", "user_name": "alice", "source_ip": "1.2.3.4", "event_action": "login", "event_outcome": "success", "custom_field": "hello"}'
        evt = self.parser.parse_line(line)
        assert evt is not None
        assert evt.user_name == "alice"
        assert evt.source_ip == "1.2.3.4"
        assert evt.event_action == "login"
        # Unknown fields end up in labels.
        assert evt.labels.get("custom_field") == "hello"

    def test_returns_none_for_invalid_json(self):
        assert self.parser.parse_line("{not json") is None

    def test_returns_none_for_missing_timestamp(self):
        assert self.parser.parse_line('{"user_name": "alice"}') is None


def test_returns_none_for_bad_timestamp():
    from pysoc.parser import parse_line as legacy_parse_line

    assert legacy_parse_line('{"timestamp": "not-a-timestamp", "event_type": "login"}') is None
    assert legacy_parse_line('[1, 2, 3]') is None
