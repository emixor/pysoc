"""Integration test: data generator → files → parser → events."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


def test_generate_logs_creates_all_files(tmp_path: Path):
    out = tmp_path / "raw"
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parents[2] / "data" / "generator" / "generate_logs.py"),
         "--out", str(out), "--seed", "42"],
        check=True, capture_output=True, text=True,
    )
    assert (out / "auth.log").exists()
    assert (out / "nginx_access.log").exists()
    assert (out / "apache_access.log").exists()
    assert (out / "windows_events.json").exists()
    assert (out / "impossible_travel.jsonl").exists()


def test_generated_auth_log_has_brute_force_burst(tmp_path: Path):
    out = tmp_path / "raw"
    subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parents[2] / "data" / "generator" / "generate_logs.py"),
         "--out", str(out), "--seed", "42"],
        check=True,
    )
    auth = (out / "auth.log").read_text()
    # The brute-force burst is 8 failed logins for root from 203.0.113.5.
    assert auth.count("Failed password for invalid user root from 203.0.113.5") == 8


def test_generated_windows_events_contains_encoded_powershell(tmp_path: Path):
    out = tmp_path / "raw"
    subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parents[2] / "data" / "generator" / "generate_logs.py"),
         "--out", str(out), "--seed", "42"],
        check=True,
    )
    records = json.loads((out / "windows_events.json").read_text())
    cmd_lines = [
        r["Properties"][3]["Value"]
        for r in records
        if r.get("EventID") == 4688 and len(r.get("Properties", [])) >= 4
    ]
    assert any("-EncodedCommand" in c for c in cmd_lines)
    assert any("mimikatz" in c.lower() for c in cmd_lines)
