# Data Generator

This directory contains PySOC's synthetic mock-log generator.

## Purpose

The generator produces **deterministic, harmless** mock log files for
five log formats:

| File | Format | Records |
|---|---|---|
| `auth.log` | Linux rsyslog (`/var/log/auth.log`) | 24 lines |
| `nginx_access.log` | Nginx combined access log | 22 lines |
| `apache_access.log` | Apache combined access log | 22 lines |
| `windows_events.json` | Windows Security event log JSON export | 14 records |
| `impossible_travel.jsonl` | JSON-lines login events | 4 records |

The data simulates a mix of:

- **Benign traffic** — successful SSH logins, normal web requests, normal
  Windows process creations.
- **Malicious traffic** — SSH brute-force, Windows 4625 brute-force,
  encoded PowerShell, mimikatz, Word→PowerShell macro-malware pattern,
  SQLi/XSS/path-traversal/SSRF probes, and impossible-travel logins.

All "malicious" content is purely synthetic log text — no executable
code is ever produced, and the encoded PowerShell payload decodes to
`Write-Host 'pysoc-test: harmless encoded payload'`.

## Usage

```bash
# Generate into the default location (data/raw/)
python -m pysoc generate

# Or, with explicit output directory and seed:
python data/generator/generate_logs.py --out /tmp/pysoc-data --seed 42
```

## Determinism

The generator uses Python's `random.Random(seed)` with a default seed of
`42`. Running it twice with the same seed produces byte-identical output,
which is critical for reproducible test runs.

## Adding new mock scenarios

To add a new attack scenario:

1. Add a private `_generate_<scenario>()` function that returns a list
   of log lines (or JSON records).
2. Append its output to the appropriate file in `generate_all()`.
3. Add an assertion in
   [`tests/integration/test_data_generator.py`](../../tests/integration/test_data_generator.py)
   that verifies the new scenario is present in the generated output.
4. Add or update an integration test in
   [`tests/integration/test_end_to_end.py`](../../tests/integration/test_end_to_end.py)
   that verifies the corresponding detector fires on the new scenario.

## Threats simulated

| Threat | Where it appears | Detector that catches it |
|---|---|---|
| SSH brute-force (8 failures for `root` from `203.0.113.5`) | `auth.log` | `BF-001` |
| SSH brute-force (6 failures for `admin` from `203.0.113.6`) | `auth.log` | `BF-001` |
| Windows 4625 brute-force (7 failures for `Administrator` from `203.0.113.5`) | `windows_events.json` | `BF-001` |
| SQLi (UNION SELECT, OR comment, admin'--) | `nginx_access.log`, `apache_access.log` | `WA-001` |
| XSS (`<script>`, `<img onerror>`, `javascript:`) | `nginx_access.log`, `apache_access.log` | `WA-001` |
| Path traversal (`../`, `%2e%2e%2f`, `/etc/passwd`) | `nginx_access.log`, `apache_access.log` | `WA-001` |
| SSRF (cloud metadata endpoint) | `nginx_access.log`, `apache_access.log` | `WA-001` |
| Command injection (`;cat /etc/passwd`) | `nginx_access.log`, `apache_access.log` | `WA-001` |
| Encoded PowerShell (`-EncodedCommand`) | `windows_events.json` | `SP-001` |
| Mimikatz (`mimikatz.exe sekurlsa::logonpasswords`) | `windows_events.json` | `SP-001` |
| Word → PowerShell (macro-malware parent/child) | `windows_events.json` | `SP-001` |
| Impossible travel (US → CN in 30 min for `alice`) | `impossible_travel.jsonl` | `IT-001` |

## Benign controls

The generator also produces events that should **NOT** fire any alert,
so we can verify the detector does not have false positives on normal
traffic:

- 6 successful SSH logins from internal IPs.
- 3 isolated failed SSH logins for `bob` (below threshold).
- 10 normal HTTP GETs to `/`, `/index.html`, etc.
- 4 benign Windows 4624 successful logons from `127.0.0.1`.
- 2 successful logins for `bob` from US (same country — no impossible
  travel).
