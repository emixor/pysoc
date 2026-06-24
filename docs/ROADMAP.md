# Roadmap

PySOC is intentionally scoped: the goal is a polished, well-tested
foundation — not feature-parity with Splunk. This document lists what's
planned, what's been considered and rejected, and how to propose new
features.

## Legend

- ✅ Shipped
- 🚧 In progress
- 📋 Planned (next 3 months)
- 🔮 Future (3–12 months)
- ❌ Considered and rejected (with rationale)

## Detection content

| Item | Status | Notes |
|---|---|---|
| BF-001 Brute-force login | ✅ | SSH + Windows. |
| SP-001 Suspicious process | ✅ | Encoded PowerShell, mimikatz, procdump, suspicious parent/child, certutil. |
| WA-001 Web attacks | ✅ | SQLi, XSS, path traversal, cmd injection, SSRF, RFI. |
| IT-001 Impossible travel | ✅ | Country-level; haversine distance. |
| 📋 Sigma-rule import | 📋 | Load detection rules from the open Sigma format (https://sigmahq.io). Big ecosystem win. |
| 📋 Living-off-the-Land library | 📋 | Expand SP-001 patterns using the LOLBAS project. |
| 📋 Credential dumping — LSASS access | 📋 | Windows 4656 / 4663 events targeting lsass.exe. |
| 📋 Pass-the-hash / Pass-the-ticket | 📋 | Windows 4624 with LogonType 3 and unusual source IP. |
| 📋 C2 beacon detection | 📋 | Periodic HTTP(S) traffic to the same destination (requires netflow). |
| 📋 DNS exfiltration | 📋 | Unusually long subdomain labels; high-entropy DNS queries. |
| 🔮 Anomaly-based detection | 🔮 | Baseline user behaviour, alert on deviations. Likely needs a stats library → may break the zero-deps rule. |
| ❌ Yara-rule scanning | ❌ | Out of scope — Yara is for file scanning, not log analysis. |

## Data sources

| Item | Status | Notes |
|---|---|---|
| Linux auth.log | ✅ | SSH / sudo / su. |
| Nginx access log | ✅ | Combined format. |
| Apache access log | ✅ | Combined format. |
| Windows EVTX (via JSON export) | ✅ | Use `Get-WinEvent | ConvertTo-Json`. |
| JSON-lines (generic) | ✅ | Any pre-normalised JSONL. |
| 📋 Native EVTX reader | 📋 | `python-evtx` integration — read `.evtx` files directly without PowerShell pre-export. Adds one runtime dep; the trade-off is worth it. |
| 📋 Syslog (RFC 5424) over UDP/TCP | 📋 | Listen on a socket, parse RFC 5424 frames. |
| 🔮 Kafka consumer | 🔮 | Consume events from a Kafka topic. |
| 🔮 AWS CloudTrail | 🔮 | Read CloudTrail log files from S3. |
| ❌ PCAP analysis | ❌ | Out of scope — full-packet analysis is a different tool category. |

## Enrichment

| Item | Status | Notes |
|---|---|---|
| Synthetic pseudo-GeoIP | ✅ | Deterministic first-octet → country map; good enough for demos. |
| 📋 MaxMind GeoLite2 | 📋 | Real GeoIP. Adds one runtime dep; lazy-loaded so the demo still works without the database. |
| 📋 Threat-intel lookups | 📋 | VirusTotal / AbuseIPDB on source IPs. Cached, rate-limited. |
| 🔮 ASN enrichment | 🔮 | Map source IPs to ASN; alert if ASN is known-bad. |
| 🔮 User-entity behaviour | 🔮 | Per-user baseline of normal source IPs / hours / user-agents. |

## Operational

| Item | Status | Notes |
|---|---|---|
| CLI (`python -m pysoc run`) | ✅ | Argparse-based. |
| JSON report | ✅ | Machine-readable. |
| HTML dashboard | ✅ | Self-contained, no external assets. |
| 📋 Webhook alerting | 📋 | POST alerts to Slack / MS Teams / Discord / custom URL. |
| 📋 Live tail mode | 📋 | `python -m pysoc tail /var/log/auth.log` — stream events as they arrive. |
| 📋 Metrics endpoint | 📋 | Prometheus `/metrics` — events/sec, alerts/sec, by-rule counters. |
| 🔮 Persistent state | 🔮 | SQLite-backed state for cross-run correlation (e.g. "this IP brute-forced yesterday too"). |
| 🔮 Web UI | 🔮 | Read-only Flask/FastAPI dashboard with alert filtering. Trade-off: brings in deps; may stay as a separate `pysoc-ui` package. |
| ❌ Agent mode | ❌ | Out of scope — agents create operational complexity that contradicts PySOC's "local-first" philosophy. |

## Schema

| Item | Status | Notes |
|---|---|---|
| ECS subset (25 fields) | ✅ | Pragmatic subset. |
| 📋 ECS parity (50+ fields) | 📋 | Expand to a fuller ECS subset for interop with Elastic / OpenSearch. |
| 📋 Custom field extensions | 📋 | Allow users to attach arbitrary `labels.*` fields without changing the dataclass. |
| 🔮 Versioned schema | 🔮 | Semver the schema so downstream consumers can detect breaking changes. |

## Engineering

| Item | Status | Notes |
|---|---|---|
| pytest unit tests | ✅ | 65 unit tests. |
| pytest integration tests | ✅ | 10 integration tests including end-to-end. |
| TDD workflow | ✅ | Tests written before implementation. |
| GitHub Actions CI | ✅ | `pytest` on push/PR. |
| 📋 Coverage gate | 📋 | Enforce ≥ 90% line coverage in CI. |
| 📋 Mutation testing | 📋 | `mutmut` or `cosmic-ray` to verify test quality. |
| 📋 Type checking | 📋 | `mypy --strict` on `src/pysoc/`. |
| 📋 Linting | 📋 | `ruff` + `black` enforced in CI. |
| 🔮 Fuzz testing | 🔮 | `hypothesis` property-based tests for parsers. |
| 🔮 Performance regression tests | 🔮 | Benchmark suite with `pytest-benchmark`. |

## How to propose a new feature

1. Open an issue with the prefix `[Proposal]`.
2. Describe the use case, the proposed API, and any new dependencies.
3. Discuss trade-offs (especially: does this break the zero-runtime-deps
   rule? Is the FP rate acceptable?).
4. If the proposal is accepted, follow the TDD recipe in
   [`DEVELOPMENT.md`](DEVELOPMENT.md).
