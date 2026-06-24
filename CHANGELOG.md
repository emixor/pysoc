# Changelog

All notable changes to PySOC are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

## [1.0.0] — 2026-03-07

Initial public release. PySOC ships with four production-grade detection
rules, five log parsers, two reporters, and 80 automated tests (65 unit +
10 integration + 5 data-generator integration).

### Added

- **Detection engine** with four rules out of the box:
  - `BF-001` Brute-force login (SSH/Windows) — sliding-window threshold.
  - `SP-001` Suspicious process execution — encoded PowerShell, mimikatz,
    procdump, certutil LOLBin, suspicious parent→child (Office→PowerShell).
  - `WA-001` Web attack patterns (OWASP Top-10) — SQLi, XSS, path
    traversal, command injection, SSRF probes, RFI.
  - `IT-001` Impossible travel — geo-velocity check, country-level.

- **Parsers** for five log formats:
  - Linux `auth.log` (SSH failed/accepted/invalid-user).
  - Nginx combined access log.
  - Apache combined access log.
  - Windows Security Event Log JSON exports (EventID 4624/4625/4688).
  - Generic JSON-lines.

- **Reporters**:
  - JSON reporter (machine-readable, schema documented inline).
  - HTML reporter (self-contained static dashboard, no external assets).

- **Synthetic data generator** (`data/generator/generate_logs.py`):
  deterministic, seed-driven; produces malicious AND benign traffic for
  all five log formats.

- **CLI** (`python -m pysoc`):
  - `run` — ingest → detect → report.
  - `generate` — produce synthetic mock logs.
  - `list-rules` — print all registered detection rules.

- **Documentation**:
  - `README.md` — polished project overview with Mermaid architecture diagram.
  - `docs/ARCHITECTURE.md` — pipeline deep-dive.
  - `docs/DETECTION_RULES.md` — per-rule reference with MITRE ATT&CK mappings.
  - `docs/FALSE_POSITIVES.md` — FP strategy and TPR priors.
  - `docs/ROADMAP.md` — what's planned, what's rejected.
  - `docs/DEVELOPMENT.md` — TDD recipe for adding new detectors.

- **Tests**: 80 tests total.
  - `tests/unit/` — 65 unit tests covering parsers, detectors, reporters,
    models, ingest.
  - `tests/integration/` — 10 end-to-end tests proving every rule fires
    against the generated mock data.
  - `tests/integration/test_data_generator.py` — 3 tests verifying the
    generator produces the expected files.

- **Engineering**:
  - `pyproject.toml` with PEP 621 metadata and pytest config.
  - `Makefile` with `install`, `test`, `demo`, `lint`, `clean` targets.
  - GitHub Actions CI workflow (`.github/workflows/ci.yml`).
  - Zero runtime dependencies (stdlib only).

### Known limitations

- Linux `auth.log` timestamps are assumed to be UTC and use the current
  year (rsyslog format has no year/TZ). Production deployments should
  replace `_CURRENT_YEAR` with the file's mtime.
- GeoIP is a synthetic first-octet → country map, not real BGP/RIR data.
  Replace `pysoc.geo.lookup_country` with MaxMind GeoLite2 for production.
- Windows EVTX files require pre-export to JSON via PowerShell
  (`Get-WinEvent | ConvertTo-Json`). Native EVTX reading is on the roadmap.
- The HTML reporter uses inline CSS — large alert feeds (>1000 alerts)
  may render slowly in some browsers.

[Unreleased]: https://github.com/example/pysoc/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/example/pysoc/releases/tag/v1.0.0
