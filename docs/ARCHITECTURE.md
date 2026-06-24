# Architecture

This document is a deep-dive on PySOC's pipeline design. For a higher-level
overview, see the [`README.md`](../README.md).

## Four-stage pipeline

PySOC is structured as a classic four-stage pipeline:

```
ingest → parse → detect → report
```

Each stage has a single, well-defined responsibility. Stages communicate
exclusively through the immutable `Event` and `Alert` dataclasses defined
in [`src/pysoc/models.py`](../src/pysoc/models.py).

### 1. Ingest (`src/pysoc/ingest.py`)

The ingestor is intentionally simple. Its only job is: *read a file from
disk and dispatch it to the right parser*. It does no deduplication, no
enrichment, no rate-limiting — those concerns belong to the detector or
reporter.

```python
def ingest_file(path, parser_name=None) -> Iterator[Event]:
    ...
```

Parser selection happens in this order:

1. If the caller passes `parser_name` explicitly, use that parser.
2. Otherwise, look up the file extension in
   [`EXTENSION_MAP`](../src/pysoc/parsers/__init__.py).
3. If that fails, **sniff** the first non-blank line of the file (e.g. if
   it starts with `{`, treat it as JSON; if it contains `sshd[`, treat it
   as Linux auth.log).
4. If all three fail, raise `ValueError` so the caller can decide whether
   to skip the file or abort.

**Why so simple?** Because the hard part — converting a heterogeneous log
line into a normalised `Event` — belongs to the parser, where it can be
unit-tested in isolation. Keeping ingest thin makes the system easy to
reason about.

### 2. Parse + Normalise (`src/pysoc/parsers/`)

Each parser inherits from [`BaseParser`](../src/pysoc/parsers/base.py) and
implements either:

- `parse_line(line: str) -> Optional[Event]` for line-oriented formats
  (Linux auth.log, Nginx, Apache, JSON-lines), or
- `parse_record(record: dict) -> Optional[Event]` for whole-file JSON
  formats (Windows EVTX exports).

The parser is responsible for:

1. **Extracting** fields from the raw line/record using compiled regexes
   or JSON key lookups.
2. **Normalising** the timestamp to UTC. Parsers that encounter a
   timezone-naive timestamp (e.g. Linux rsyslog, which has no year and
   no TZ) assume the current year and UTC. This is documented as a known
   limitation.
3. **Building** an immutable `Event` dataclass with the relevant fields
   populated and all other fields left at their default (`None`).

The parser is **not** responsible for:

- Deduplication — the pipeline handles that.
- Enrichment (GeoIP, threat-intel) — that happens in detectors that need it.
- Filtering — every parsed event flows through to the detectors.

### 3. Detect (`src/pysoc/detect/`)

Each detector inherits from [`BaseDetector`](../src/pysoc/detect/base.py)
and implements:

```python
def analyze(self, events: Iterable[Event]) -> List[Alert]:
    ...
```

The detector receives the **full event stream** and is free to:

- Filter by `event_action`, `source_type`, etc.
- Bucket events by any key (user, source IP, …).
- Maintain sliding-window state within the call.
- Emit zero, one, or many `Alert` objects.

Detectors MUST be **deterministic**: feeding the same event stream twice
must produce the same alerts. (This is enforced by the integration test
`test_pipeline_is_idempotent`.)

Detectors MUST be **stateless across calls** — internal state from one
`analyze()` call must not leak into the next. The pipeline creates a fresh
detector instance per run, but this rule makes the detectors safe to reuse.

The detector registry lives in
[`src/pysoc/detect/__init__.py`](../src/pysoc/detect/__init__.py). Adding
a new detector requires:

1. Implementing a `<Name>Detector(BaseDetector)` class.
2. Adding it to the `DETECTORS` dict with a stable rule ID.

That's it — the pipeline automatically picks it up via `all_detectors()`.

### 4. Report (`src/pysoc/report/`)

Reporters inherit from [`BaseReporter`](../src/pysoc/report/base.py) and
implement:

```python
def _render(self, alerts, events, summary) -> Path:
    ...
```

Two reporters ship with PySOC:

- **`JSONReporter`** — machine-readable JSON file. The schema is documented
  inline in the file. Suitable for piping into jq, feeding another SOC, or
  archiving.
- **`HTMLReporter`** — self-contained static HTML dashboard. No external
  CSS/JS, no web server required. Suitable for emailing, attaching to a
  ticket, or dropping onto any static web server.

Both reporters compute a shared `ReportSummary` containing:

- `total_alerts`, `by_severity`, `by_rule`, `by_source_type` counters.
- `true_positive_estimates` — documented priors per rule (see
  [`FALSE_POSITIVES.md`](FALSE_POSITIVES.md)).
- `false_positive_notes` — short triage hints.

## Schema design

The `Event` dataclass is a pragmatic subset of the
[Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/ecs-reference.html).
Every field is optional except `timestamp`, `source_type`, and `raw`, so
parsers for very different log formats can populate whatever subset is
meaningful.

Why a subset?

- **Cognitive load.** A 200-field schema is harder to reason about than a
  25-field schema. PySOC's detectors only need 25 fields; adding more would
  not make detection better, only noisier.
- **Backward compatibility.** Every field has a default, so adding new
  fields is non-breaking. We can grow toward fuller ECS parity over time
  (see [`ROADMAP.md`](ROADMAP.md)).
- **Immutability.** A small frozen dataclass is cheap to construct and
  hash. `Event.fingerprint()` is used by reporters for evidence linking.

## Why zero runtime dependencies?

Three reasons:

1. **Portability.** PySOC runs anywhere Python 3.10+ runs — including
   air-gapped environments where `pip install` is impossible.
2. **Auditability.** A SOC tool that pulls in 200 transitive dependencies
   is itself an attack surface. Zero dependencies means zero supply-chain
   risk.
3. **Pedagogy.** PySOC is also a teaching tool: every line of logic is
   readable without jumping into a third-party library.

The development dependencies (`pytest`, `pytest-cov`) are isolated to the
`dev` extra so they never leak into production deployments.

## Concurrency model

PySOC is currently single-threaded. The pipeline is fast enough on a single
core for typical log volumes (<100k events per run). Multi-threading would
violate the "deterministic" contract of detectors unless we carefully
synchronise internal state.

For very large inputs, the roadmap includes a streaming mode that processes
events in chunks (see [`ROADMAP.md`](ROADMAP.md)).
