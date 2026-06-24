# Security Policy

## Supported Versions

PySOC is currently pre-1.0. We provide security fixes for the latest
release only.

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | ✅                  |
| < 1.0   | ❌                  |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email **security@pysoc.example.org** with:

1. A description of the vulnerability.
2. Steps to reproduce (a PoC script is ideal).
3. Affected versions (usually "latest main").
4. Suggested fix, if you have one.

You will receive an acknowledgement within **48 hours**. We will work with
you to validate the issue and coordinate a disclosure timeline. We follow
responsible disclosure: we will not publish details until a fix is
available and downstream users have had time to upgrade.

## Threat Model

PySOC is a **detection tool**, not a prevention tool. It reads log files
and emits alerts. It does not:

* Block traffic.
* Modify system state.
* Make outbound network connections (except via the `--generate` CLI
  subcommand, which spawns a local Python subprocess).

### Attack surface

PySOC's attack surface is intentionally minimal:

1. **Filesystem reads.** PySOC reads files the user points it at. It does
   not follow symlinks. It does not execute file content.
2. **Regex evaluation.** Parsers and detectors compile regexes at module
   load time. User-supplied log content is matched against these regexes;
   it is never `eval`'d or `exec`'d.
3. **JSON parsing.** PySOC uses the stdlib `json` module, which is safe.
4. **HTML report generation.** The HTML reporter uses `html.escape` on
   all user-supplied content. Reports are safe to open in a browser.

### What PySOC does NOT protect against

* **Malicious log files.** A log file containing gigabytes of data could
  cause PySOC to consume excessive memory. Run PySOC on a host with
  adequate resources and consider file-size limits.
* **ReDoS.** The bundled regexes are written to be linear-time, but a
  sufficiently creative input could potentially cause quadratic behaviour.
  If you observe this, please report it as a vulnerability.
* **Resource exhaustion via the data generator.** The generator is
  deterministic given a seed; it cannot be tricked into producing
  unbounded output.

## Security Best Practices for Operators

1. **Run PySOC as a non-root user** with read-only access to the log
   files you intend to analyse.
2. **Don't run PySOC against untrusted files** — if an attacker can
   control the input file, they can at least DoS the pipeline.
3. **Treat the HTML report as semi-trusted** — it is safe to open in a
   browser (all content is HTML-escaped), but the report may contain
   attacker-controlled strings (URLs, user agents, command lines) that
   could be misleading to a human analyst.
4. **Restrict access to JSON reports** — they contain source IPs,
   usernames, and other potentially sensitive information.

## Disclosure Timeline

We aim for the following timeline after a vulnerability is reported:

| Day | Action |
|-----|--------|
| 0   | Acknowledge receipt. |
| 7   | Validate / reproduce the issue. |
| 30  | Develop and test a fix. |
| 60  | Coordinate disclosure (publish CVE, release fixed version). |
| 90  | Publish public write-up. |

These are targets, not guarantees — we will work with the reporter to
adjust the timeline as needed.
