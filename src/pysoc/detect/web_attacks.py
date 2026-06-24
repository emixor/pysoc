"""
Web-attack detector (rule ``WA-001``).

Strategy
--------
Run the request URL (and ``User-Agent``) against a small curated regex set
covering OWASP Top-10 patterns observable from access logs:

* **SQL injection** — classic ``' OR '1'='1``, ``UNION SELECT``, comments,
  stacked queries.
* **Cross-site scripting (XSS)** — ``<script>``, ``onerror=``, ``javascript:``
  URIs.
* **Path traversal** — ``../`` sequences (and URL-encoded ``%2e%2e%2f``).
* **Command injection** — ``;``, ``|``, ``&&``, backticks inside parameters.
* **SSRF probes** — ``http://localhost``, ``http://169.254.169.254`` (cloud
  metadata endpoint).

Each request is matched against every pattern; one alert per request (the
alert's ``matched_patterns`` lists every signature that fired).

Severity is bumped to ``HIGH`` if **multiple** pattern families fire on the
same request — that is a strong signal of an automated scanner.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Optional

from ..models import Alert, Event, Severity
from .base import BaseDetector


# --- Pattern families -----------------------------------------------------
# Each entry: (family_name, compiled_regex, base_severity, mitre_attack_id)
# Patterns are intentionally narrow to reduce false positives in production
# web traffic. See docs/FALSE_POSITIVES.md for tuning guidance.
_PATTERNS = [
    # SQL injection
    ("sqli_union", re.compile(r"(?i)\bunion\b\s+\bselect\b"), Severity.HIGH, "T1190"),
    ("sqli_or_comment", re.compile(r"(?i)'\s*or\s*'?1'?\s*=\s*'?1"), Severity.HIGH, "T1190"),
    ("sqli_comment", re.compile(r"(?i)(--|#|/\*)"), Severity.MEDIUM, "T1190"),
    ("sqli_sleep", re.compile(r"(?i)\bsleep\s*\(\s*\d+\s*\)"), Severity.HIGH, "T1190"),
    ("sqli_select_from", re.compile(r"(?i)\bselect\b.+\bfrom\b"), Severity.MEDIUM, "T1190"),

    # XSS
    ("xss_script_tag", re.compile(r"(?i)<\s*script\b"), Severity.HIGH, "T1059.007"),
    ("xss_event_handler", re.compile(r"(?i)\bon(error|load|click|mouseover)\s*="), Severity.MEDIUM, "T1059.007"),
    ("xss_js_uri", re.compile(r"(?i)javascript:"), Severity.MEDIUM, "T1059.007"),
    ("xss_img_tag", re.compile(r"(?i)<\s*img\b[^>]*\bonerror\s*="), Severity.HIGH, "T1059.007"),

    # Path traversal
    ("path_traversal_dotdot", re.compile(r"\.\./"), Severity.HIGH, "T1083"),
    ("path_traversal_encoded", re.compile(r"(?i)%2e%2e[/\\]|%2e%2e%2f|%2e%2e%5c"), Severity.HIGH, "T1083"),
    ("path_traversal_etc_passwd", re.compile(r"(?i)/etc/passwd"), Severity.CRITICAL, "T1083"),

    # Command injection
    ("cmd_injection_pipe", re.compile(r"[?&][^=]+=.*\|\s*\w"), Severity.MEDIUM, "T1059.004"),
    ("cmd_injection_semicolon", re.compile(r"[?&][^=]+=.*;\s*\w"), Severity.MEDIUM, "T1059.004"),
    ("cmd_injection_backtick", re.compile(r"`[^`]+`"), Severity.MEDIUM, "T1059.004"),

    # SSRF probes
    ("ssrf_metadata", re.compile(r"(?i)169\.254\.169\.254"), Severity.CRITICAL, "T1190"),
    ("ssrf_localhost", re.compile(r"(?i)https?://localhost"), Severity.MEDIUM, "T1190"),

    # File inclusion
    ("rfi_remote", re.compile(r"(?i)[?&][^=]+=https?://"), Severity.HIGH, "T1190"),
]


class WebAttackDetector(BaseDetector):
    """Detect web attacks (SQLi / XSS / path traversal / SSRF / RFI)."""

    rule_id = "WA-001"
    rule_name = "Web attack patterns (OWASP Top-10)"
    default_severity = Severity.HIGH
    description = (
        "Matches request URLs against curated OWASP Top-10 patterns: SQLi, "
        "XSS, path traversal, command injection, SSRF probes, and remote "
        "file inclusion."
    )

    def analyze(self, events: Iterable[Event]) -> List[Alert]:
        alerts: List[Alert] = []
        for e in events:
            if e.event_action != "http_request":
                continue
            haystack = " ".join(filter(None, [e.http_url, e.http_user_agent]))
            if not haystack:
                continue
            hits = []
            for name, rx, sev, mitre in _PATTERNS:
                if rx.search(haystack):
                    hits.append((name, sev, mitre))
            if not hits:
                continue
            # Overall severity = the maximum sub-severity among matched
            # patterns. If multiple distinct families fire on the same
            # request, the alert severity is *at least* HIGH (scanner
            # behaviour).
            families = {h[0].split("_")[0] for h in hits}
            severity = max(h[1] for h in hits)
            if len(families) >= 2 and severity < Severity.HIGH:
                severity = Severity.HIGH
            alerts.append(Alert(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=severity,
                description=(
                    f"Web attack pattern(s) detected: {', '.join(h[0] for h in hits)}"
                ),
                timestamp=e.timestamp,
                source_events=(e.fingerprint(),),
                context={
                    "source_ip": e.source_ip,
                    "http_method": e.http_method,
                    "http_url": e.http_url,
                    "http_status_code": e.http_status_code,
                    "http_user_agent": e.http_user_agent,
                    "matched_patterns": [h[0] for h in hits],
                    "mitre_attack_ids": sorted({h[2] for h in hits}),
                    "families_matched": sorted(families),
                    "note": (
                        "If source_ip is a known scanner (e.g., security tool, "
                        "load balancer health-check), consider suppressing."
                    ),
                },
            ))
        return alerts

    @staticmethod
    def _safe_match(rx: re.Pattern, s: str) -> Optional[re.Match]:  # pragma: no cover
        """Convenience wrapper used by tests."""
        return rx.search(s)
