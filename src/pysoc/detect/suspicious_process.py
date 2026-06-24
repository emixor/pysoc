"""
Suspicious-process detector (rule ``SP-001``).

Strategy
--------
Matches Windows Event ID 4688 (process creation) records — or any event with
``event_action == "process_create"`` — against a set of well-known
attacker tradecraft signatures:

1. **Encoded PowerShell** — ``powershell.exe -EncodedCommand <base64>`` or
   ``-e`` / ``-enc`` shortcuts. This is the single most common LOLBin
   (Living-off-the-Land-Binary) pattern observed in the wild.
2. **PowerShell download cradle** — ``IEX (New-Object Net.WebClient).DownloadString(...)``.
3. **Suspicious parent→child relationships** — e.g., ``Word.exe`` spawning
   ``cmd.exe`` or ``powershell.exe`` (a classic macro-malware pattern).
4. **Commonly-abused binaries** — ``mimikatz``, ``procdump``, ``rundll32``
   invoked with a network path.

Each pattern carries its own sub-severity; the alert's overall severity is
the max of all matched patterns.
"""

from __future__ import annotations

import base64
import re
from typing import Iterable, List, Optional

from ..models import Alert, Event, Severity
from .base import BaseDetector


# --- Compiled signatures ---------------------------------------------------
# Each tuple is (pattern_name, compiled_regex, sub_severity, mitre_attack_id).
# MITRE ATT&CK IDs are included so the report can show technique mapping.
_RE_ENCODED_POWERSHELL = re.compile(
    r"powershell(?:\.exe)?\s+(?:.*?\s+)?-(?:e|enc|encodedcommand)\s+([A-Za-z0-9+/=]+)",
    re.IGNORECASE,
)
_RE_PS_DOWNLOAD_CRADLE = re.compile(
    r"(?i)\b(IEX|Invoke-Expression)\s*\(?\s*(?:New-Object|New\s+Object).+?DownloadString",
    re.IGNORECASE,
)
_RE_MIMIKATZ = re.compile(r"(?i)\bmimikatz(?:\.exe)?\b")
_RE_PROCDUMP = re.compile(r"(?i)\bprocdump(?:\.exe)?\b")
_RE_RUNDLL_NET = re.compile(r"(?i)\brundll32(?:\.exe)?\s+\S*://\S+")
_RE_CERTUTIL = re.compile(r"(?i)\bcertutil(?:\.exe)?\s+(?:.*?\s+)?(-urlcache|-decode|-encode)")

# Suspicious parent→child pairs. Stored as (parent_lower, child_lower).
_SUSPICIOUS_PARENT_CHILD = {
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    ("acrord32.exe", "powershell.exe"),
}


class SuspiciousProcessDetector(BaseDetector):
    """Detect suspicious process-execution patterns."""

    rule_id = "SP-001"
    rule_name = "Suspicious process execution"
    default_severity = Severity.HIGH
    description = (
        "Detects encoded PowerShell, download cradles, mimikatz, procdump, "
        "suspicious parent-child process relationships, and other LOLBin "
        "tradecraft."
    )

    def analyze(self, events: Iterable[Event]) -> List[Alert]:
        alerts: List[Alert] = []
        for e in events:
            if e.event_action != "process_create":
                continue
            cmd = e.process_command_line or ""
            hits = self._match(e, cmd)
            if hits:
                # Overall severity = the highest sub-severity among the
                # matched patterns (CRITICAL > HIGH > MEDIUM > LOW > INFO).
                top_sev = max(h[1] for h in hits)
                alerts.append(Alert(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=top_sev,
                    description=(
                        f"Suspicious process execution detected: "
                        f"{', '.join(h[0] for h in hits)}"
                    ),
                    timestamp=e.timestamp,
                    source_events=(e.fingerprint(),),
                    context={
                        "user": e.user_name,
                        "process_name": e.process_name,
                        "process_parent_name": e.process_parent_name,
                        "command_line": cmd,
                        "matched_patterns": [h[0] for h in hits],
                        "mitre_attack_ids": sorted({h[2] for h in hits if h[2]}),
                        "decoded_payload": self._maybe_decode_ps(cmd),
                    },
                ))
        return alerts

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    @staticmethod
    def _match(e: Event, cmd: str):
        """Return a list of (pattern_name, severity, mitre_id) tuples."""
        hits = []
        if _RE_ENCODED_POWERSHELL.search(cmd):
            hits.append(("encoded_powershell", Severity.HIGH, "T1059.001"))
        if _RE_PS_DOWNLOAD_CRADLE.search(cmd):
            hits.append(("powershell_download_cradle", Severity.HIGH, "T1059.001"))
        if _RE_MIMIKATZ.search(cmd):
            hits.append(("mimikatz", Severity.CRITICAL, "T1003.002"))
        if _RE_PROCDUMP.search(cmd):
            hits.append(("procdump", Severity.HIGH, "T1003.001"))
        if _RE_RUNDLL_NET.search(cmd):
            hits.append(("rundll32_network", Severity.HIGH, "T1218.011"))
        if _RE_CERTUTIL.search(cmd):
            hits.append(("certutil_loldb", Severity.MEDIUM, "T1218"))
        # Suspicious parent/child pair. Compare on basename (e.g.
        # "C:\\Program Files\\...\\WINWORD.EXE" → "winword.exe") so we are
        # robust to install-location differences.
        def _basename(p: str) -> str:
            if not p:
                return ""
            # Strip trailing slash/backslash, then take the last path segment.
            for sep in ("\\", "/"):
                if sep in p:
                    p = p.rsplit(sep, 1)[-1]
            return p.lower()

        parent = _basename(e.process_parent_name or "")
        child = _basename(e.process_name or "")
        if (parent, child) in _SUSPICIOUS_PARENT_CHILD:
            hits.append((f"suspicious_parent_child:{parent}->{child}", Severity.HIGH, "T1204.002"))
        return hits

    @staticmethod
    def _maybe_decode_ps(cmd: str) -> Optional[str]:
        """If the command line contains an ``-EncodedCommand`` payload, decode
        the base64 (UTF-16LE) and return the first 200 chars."""
        m = _RE_ENCODED_POWERSHELL.search(cmd)
        if not m:
            return None
        b64 = m.group(1)
        try:
            decoded = base64.b64decode(b64).decode("utf-16-le", errors="replace")
            return decoded[:200]
        except Exception:  # noqa: BLE001
            return None
