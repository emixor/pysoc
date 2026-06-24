"""Generate synthetic sample logs for the legacy PySOC API."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="data/sample_logs", help="Output directory")
    args = parser.parse_args()

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    (outdir / "windows.jsonl").write_text(
        "\n".join([
            json.dumps({"timestamp":"2026-06-24T01:00:00Z","event_type":"login_success","source":"windows","host":"workstation-01","user":"alice","ip":"198.51.100.10","message":"Interactive logon success."}),
            json.dumps({"timestamp":"2026-06-24T01:01:00Z","event_type":"process_creation","source":"windows","host":"workstation-01","user":"alice","ip":"198.51.100.10","message":"powershell.exe -EncodedCommand SQBFAFgA"}),
        ]) + "\n",
        encoding="utf-8",
    )
    (outdir / "linux_auth.log").write_text(
        "Jun 24 01:00:03 host1 sshd[123]: Failed password for invalid user root from 203.0.113.10 port 22 ssh2\n"
        "Jun 24 01:01:03 host1 sshd[123]: Failed password for invalid user root from 203.0.113.10 port 22 ssh2\n",
        encoding="utf-8",
    )
    (outdir / "web_access.log").write_text(
        '203.0.113.10 - - [24/Jun/2026:01:02:03 +0000] "GET /?q=../../etc/passwd HTTP/1.1" 200 123\n',
        encoding="utf-8",
    )

    manifest = {
        "files": ["windows.jsonl", "linux_auth.log", "web_access.log"],
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "note": "Synthetic sample telemetry for local testing.",
    }
    (outdir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
