"""
Example: PySOC as a library.

This script shows the most common library usage pattern:

1. Generate mock data (or substitute your own log files).
2. Run the full pipeline.
3. Iterate over alerts and print a one-line summary per alert.
4. Inspect the structured ``context`` for richer triage.

Run::

    python examples/run_pysoc.py
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    # 1. Generate mock data into a temp dir (replace with your real logs).
    data_dir = Path(tempfile.mkdtemp()) / "raw"
    repo_root = Path(__file__).resolve().parents[1]
    subprocess.run(
        [sys.executable, str(repo_root / "data" / "generator" / "generate_logs.py"),
         "--out", str(data_dir), "--seed", "42"],
        check=True,
    )

    # 2. Import PySOC and run the pipeline.
    sys.path.insert(0, str(repo_root / "src"))
    from pysoc import run_pipeline  # noqa: E402

    result = run_pipeline(
        [
            data_dir / "auth.log",
            data_dir / "nginx_access.log",
            data_dir / "apache_access.log",
            data_dir / "windows_events.json",
            data_dir / "impossible_travel.jsonl",
        ],
    )

    # 3. Print a one-line summary per alert.
    print(f"\n{'Severity':<10} {'Rule':<8} {'Description':<60}")
    print("-" * 80)
    for a in result["alerts"]:
        print(f"{a.severity.value:<10} {a.rule_id:<8} {a.description[:60]}")

    # 4. Inspect rich context for one alert of each rule.
    print(f"\nTotal alerts: {result['summary']['total_alerts']}\n")
    seen_rules = set()
    for a in result["alerts"]:
        if a.rule_id in seen_rules:
            continue
        seen_rules.add(a.rule_id)
        print(f"=== {a.rule_id} sample context ===")
        for k, v in a.context.items():
            print(f"  {k}: {v}")
        print()
        if len(seen_rules) >= 4:
            break

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
