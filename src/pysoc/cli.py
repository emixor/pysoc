"""Command-line interface for PySOC."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pysoc",
        description="PySOC — a local-first mini SOC / detection engine.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="Ingest logs, run detectors, emit reports.")
    run.add_argument("paths", nargs="+", help="Log file(s) to analyse.")
    run.add_argument("--parser", default=None,
                     help="Force a parser (linux_auth, nginx, apache, json, windows_json).")
    run.add_argument("--json-out", default=None, help="Write JSON report to this path.")
    run.add_argument("--html-out", default=None, help="Write HTML report to this path.")
    run.add_argument("--quiet", action="store_true", help="Suppress stdout summary.")

    gen = sub.add_parser("generate", help="Generate synthetic mock log data.")
    gen.add_argument("--out", default="data/raw", help="Output directory for mock logs.")
    gen.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility.")

    sub.add_parser("list-rules", help="List all detection rules.")
    return p


def _looks_like_legacy(argv: list[str]) -> bool:
    return "--input" in argv or "--output" in argv


def _cmd_run(args) -> int:
    from .pipeline import run_pipeline
    result = run_pipeline(
        args.paths,
        json_out=args.json_out,
        html_out=args.html_out,
        parser_name=args.parser,
    )
    if not args.quiet:
        s = result["summary"]
        print("PySOC run complete.")
        print(f"  Events analysed : {len(result['events'])}")
        print(f"  Alerts raised   : {s['total_alerts']}")
        for sev in ("critical", "high", "medium", "low", "info"):
            n = s["by_severity"].get(sev, 0)
            if n:
                print(f"    {sev:<10}: {n}")
        if args.json_out:
            print(f"  JSON report : {args.json_out}")
        if args.html_out:
            print(f"  HTML report : {args.html_out}")
    return 0


def _cmd_generate(args) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    import subprocess
    repo_root = Path(__file__).resolve().parents[2]
    gen_script = repo_root / "data" / "generator" / "generate_logs.py"
    if not gen_script.exists():
        print(f"ERROR: data generator not found at {gen_script}", file=sys.stderr)
        return 2
    subprocess.run(
        [sys.executable, str(gen_script), "--out", str(out), "--seed", str(args.seed)],
        check=True,
    )
    return 0


def _cmd_list_rules(args) -> int:
    from .detect import DETECTORS
    print(f"{'ID':<8} {'Name':<45} {'Severity':<10}")
    print("-" * 65)
    for rid, cls in sorted(DETECTORS.items()):
        print(f"{rid:<8} {cls.rule_name:<45} {cls.default_severity.value:<10}")
    return 0


def _cmd_legacy(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="pysoc", description="PySOC legacy compatibility mode.")
    parser.add_argument("--input", required=True, help="File or directory of logs")
    parser.add_argument("--output", required=True, help="Directory for reports")
    args = parser.parse_args(argv)

    from .ingest import ingest_logs
    from .detect import DetectionEngine
    from .report import write_html_report, write_json_report

    events = ingest_logs(args.input)
    findings = DetectionEngine().detect(events)

    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)

    json_path = write_json_report(findings, outdir / "findings.json")
    html_path = write_html_report(findings, outdir / "report.html")

    print(json.dumps({
        "events": len(events),
        "findings": len(findings),
        "json_report": str(json_path),
        "html_report": str(html_path),
    }, indent=2))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] != "run" and argv[0] != "generate" and argv[0] != "list-rules" and _looks_like_legacy(argv):
        return _cmd_legacy(argv)

    args = _build_parser().parse_args(argv)
    if args.cmd == "run":
        return _cmd_run(args)
    if args.cmd == "generate":
        return _cmd_generate(args)
    if args.cmd == "list-rules":
        return _cmd_list_rules(args)
    return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
