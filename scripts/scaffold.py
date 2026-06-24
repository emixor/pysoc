#!/usr/bin/env python3
"""
Scaffolding script: recreate the PySOC directory structure with empty files.

Useful when starting a fresh repo from this template, or when teaching the
architecture to a new contributor.

Usage::

    python scripts/scaffold.py --root /tmp/new-pysoc
"""

from __future__ import annotations

import argparse
from pathlib import Path

# (path, contents) tuples. An empty string means "create an empty file".
# Files are intentionally minimal — the actual contents live in the repo.
STRUCTURE = [
    # Top-level docs
    ("README.md", "# PySOC\n\nTODO: write me.\n"),
    ("LICENSE", ""),
    ("CONTRIBUTING.md", ""),
    ("CODE_OF_CONDUCT.md", ""),
    ("SECURITY.md", ""),
    ("CHANGELOG.md", "# Changelog\n\n## [Unreleased]\n"),
    ("pyproject.toml", ""),
    ("requirements.txt", ""),
    ("requirements-dev.txt", ""),
    ("Makefile", ""),
    (".gitignore", ""),
    (".env.example", ""),

    # GitHub
    (".github/workflows/ci.yml", ""),

    # Docs
    ("docs/ARCHITECTURE.md", ""),
    ("docs/DETECTION_RULES.md", ""),
    ("docs/FALSE_POSITIVES.md", ""),
    ("docs/ROADMAP.md", ""),
    ("docs/DEVELOPMENT.md", ""),

    # Source: package root
    ("src/pysoc/__init__.py", ""),
    ("src/pysoc/__main__.py", ""),
    ("src/pysoc/cli.py", ""),
    ("src/pysoc/models.py", ""),
    ("src/pysoc/geo.py", ""),
    ("src/pysoc/ingest.py", ""),
    ("src/pysoc/pipeline.py", ""),

    # Source: parsers
    ("src/pysoc/parsers/__init__.py", ""),
    ("src/pysoc/parsers/base.py", ""),
    ("src/pysoc/parsers/linux_auth.py", ""),
    ("src/pysoc/parsers/nginx.py", ""),
    ("src/pysoc/parsers/apache.py", ""),
    ("src/pysoc/parsers/json_parser.py", ""),
    ("src/pysoc/parsers/windows_json.py", ""),

    # Source: detect
    ("src/pysoc/detect/__init__.py", ""),
    ("src/pysoc/detect/base.py", ""),
    ("src/pysoc/detect/brute_force.py", ""),
    ("src/pysoc/detect/suspicious_process.py", ""),
    ("src/pysoc/detect/web_attacks.py", ""),
    ("src/pysoc/detect/impossible_travel.py", ""),

    # Source: report
    ("src/pysoc/report/__init__.py", ""),
    ("src/pysoc/report/base.py", ""),
    ("src/pysoc/report/json_reporter.py", ""),
    ("src/pysoc/report/html_reporter.py", ""),

    # Data
    ("data/generator/__init__.py", ""),
    ("data/generator/generate_logs.py", ""),
    ("data/generator/README.md", ""),
    ("data/raw/.gitkeep", ""),
    ("data/sample/.gitkeep", ""),
    ("data/output/.gitkeep", ""),

    # Examples
    ("examples/run_pysoc.py", ""),
    ("examples/custom_rule.py", ""),

    # Screenshots
    ("screenshots/README.md", ""),

    # Scripts
    ("scripts/scaffold.py", ""),
    ("scripts/run_all.sh", ""),

    # Tests
    ("tests/__init__.py", ""),
    ("tests/conftest.py", ""),
    ("tests/fixtures/.gitkeep", ""),
    ("tests/unit/__init__.py", ""),
    ("tests/unit/test_parsers.py", ""),
    ("tests/unit/test_models.py", ""),
    ("tests/unit/test_ingest.py", ""),
    ("tests/unit/test_detect_brute_force.py", ""),
    ("tests/unit/test_detect_suspicious_process.py", ""),
    ("tests/unit/test_detect_web_attacks.py", ""),
    ("tests/unit/test_detect_impossible_travel.py", ""),
    ("tests/unit/test_report.py", ""),
    ("tests/integration/__init__.py", ""),
    ("tests/integration/test_data_generator.py", ""),
    ("tests/integration/test_end_to_end.py", ""),
]


def scaffold(root: Path) -> int:
    created = 0
    for rel_path, contents in STRUCTURE:
        path = root / rel_path
        if path.exists():
            print(f"  skip    {rel_path}  (already exists)")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        print(f"  create  {rel_path}")
        created += 1
    print(f"\nScaffolded {created} files under {root}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Scaffold a fresh PySOC directory structure.")
    p.add_argument("--root", default=".", help="Root directory to scaffold (default: cwd)")
    args = p.parse_args(argv)
    return scaffold(Path(args.root).resolve())


if __name__ == "__main__":
    raise SystemExit(main())
