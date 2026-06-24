#!/usr/bin/env bash
#
# End-to-end demo script: generate mock data, run the pipeline, print a
# summary, and open the HTML dashboard.
#
# Usage:
#   ./scripts/run_all.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python}"

echo "==> [1/4] Installing PySOC in editable mode..."
$PYTHON -m pip install --quiet -e ".[dev]"

echo "==> [2/4] Running tests..."
$PYTHON -m pytest -q

echo "==> [3/4] Generating mock data + running pipeline..."
$PYTHON -m pysoc generate --out data/raw --seed 42
$PYTHON -m pysoc run \
    data/raw/auth.log \
    data/raw/nginx_access.log \
    data/raw/apache_access.log \
    data/raw/windows_events.json \
    data/raw/impossible_travel.jsonl \
    --json-out data/output/report.json \
    --html-out data/output/report.html

echo "==> [4/4] Opening the HTML dashboard..."
case "$(uname -s)" in
    Darwin*) open data/output/report.html ;;
    Linux*)  xdg-open data/output/report.html || echo "Open manually: data/output/report.html" ;;
    MINGW*|MSYS*|CYGWIN*) start data/output/report.html ;;
    *) echo "Open manually: data/output/report.html" ;;
esac

echo
echo "✓ Demo complete."
echo "  JSON report: data/output/report.json"
echo "  HTML report: data/output/report.html"
