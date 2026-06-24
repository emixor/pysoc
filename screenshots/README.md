# Screenshots

This directory holds screenshots of the PySOC HTML dashboard for
documentation purposes (README, blog posts, etc.).

## How to regenerate

```bash
cd /path/to/pysoc
make demo
# → data/output/report.html is created

# Convert the HTML dashboard to a PNG screenshot using any headless
# browser (Chromium, Chrome, Firefox):
chromium --headless --screenshot=screenshots/dashboard.png \
         --window-size=1440,900 file://$(pwd)/data/output/report.html
```

## Expected screenshots

| File | What it shows |
|---|---|
| `dashboard.png` | Top of the HTML dashboard: KPI tiles, "alerts by rule" table, "events by source type" table. |
| `alert-cards.png` | Scroll view: individual alert cards with severity badges, descriptions, and JSON context. |
| `fp-notes.png` | Footer: false-positive handling notes. |

## Why we don't commit binaries

The `.gitignore` excludes `*.png` from this directory (only `README.md`
is tracked). Screenshots are regenerated on demand by the recipe above —
this keeps the repository small and avoids drift between the dashboard
HTML and the committed screenshots.
