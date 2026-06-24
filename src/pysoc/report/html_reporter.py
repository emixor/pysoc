"""
HTML reporter — renders a self-contained, static HTML dashboard.

The dashboard is a single file (no external CSS / JS) so that it can be
emailed, attached to a ticket, or dropped onto any static web server.

Layout
------
1. **Header** — title, generation timestamp, total alert count.
2. **KPI tiles** — counts by severity (Critical/High/Medium/Low/Info).
3. **Summary tables** — alerts by rule, events by source type, estimated
   true-positive rate per rule.
4. **Alert feed** — every alert as a card with full context.
5. **Footer** — false-positive handling notes, links to docs.
"""

from __future__ import annotations

from datetime import datetime
from html import escape
from importlib.metadata import PackageNotFoundError, version as package_version
from pathlib import Path
from typing import List

from ..models import Alert, Event, Severity
from .base import BaseReporter, ReportSummary


def _package_version() -> str:
    try:
        return package_version("pysoc")
    except PackageNotFoundError:
        return "1.0.0"


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PySOC Report — {generated_at}</title>
  <style>
    :root {{
      --bg: #0f172a; --panel: #1e293b; --text: #e2e8f0; --muted: #94a3b8;
      --accent: #38bdf8; --critical: #ef4444; --high: #f97316;
      --medium: #eab308; --low: #22c55e; --info: #64748b;
      --border: #334155;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; padding: 2rem; background: var(--bg); color: var(--text);
           font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
    h1 {{ margin: 0 0 0.25rem 0; font-size: 1.75rem; }}
    h2 {{ margin: 2rem 0 0.75rem 0; font-size: 1.25rem; color: var(--accent);
         border-bottom: 1px solid var(--border); padding-bottom: 0.25rem; }}
    .muted {{ color: var(--muted); font-size: 0.85rem; }}
    .kpi-row {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.75rem; margin: 1rem 0 2rem 0; }}
    .kpi {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
            padding: 1rem; text-align: center; }}
    .kpi .label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }}
    .kpi .value {{ font-size: 2rem; font-weight: 700; margin-top: 0.25rem; }}
    .kpi.critical .value {{ color: var(--critical); }}
    .kpi.high .value {{ color: var(--high); }}
    .kpi.medium .value {{ color: var(--medium); }}
    .kpi.low .value {{ color: var(--low); }}
    .kpi.info .value {{ color: var(--info); }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 1.5rem;
             background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
    th, td {{ padding: 0.6rem 0.8rem; text-align: left; border-bottom: 1px solid var(--border); }}
    th {{ background: #0b1220; color: var(--muted); font-weight: 600; font-size: 0.8rem;
         text-transform: uppercase; letter-spacing: 0.05em; }}
    tr:last-child td {{ border-bottom: none; }}
    .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
             padding: 1rem 1.25rem; margin-bottom: 1rem; }}
    .card-header {{ display: flex; align-items: baseline; justify-content: space-between; gap: 1rem; }}
    .card-title {{ font-weight: 700; font-size: 1rem; margin: 0; }}
    .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
              font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }}
    .badge.critical {{ background: var(--critical); color: white; }}
    .badge.high {{ background: var(--high); color: white; }}
    .badge.medium {{ background: var(--medium); color: #1a1a1a; }}
    .badge.low {{ background: var(--low); color: #1a1a1a; }}
    .badge.info {{ background: var(--info); color: white; }}
    .card-meta {{ color: var(--muted); font-size: 0.8rem; margin: 0.5rem 0; }}
    .card-desc {{ margin: 0.5rem 0; }}
    pre {{ background: #0b1220; padding: 0.75rem; border-radius: 6px; overflow-x: auto;
           font-size: 0.8rem; color: var(--text); border: 1px solid var(--border); }}
    .footer {{ margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border);
              color: var(--muted); font-size: 0.8rem; }}
    a {{ color: var(--accent); }}
  </style>
</head>
<body>
  <h1>PySOC Detection Report</h1>
  <p class="muted">Generated {generated_at} · {total_alerts} alerts · {event_count} events analysed</p>

  <div class="kpi-row">
    <div class="kpi critical"><div class="label">Critical</div><div class="value">{critical}</div></div>
    <div class="kpi high"><div class="label">High</div><div class="value">{high}</div></div>
    <div class="kpi medium"><div class="label">Medium</div><div class="value">{medium}</div></div>
    <div class="kpi low"><div class="label">Low</div><div class="value">{low}</div></div>
    <div class="kpi info"><div class="label">Info</div><div class="value">{info}</div></div>
  </div>

  <h2>Alerts by Rule</h2>
  <table>
    <thead><tr><th>Rule ID</th><th>Rule Name</th><th>Count</th><th>Est. True-Positive Rate</th></tr></thead>
    <tbody>
{by_rule_rows}
    </tbody>
  </table>

  <h2>Events by Source Type</h2>
  <table>
    <thead><tr><th>Source Type</th><th>Event Count</th></tr></thead>
    <tbody>
{by_source_rows}
    </tbody>
  </table>

  <h2>Alert Feed</h2>
  {alert_cards}

  <div class="footer">
    <h2>False-Positive Handling Notes</h2>
    <ul>{fp_notes}</ul>
    <p>See <code>docs/FALSE_POSITIVES.md</code> for full tuning guidance.</p>
    <p>PySOC {version} — MIT License</p>
  </div>
</body>
</html>
"""


class HTMLReporter(BaseReporter):
    """Render alerts as a self-contained static HTML dashboard."""

    def _render(
        self,
        alerts: List[Alert],
        events: List[Event],
        summary: ReportSummary,
    ) -> Path:
        # KPI counts
        sev = summary.by_severity
        # By-rule rows
        rule_names = {
            "BF-001": "Brute-force login (SSH/Windows)",
            "SP-001": "Suspicious process execution",
            "WA-001": "Web attack patterns (OWASP Top-10)",
            "IT-001": "Impossible travel (anomalous geo-velocity)",
        }
        by_rule_rows = "\n".join(
            f'      <tr><td><code>{escape(rid)}</code></td><td>{escape(rule_names.get(rid, ""))}</td>'
            f'<td>{count}</td><td>{summary.true_positive_estimates.get(rid, "n/a")}</td></tr>'
            for rid, count in sorted(summary.by_rule.items())
        ) or '      <tr><td colspan="4" class="muted">No alerts.</td></tr>'

        by_source_rows = "\n".join(
            f'      <tr><td><code>{escape(st)}</code></td><td>{count}</td></tr>'
            for st, count in sorted(summary.by_source_type.items())
        ) or '      <tr><td colspan="2" class="muted">No events.</td></tr>'

        alert_cards = "\n".join(self._render_card(a) for a in alerts) or '<p class="muted">No alerts.</p>'

        fp_notes = "".join(f'<li>{escape(n)}</li>' for n in summary.false_positive_notes)

        html = _HTML_TEMPLATE.format(
            generated_at=summary.generated_at.isoformat(timespec="seconds"),
            total_alerts=summary.total_alerts,
            event_count=len(events),
            critical=sev.get("critical", 0),
            high=sev.get("high", 0),
            medium=sev.get("medium", 0),
            low=sev.get("low", 0),
            info=sev.get("info", 0),
            by_rule_rows=by_rule_rows,
            by_source_rows=by_source_rows,
            alert_cards=alert_cards,
            fp_notes=fp_notes,
            version=_package_version(),
        )

        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_text(html, encoding="utf-8")
        return self.output_path

    @staticmethod
    def _render_card(a: Alert) -> str:
        """Render one alert as a card."""
        import json
        ctx_pretty = json.dumps(a.context, indent=2, default=str)
        return f"""    <div class="card">
      <div class="card-header">
        <p class="card-title"><code>{escape(a.rule_id)}</code> {escape(a.rule_name)}</p>
        <span class="badge {a.severity.value}">{escape(a.severity.value)}</span>
      </div>
      <p class="card-meta">{escape(a.timestamp.isoformat())} · source events: {len(a.source_events)}</p>
      <p class="card-desc">{escape(a.description)}</p>
      <pre>{escape(ctx_pretty)}</pre>
    </div>"""
