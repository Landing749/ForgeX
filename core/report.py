"""Report Engine.

Renders an InvestigationResult to HTML, Markdown, JSON, or CSV.
PDF is supported when an optional PDF backend (weasyprint) is
installed; otherwise Forgex renders HTML and tells the user how to
get PDF output, rather than failing the whole report run.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import BaseLoader, Environment, select_autoescape

if TYPE_CHECKING:
    from core.investigation import InvestigationResult

SUPPORTED_FORMATS = ("json", "markdown", "html", "csv", "pdf")

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Forgex Report - {{ result.case_id }}</title>
<style>
  body { font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif; margin: 2rem; color: #1a1a1a; background: #fafafa; }
  h1 { margin-bottom: 0.2rem; }
  .meta { color: #555; margin-bottom: 1.5rem; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 2rem; background: #fff; }
  th, td { border: 1px solid #ddd; padding: 8px 10px; text-align: left; font-size: 0.9rem; }
  th { background: #222; color: #fff; }
  tr:nth-child(even) { background: #f4f4f4; }
  .sev-critical { color: #fff; background: #7f1d1d; font-weight: bold; }
  .sev-high { color: #fff; background: #b91c1c; }
  .sev-medium { color: #7c2d12; background: #fed7aa; }
  .sev-low { color: #1e3a8a; background: #dbeafe; }
  .sev-info { color: #374151; background: #e5e7eb; }
  section { margin-bottom: 2.5rem; }
</style>
</head>
<body>
  <h1>Forgex Investigation Report</h1>
  <div class="meta">
    Case: <strong>{{ result.case_id }}</strong> &middot;
    Profile: <strong>{{ result.profile }}</strong> &middot;
    Target: <code>{{ result.target }}</code> &middot;
    Duration: {{ "%.2f"|format(result.finished_at - result.started_at) }}s
  </div>

  <section>
    <h2>Findings ({{ findings|length }})</h2>
    <table>
      <tr><th>Severity</th><th>Confidence</th><th>Title</th><th>Description</th><th>Module</th></tr>
      {% for f in findings %}
      <tr>
        <td class="sev-{{ f.severity }}">{{ f.severity|upper }}</td>
        <td>{{ f.confidence }}</td>
        <td>{{ f.title }}</td>
        <td>{{ f.description }}</td>
        <td>{{ f.module }}</td>
      </tr>
      {% endfor %}
    </table>
  </section>

  <section>
    <h2>Timeline ({{ timeline|length }} events)</h2>
    <table>
      <tr><th>Timestamp</th><th>Source</th><th>Event Type</th><th>Description</th></tr>
      {% for e in timeline[:200] %}
      <tr>
        <td>{{ e.timestamp }}</td>
        <td>{{ e.source }}</td>
        <td>{{ e.event_type }}</td>
        <td>{{ e.description }}</td>
      </tr>
      {% endfor %}
    </table>
    {% if timeline|length > 200 %}<p><em>Showing first 200 of {{ timeline|length }} events. See JSON export for full timeline.</em></p>{% endif %}
  </section>

  <section>
    <h2>Correlation Graph</h2>
    <p>{{ graph.nodes|length }} nodes, {{ graph.edges|length }} edges. See JSON export for full graph data.</p>
  </section>
</body>
</html>
"""


class ReportEngine:
    def __init__(self):
        self._env = Environment(loader=BaseLoader(), autoescape=select_autoescape(["html"]))

    def render(self, result: InvestigationResult, fmt: str) -> str | bytes:
        fmt = fmt.lower()
        if fmt == "json":
            return self._render_json(result)
        if fmt == "markdown":
            return self._render_markdown(result)
        if fmt == "html":
            return self._render_html(result)
        if fmt == "csv":
            return self._render_csv_findings(result)
        if fmt == "pdf":
            return self._render_pdf(result)
        raise ValueError(f"Unsupported report format '{fmt}'. Supported: {SUPPORTED_FORMATS}")

    def write(self, result: InvestigationResult, fmt: str, out_path: str | Path) -> Path:
        content = self.render(result, fmt)
        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        with out.open(mode, **({} if mode == "wb" else {"encoding": "utf-8"})) as fh:
            fh.write(content)
        return out

    # -- format renderers -------------------------------------------------
    def _render_json(self, result: InvestigationResult) -> str:
        payload = result.to_summary_dict()
        payload["timeline"] = [e.to_dict() for e in result.timeline.merged()]
        payload["graph"] = result.graph.to_dict()
        return json.dumps(payload, indent=2, default=str)

    def _render_markdown(self, result: InvestigationResult) -> str:
        lines = [
            "# Forgex Investigation Report",
            "",
            f"- **Case ID:** {result.case_id}",
            f"- **Profile:** {result.profile}",
            f"- **Target:** `{result.target}`",
            f"- **Duration:** {result.finished_at - result.started_at:.2f}s",
            "",
            f"## Findings ({len(result.findings)})",
            "",
            "| Severity | Confidence | Title | Description | Module |",
            "|---|---|---|---|---|",
        ]
        for f in result.findings:
            lines.append(f"| {f.severity.upper()} | {f.confidence} | {f.title} | {f.description} | {f.module} |")

        events = result.timeline.merged()
        lines += ["", f"## Timeline ({len(events)} events, showing first 100)", "",
                  "| Timestamp | Source | Type | Description |", "|---|---|---|---|"]
        for e in events[:100]:
            lines.append(f"| {e.timestamp} | {e.source} | {e.event_type} | {e.description} |")

        lines += ["", "## Correlation Graph",
                   f"{len(result.graph.nodes)} nodes, {len(result.graph.edges)} edges."]
        return "\n".join(lines) + "\n"

    def _render_html(self, result: InvestigationResult) -> str:
        template = self._env.from_string(_HTML_TEMPLATE)
        return template.render(
            result=result,
            findings=[f.to_dict() for f in result.findings],
            timeline=[e.to_dict() for e in result.timeline.merged()],
            graph=result.graph.to_dict(),
        )

    def _render_csv_findings(self, result: InvestigationResult) -> str:
        import io
        buf = io.StringIO()
        fields = ["id", "title", "severity", "confidence", "description", "module", "tags"]
        writer = csv.DictWriter(buf, fieldnames=fields)
        writer.writeheader()
        for f in result.findings:
            row = f.to_dict()
            row["tags"] = ",".join(row["tags"])
            row.pop("evidence_refs", None)
            writer.writerow({k: row.get(k, "") for k in fields})
        return buf.getvalue()

    def _render_pdf(self, result: InvestigationResult) -> bytes:
        try:
            from weasyprint import HTML
        except ImportError as exc:
            raise ImportError(
                "PDF export requires the optional 'weasyprint' package "
                "(pip install weasyprint). Falling back is intentional: "
                "use --format html for a dependency-free report."
            ) from exc
        html_str = self._render_html(result)
        return HTML(string=html_str).write_pdf()
