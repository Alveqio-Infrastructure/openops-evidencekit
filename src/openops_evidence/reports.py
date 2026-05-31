from __future__ import annotations

import html
from typing import Any


def render_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    lines = [
        "# OpenOps Evidence Report",
        "",
        f"- Generated: `{report.get('generated_at', 'unknown')}`",
        f"- Status: **{summary.get('status', 'unknown').upper()}**",
        f"- Score: **{summary.get('score', 'n/a')}**",
        f"- Checks: {summary.get('checks_passed', 0)} passed, "
        f"{summary.get('checks_failed', 0)} failed, {summary.get('checks_warn', 0)} warnings",
        "",
        "## Findings",
        "",
    ]
    for item in report.get("results", []):
        icon = {"pass": "PASS", "fail": "FAIL", "warn": "WARN"}.get(item["status"], item["status"])
        lines.extend(
            [
                f"### {icon}: {item['title']}",
                "",
                f"- ID: `{item['id']}`",
                f"- Severity: `{item['severity']}`",
                f"- Path: `{item['path']}`",
                f"- Operator: `{item['operator']}`",
                f"- Observed values: `{item.get('observed_count', 0)}`",
            ]
        )
        if item.get("remediation"):
            lines.append(f"- Remediation: {item['remediation']}")
        if item.get("error"):
            lines.append(f"- Error: `{item['error']}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_html(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    rows = []
    for item in report.get("results", []):
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['status'])}</td>"
            f"<td>{html.escape(item['severity'])}</td>"
            f"<td>{html.escape(item['id'])}</td>"
            f"<td>{html.escape(item['title'])}</td>"
            f"<td>{html.escape(item.get('remediation') or '')}</td>"
            "</tr>"
        )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>OpenOps Evidence Report</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #17202a; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #d5d8dc; padding: .5rem; text-align: left; vertical-align: top; }}
    th {{ background: #f4f6f7; }}
  </style>
</head>
<body>
  <h1>OpenOps Evidence Report</h1>
  <p>Status: <strong>{html.escape(str(summary.get("status", "unknown")).upper())}</strong></p>
  <p>Score: <strong>{html.escape(str(summary.get("score", "n/a")))}</strong></p>
  <table>
    <thead><tr><th>Status</th><th>Severity</th><th>ID</th><th>Title</th><th>Remediation</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</body>
</html>
"""
