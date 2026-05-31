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


def render_bookstack_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    failed = [item for item in report.get("results", []) if item.get("status") == "fail"]
    warnings = [item for item in report.get("results", []) if item.get("status") == "warn"]
    passed = [item for item in report.get("results", []) if item.get("status") == "pass"]
    lines = [
        "# Infrastructure Readiness Evidence",
        "",
        "## Summary",
        "",
        f"| Field | Value |",
        "| --- | --- |",
        f"| Generated | `{report.get('generated_at', 'unknown')}` |",
        f"| Status | **{str(summary.get('status', 'unknown')).upper()}** |",
        f"| Score | **{summary.get('score', 'n/a')}** |",
        f"| Passed | {summary.get('checks_passed', 0)} |",
        f"| Failed | {summary.get('checks_failed', 0)} |",
        f"| Warnings | {summary.get('checks_warn', 0)} |",
        "",
        "## Required Action",
        "",
    ]
    if not failed and not warnings:
        lines.append("No failed checks or warnings were reported.")
        lines.append("")
    else:
        for item in [*failed, *warnings]:
            lines.extend(_bookstack_finding(item))
    lines.extend(
        [
            "## Passed Checks",
            "",
        ]
    )
    for item in passed:
        lines.append(f"- `{item['id']}`: {item['title']}")
    lines.extend(
        [
            "",
            "## Notes",
            "",
            "This report is operational evidence, not a legal certification. Review raw evidence and redaction status before sharing outside the operating team.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _bookstack_finding(item: dict[str, Any]) -> list[str]:
    return [
        f"### {item['title']}",
        "",
        f"- Status: `{item['status']}`",
        f"- Severity: `{item['severity']}`",
        f"- Check ID: `{item['id']}`",
        f"- Evidence path: `{item['path']}`",
        f"- Remediation: {item.get('remediation') or 'No remediation text provided.'}",
        "",
    ]


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
