from __future__ import annotations

import html
import re
import xml.etree.ElementTree as ET
from typing import Any


_MARKDOWN_TEXT_RE = re.compile(r"([\\`*_{}\[\]()#+\-.!|>])")


def escape_markdown_text(value: Any) -> str:
    escaped = html.escape(str(value), quote=False)
    return _MARKDOWN_TEXT_RE.sub(r"\\\1", escaped)


def format_markdown_code(value: Any) -> str:
    escaped = html.escape(str(value), quote=False)
    runs = re.findall(r"`+", escaped)
    delimiter = "`" * (max((len(run) for run in runs), default=0) + 1)
    if escaped.startswith("`") or escaped.endswith("`"):
        escaped = f" {escaped} "
    return f"{delimiter}{escaped}{delimiter}"


def render_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    lines = [
        "# OpenOps Evidence Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Score: **{escape_markdown_text(summary.get('score', 'n/a'))}**",
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
                f"### {escape_markdown_text(icon)}: {escape_markdown_text(item['title'])}",
                "",
                f"- ID: {format_markdown_code(item['id'])}",
                f"- Severity: {format_markdown_code(item['severity'])}",
                f"- Path: {format_markdown_code(item['path'])}",
                f"- Operator: {format_markdown_code(item['operator'])}",
                f"- Observed values: {format_markdown_code(item.get('observed_count', 0))}",
            ]
        )
        if item.get("remediation"):
            lines.append(f"- Remediation: {escape_markdown_text(item['remediation'])}")
        if item.get("error"):
            lines.append(f"- Error: {format_markdown_code(item['error'])}")
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
        f"| Generated | {format_markdown_code(report.get('generated_at', 'unknown'))} |",
        f"| Status | **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}** |",
        f"| Score | **{escape_markdown_text(summary.get('score', 'n/a'))}** |",
        f"| Passed | {escape_markdown_text(summary.get('checks_passed', 0))} |",
        f"| Failed | {escape_markdown_text(summary.get('checks_failed', 0))} |",
        f"| Warnings | {escape_markdown_text(summary.get('checks_warn', 0))} |",
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
        lines.append(f"- {format_markdown_code(item['id'])}: {escape_markdown_text(item['title'])}")
    lines.extend(
        [
            "",
            "## Notes",
            "",
            "This report is operational evidence, not a legal certification. Review raw evidence and redaction status before sharing outside the operating team.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_junit(report: dict[str, Any]) -> str:
    results = [item for item in report.get("results", []) if isinstance(item, dict)]
    failures = [item for item in results if item.get("status") == "fail"]
    warnings = [item for item in results if item.get("status") == "warn"]
    summary = report.get("summary", {})
    testsuite = ET.Element(
        "testsuite",
        {
            "name": "openops-evidence",
            "tests": str(len(results)),
            "failures": str(len(failures)),
            "errors": "0",
            "skipped": str(len(warnings)),
            "timestamp": str(report.get("generated_at", "")),
        },
    )
    properties = ET.SubElement(testsuite, "properties")
    for key in ("status", "score", "checks_passed", "checks_failed", "checks_warn"):
        ET.SubElement(
            properties,
            "property",
            {"name": str(key), "value": str(summary.get(key, ""))},
        )
    for item in results:
        testcase = ET.SubElement(
            testsuite,
            "testcase",
            {
                "classname": "openops.evidence",
                "name": str(item.get("id", "unknown")),
                "time": "0",
            },
        )
        if item.get("status") == "fail":
            failure = ET.SubElement(
                testcase,
                "failure",
                {
                    "message": str(item.get("title") or item.get("id") or "OpenOps check failed"),
                    "type": str(item.get("severity") or "unknown"),
                },
            )
            failure.text = _junit_detail(item)
        elif item.get("status") == "warn":
            skipped = ET.SubElement(
                testcase,
                "skipped",
                {"message": str(item.get("title") or item.get("id") or "OpenOps check warning")},
            )
            skipped.text = _junit_detail(item)
    return "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" + ET.tostring(testsuite, encoding="unicode") + "\n"


def _junit_detail(item: dict[str, Any]) -> str:
    lines = [
        f"Check: {item.get('id', 'unknown')}",
        f"Title: {item.get('title', '')}",
        f"Status: {item.get('status', '')}",
        f"Severity: {item.get('severity', '')}",
        f"Required: {item.get('required', '')}",
        f"Path: {item.get('path', '')}",
        f"Operator: {item.get('operator', '')}",
        f"Observed count: {item.get('observed_count', 0)}",
    ]
    if item.get("remediation"):
        lines.append(f"Remediation: {item.get('remediation')}")
    if item.get("error"):
        lines.append(f"Error: {item.get('error')}")
    return "\n".join(lines)


def _bookstack_finding(item: dict[str, Any]) -> list[str]:
    return [
        f"### {escape_markdown_text(item['title'])}",
        "",
        f"- Status: {format_markdown_code(item['status'])}",
        f"- Severity: {format_markdown_code(item['severity'])}",
        f"- Check ID: {format_markdown_code(item['id'])}",
        f"- Evidence path: {format_markdown_code(item['path'])}",
        f"- Remediation: {escape_markdown_text(item.get('remediation') or 'No remediation text provided.')}",
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
