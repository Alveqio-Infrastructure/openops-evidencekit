from __future__ import annotations

import html
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
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


def render_sarif(report: dict[str, Any]) -> str:
    findings = [
        item
        for item in report.get("results", [])
        if isinstance(item, dict) and item.get("status") in {"fail", "warn"}
    ]
    rules = [_sarif_rule(item) for item in findings]
    results = [_sarif_result(item) for item in findings]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OpenOps EvidenceKit",
                        "informationUri": "https://github.com/Alveqio-Infrastructure/openops-evidencekit",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "source_report_generated_at": report.get("generated_at"),
                            "source_status": report.get("summary", {}).get("status"),
                            "source_score": report.get("summary", {}).get("score"),
                        },
                    }
                ],
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True) + "\n"


def render_prometheus(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    status = str(summary.get("status", "unknown"))
    lines = [
        "# HELP openops_readiness_score OpenOps readiness score from the latest report.",
        "# TYPE openops_readiness_score gauge",
        f"openops_readiness_score {_metric_number(summary.get('score'))}",
        "# HELP openops_report_status OpenOps report status, labelled by status.",
        "# TYPE openops_report_status gauge",
        f'openops_report_status{{status="pass"}} {_status_metric(status, "pass")}',
        f'openops_report_status{{status="fail"}} {_status_metric(status, "fail")}',
        "# HELP openops_checks_total OpenOps checks evaluated by result class.",
        "# TYPE openops_checks_total gauge",
        f'openops_checks_total{{result="total"}} {_metric_number(summary.get("checks_total"))}',
        f'openops_checks_total{{result="passed"}} {_metric_number(summary.get("checks_passed"))}',
        f'openops_checks_total{{result="failed"}} {_metric_number(summary.get("checks_failed"))}',
        f'openops_checks_total{{result="warnings"}} {_metric_number(summary.get("checks_warn"))}',
    ]
    generated_at_seconds = _timestamp_seconds(report.get("generated_at"))
    if generated_at_seconds is not None:
        lines.extend(
            [
                "# HELP openops_report_generated_at_seconds Unix timestamp for the source report.",
                "# TYPE openops_report_generated_at_seconds gauge",
                f"openops_report_generated_at_seconds {generated_at_seconds}",
            ]
        )
    lines.extend(
        [
            "# HELP openops_check_result OpenOps check result by check, status, severity, and required flag.",
            "# TYPE openops_check_result gauge",
        ]
    )
    for item in report.get("results", []):
        if not isinstance(item, dict):
            continue
        labels = {
            "check_id": item.get("id", "unknown"),
            "status": item.get("status", "unknown"),
            "severity": item.get("severity", "unknown"),
            "required": str(bool(item.get("required"))).lower(),
        }
        label_text = ",".join(
            f'{key}="{_prometheus_label(value)}"' for key, value in labels.items()
        )
        lines.append(f"openops_check_result{{{label_text}}} 1")
    return "\n".join(lines).rstrip() + "\n"


def _sarif_rule(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(item.get("id", "unknown")),
        "name": str(item.get("title") or item.get("id") or "OpenOps check"),
        "shortDescription": {"text": str(item.get("title") or item.get("id") or "OpenOps check")},
        "fullDescription": {"text": str(item.get("remediation") or "Review the finding and update evidence.")},
        "defaultConfiguration": {"level": _sarif_level(item)},
        "properties": {
            "severity": item.get("severity"),
            "required": item.get("required"),
            "operator": item.get("operator"),
            "path": item.get("path"),
        },
    }


def _sarif_result(item: dict[str, Any]) -> dict[str, Any]:
    message = str(item.get("title") or item.get("id") or "OpenOps finding")
    remediation = item.get("remediation")
    if remediation:
        message = f"{message}: {remediation}"
    return {
        "ruleId": str(item.get("id", "unknown")),
        "level": _sarif_level(item),
        "message": {"text": message},
        "locations": [
            {
                "logicalLocations": [
                    {
                        "name": str(item.get("path") or item.get("id") or "evidence"),
                        "fullyQualifiedName": str(item.get("path") or item.get("id") or "evidence"),
                        "kind": "object",
                    }
                ]
            }
        ],
        "properties": {
            "status": item.get("status"),
            "severity": item.get("severity"),
            "required": item.get("required"),
            "observed_count": item.get("observed_count"),
            "operator": item.get("operator"),
            "evidence_path": item.get("path"),
        },
    }


def _sarif_level(item: dict[str, Any]) -> str:
    if item.get("status") == "fail":
        return "error"
    if item.get("status") == "warn":
        return "warning"
    return "note"


def _metric_number(value: Any) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return str(value)
    return "0"


def _status_metric(actual: str, expected: str) -> str:
    return "1" if actual == expected else "0"


def _prometheus_label(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _timestamp_seconds(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return int(parsed.timestamp())


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
