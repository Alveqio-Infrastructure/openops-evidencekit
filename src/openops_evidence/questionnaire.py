from __future__ import annotations

import csv
import json
import re
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .policy import Check
from .reports import escape_markdown_text, format_markdown_code


def create_policy_questionnaire(checks: list[Check]) -> dict[str, Any]:
    questions = [_question(check) for check in checks]
    domains = {item["domain"] for item in questions}
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "source": "policy",
        },
        "summary": {
            "questions_total": len(questions),
            "domain_count": len(domains),
            "required_count": sum(1 for item in questions if item["required"]),
            "optional_count": sum(1 for item in questions if not item["required"]),
            "critical_count": sum(1 for item in questions if item["severity"] == "critical"),
            "high_count": sum(1 for item in questions if item["severity"] == "high"),
            "medium_count": sum(1 for item in questions if item["severity"] == "medium"),
            "low_count": sum(1 for item in questions if item["severity"] == "low"),
        },
        "questions": questions,
    }


def render_questionnaire_markdown(questionnaire: dict[str, Any]) -> str:
    summary = questionnaire.get("summary", {})
    lines = [
        "# OpenOps Evidence Questionnaire",
        "",
        f"- Generated: {format_markdown_code(questionnaire.get('generated_at', 'unknown'))}",
        f"- Questions: **{escape_markdown_text(summary.get('questions_total', 0))}**",
        f"- Required: **{escape_markdown_text(summary.get('required_count', 0))}**",
        f"- Optional: **{escape_markdown_text(summary.get('optional_count', 0))}**",
        "",
    ]
    by_domain: dict[str, list[dict[str, Any]]] = {}
    for item in questionnaire.get("questions", []):
        by_domain.setdefault(str(item.get("domain") or "general"), []).append(item)
    for domain, questions in sorted(by_domain.items()):
        lines.extend(
            [
                f"## {escape_markdown_text(_domain_title(domain))}",
                "",
                "| Required | Severity | Question | Evidence path |",
                "| --- | --- | --- | --- |",
            ]
        )
        for item in questions:
            lines.append(
                "| "
                f"{format_markdown_code(str(bool(item.get('required'))).lower())} | "
                f"{escape_markdown_text(item.get('severity', ''))} | "
                f"{escape_markdown_text(item.get('request', ''))} | "
                f"{format_markdown_code(item.get('path', ''))} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_questionnaire_csv(questionnaire: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "id",
            "domain",
            "title",
            "required",
            "severity",
            "path",
            "operator",
            "expected",
            "request",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for item in questionnaire.get("questions", []):
        row = {key: item.get(key) for key in writer.fieldnames}
        row["expected"] = _display_value(row["expected"])
        writer.writerow(row)
    return output.getvalue()


def _question(check: Check) -> dict[str, Any]:
    return {
        "id": check.id,
        "domain": _path_domain(check.path),
        "title": check.title,
        "required": check.required,
        "severity": check.severity,
        "path": check.path,
        "operator": check.operator,
        "expected": check.value,
        "request": _request_text(check),
    }


def _request_text(check: Check) -> str:
    path = check.path
    if check.operator == "exists":
        return f"Provide evidence that {path} is present."
    if check.operator == "within_days":
        return f"Provide a timestamp for {path} no older than {check.value} day(s)."
    if check.operator == "after_now":
        return f"Provide a future timestamp for {path}."
    if check.operator == "equals":
        return f"Provide evidence that {path} equals {_display_value(check.value)}."
    if check.operator == "one_of":
        return f"Provide evidence that {path} is one of {_display_value(check.value)}."
    if check.operator == "at_least":
        return f"Provide evidence that {path} is at least {_display_value(check.value)}."
    if check.operator == "at_most":
        return f"Provide evidence that {path} is at most {_display_value(check.value)}."
    if check.operator == "missing":
        return f"Confirm that {path} is absent."
    return f"Provide evidence for {path} using operator {check.operator}."


def _path_domain(path: str) -> str:
    parts = path.split(".")
    if len(parts) > 1 and parts[0] == "signals":
        return _clean_domain(parts[1])
    if parts:
        return _clean_domain(parts[0])
    return "general"


def _clean_domain(value: str) -> str:
    cleaned = re.split(r"[\[\]\*]", value, maxsplit=1)[0].strip().lower()
    return cleaned.replace("-", "_") or "general"


def _domain_title(domain: str) -> str:
    if domain == "tls":
        return "TLS"
    return domain.replace("_", " ").title()


def _display_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)
