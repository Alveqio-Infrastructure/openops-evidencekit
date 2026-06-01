from __future__ import annotations

import csv
import re
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


SEVERITY_WEIGHT = {"critical": 5, "high": 3, "medium": 2, "low": 1}
STATUS_RANK = {"fail": 0, "warn": 1, "pass": 2}


def create_report_scorecard(report: dict[str, Any]) -> dict[str, Any]:
    results = [item for item in report.get("results", []) if isinstance(item, dict)]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in results:
        grouped.setdefault(_domain_id(item), []).append(item)
    domains = [_domain_scorecard(domain, items) for domain, items in sorted(grouped.items())]
    failed = [item for item in domains if item["status"] == "fail"]
    warnings = [item for item in domains if item["status"] == "warn"]
    passed = [item for item in domains if item["status"] == "pass"]
    summary = report.get("summary", {})
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "source_report_generated_at": report.get("generated_at"),
            "source_status": summary.get("status"),
            "source_score": summary.get("score"),
        },
        "summary": {
            "status": "fail" if failed else ("warn" if warnings else "pass"),
            "source_score": _int(summary.get("score")),
            "domains_total": len(domains),
            "domains_passed": len(passed),
            "domains_failed": len(failed),
            "domains_warn": len(warnings),
            "checks_total": sum(item["checks_total"] for item in domains),
            "checks_passed": sum(item["checks_passed"] for item in domains),
            "checks_failed": sum(item["checks_failed"] for item in domains),
            "checks_warn": sum(item["checks_warn"] for item in domains),
        },
        "domains": domains,
    }


def render_scorecard_markdown(scorecard: dict[str, Any]) -> str:
    summary = scorecard.get("summary", {})
    metadata = scorecard.get("metadata", {})
    lines = [
        "# OpenOps Domain Scorecard",
        "",
        f"- Generated: {format_markdown_code(scorecard.get('generated_at', 'unknown'))}",
        f"- Source report: {format_markdown_code(metadata.get('source_report_generated_at', 'unknown'))}",
        f"- Source status: {format_markdown_code(metadata.get('source_status', 'unknown'))}",
        f"- Source score: **{escape_markdown_text(summary.get('source_score', 0))}**",
        f"- Domains: **{escape_markdown_text(summary.get('domains_total', 0))}**",
        "",
        "| Domain | Status | Score | Checks | Failed | Warnings | Critical | High |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for domain in scorecard.get("domains", []):
        lines.append(
            "| "
            f"{escape_markdown_text(domain.get('title', ''))} | "
            f"{escape_markdown_text(domain.get('status', ''))} | "
            f"{escape_markdown_text(domain.get('score', 0))} | "
            f"{escape_markdown_text(domain.get('checks_total', 0))} | "
            f"{escape_markdown_text(domain.get('checks_failed', 0))} | "
            f"{escape_markdown_text(domain.get('checks_warn', 0))} | "
            f"{escape_markdown_text(domain.get('critical_count', 0))} | "
            f"{escape_markdown_text(domain.get('high_count', 0))} |"
        )
    lines.extend(["", "## Checks", ""])
    for domain in scorecard.get("domains", []):
        lines.extend(
            [
                f"### {escape_markdown_text(domain.get('title', ''))}",
                "",
                "| Status | Severity | Check |",
                "| --- | --- | --- |",
            ]
        )
        for check in domain.get("checks", []):
            lines.append(
                "| "
                f"{escape_markdown_text(check.get('status', ''))} | "
                f"{escape_markdown_text(check.get('severity', ''))} | "
                f"{format_markdown_code(check.get('id', ''))} {escape_markdown_text(check.get('title', ''))} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_scorecard_csv(scorecard: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "domain",
            "title",
            "status",
            "score",
            "checks_total",
            "checks_passed",
            "checks_failed",
            "checks_warn",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for domain in scorecard.get("domains", []):
        writer.writerow({key: domain.get(key) for key in writer.fieldnames})
    return output.getvalue()


def _domain_scorecard(domain: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    checks = [_check_summary(item) for item in sorted(items, key=_check_sort_key)]
    failed = [item for item in checks if item["status"] == "fail"]
    warnings = [item for item in checks if item["status"] == "warn"]
    passed = [item for item in checks if item["status"] == "pass"]
    return {
        "domain": domain,
        "title": _domain_title(domain),
        "status": "fail" if failed else ("warn" if warnings else "pass"),
        "score": _domain_score(checks),
        "checks_total": len(checks),
        "checks_passed": len(passed),
        "checks_failed": len(failed),
        "checks_warn": len(warnings),
        "critical_count": _attention_count(checks, "critical"),
        "high_count": _attention_count(checks, "high"),
        "medium_count": _attention_count(checks, "medium"),
        "low_count": _attention_count(checks, "low"),
        "checks": checks,
    }


def _check_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(item.get("id") or ""),
        "title": str(item.get("title") or item.get("id") or ""),
        "status": str(item.get("status") or ""),
        "severity": str(item.get("severity") or "medium"),
        "required": bool(item.get("required")),
        "path": str(item.get("path") or ""),
    }


def _domain_id(item: dict[str, Any]) -> str:
    path = str(item.get("path") or "")
    if path.startswith("signals."):
        parts = path.split(".")
        if len(parts) > 1:
            return _clean_domain_token(parts[1])
    first = path.split(".", 1)[0] if path else ""
    return _clean_domain_token(first) or "general"


def _clean_domain_token(value: str) -> str:
    cleaned = re.split(r"[\[\]\*]", value, maxsplit=1)[0].strip().lower()
    return cleaned.replace("-", "_")


def _domain_title(domain: str) -> str:
    if domain == "tls":
        return "TLS"
    return domain.replace("_", " ").title()


def _domain_score(checks: list[dict[str, Any]]) -> int:
    total = sum(_severity_weight(item.get("severity")) for item in checks) or 1
    lost = sum(
        _severity_weight(item.get("severity"))
        for item in checks
        if item.get("status") == "fail" and item.get("required")
    )
    return max(0, round(100 * (1 - lost / total)))


def _attention_count(checks: list[dict[str, Any]], severity: str) -> int:
    return sum(1 for item in checks if item.get("status") != "pass" and item.get("severity") == severity)


def _check_sort_key(item: dict[str, Any]) -> tuple[int, int, str]:
    return (
        STATUS_RANK.get(str(item.get("status", "")), 9),
        SEVERITY_WEIGHT.get(str(item.get("severity", "")), 0) * -1,
        str(item.get("id", "")),
    )


def _severity_weight(value: Any) -> int:
    return SEVERITY_WEIGHT.get(str(value), 2)


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0
