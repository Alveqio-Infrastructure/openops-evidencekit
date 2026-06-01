from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


def append_report_history(
    existing: dict[str, Any] | None,
    report: dict[str, Any],
    *,
    source: str = "",
    note: str = "",
) -> dict[str, Any]:
    entries = list(existing.get("entries", [])) if isinstance(existing, dict) else []
    entries.append(_history_entry(report, source=source, note=note))
    return _history_document(entries)


def render_history_markdown(history: dict[str, Any]) -> str:
    summary = history.get("summary", {})
    lines = [
        "# OpenOps Readiness History",
        "",
        f"- Entries: **{escape_markdown_text(summary.get('entries_total', 0))}**",
        f"- Latest status: **{escape_markdown_text(str(summary.get('latest_status', 'unknown')).upper())}**",
        f"- Latest score: **{escape_markdown_text(summary.get('latest_score', 0))}**",
        f"- Score change: **{_signed(summary.get('score_change', 0))}**",
        f"- Failed checks change: **{_signed(summary.get('failed_delta', 0))}**",
        "",
        "| Recorded | Report | Source | Status | Score | Failed | Warnings | Note |",
        "| --- | --- | --- | --- | ---: | ---: | ---: | --- |",
    ]
    for entry in history.get("entries", []):
        lines.append(
            "| "
            f"{format_markdown_code(entry.get('recorded_at', ''))} | "
            f"{format_markdown_code(entry.get('report_generated_at', ''))} | "
            f"{escape_markdown_text(entry.get('source', '') or '-')} | "
            f"{escape_markdown_text(str(entry.get('status', '')).upper())} | "
            f"{entry.get('score', 0)} | "
            f"{entry.get('checks_failed', 0)} | "
            f"{entry.get('checks_warn', 0)} | "
            f"{escape_markdown_text(entry.get('note', '') or '-')} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def render_history_csv(history: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "recorded_at",
            "report_generated_at",
            "source",
            "status",
            "score",
            "checks_total",
            "checks_passed",
            "checks_failed",
            "checks_warn",
            "note",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for entry in history.get("entries", []):
        writer.writerow({key: entry.get(key, "") for key in writer.fieldnames})
    return output.getvalue()


def _history_document(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "entry_count": len(entries),
        },
        "summary": _history_summary(entries),
        "entries": entries,
    }


def _history_entry(report: dict[str, Any], *, source: str, note: str) -> dict[str, Any]:
    summary = report.get("summary", {})
    return {
        "recorded_at": datetime.now(UTC).isoformat(),
        "report_generated_at": str(report.get("generated_at", "")),
        "source": source,
        "note": note,
        "status": str(summary.get("status", "fail")),
        "score": _int(summary.get("score")),
        "checks_total": _int(summary.get("checks_total")),
        "checks_passed": _int(summary.get("checks_passed")),
        "checks_failed": _int(summary.get("checks_failed")),
        "checks_warn": _int(summary.get("checks_warn")),
    }


def _history_summary(entries: list[dict[str, Any]]) -> dict[str, Any]:
    latest = entries[-1]
    previous = entries[-2] if len(entries) > 1 else latest
    latest_score = _int(latest.get("score"))
    previous_score = _int(previous.get("score"))
    latest_failed = _int(latest.get("checks_failed"))
    previous_failed = _int(previous.get("checks_failed"))
    latest_warnings = _int(latest.get("checks_warn"))
    previous_warnings = _int(previous.get("checks_warn"))
    scores = [_int(entry.get("score")) for entry in entries]
    return {
        "entries_total": len(entries),
        "latest_status": str(latest.get("status", "fail")),
        "latest_score": latest_score,
        "previous_score": previous_score,
        "score_change": latest_score - previous_score,
        "best_score": max(scores),
        "worst_score": min(scores),
        "latest_failed": latest_failed,
        "latest_warnings": latest_warnings,
        "failed_delta": latest_failed - previous_failed,
        "warnings_delta": latest_warnings - previous_warnings,
    }


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _signed(value: Any) -> str:
    number = _int(value)
    if number > 0:
        return f"+{number}"
    return str(number)
