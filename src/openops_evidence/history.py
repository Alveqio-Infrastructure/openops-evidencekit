from __future__ import annotations

import csv
import html
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


def render_history_svg(history: dict[str, Any]) -> str:
    entries = [entry for entry in history.get("entries", []) if isinstance(entry, dict)]
    summary = history.get("summary", {})
    width = 760
    height = 320
    left = 56
    right = 28
    top = 48
    bottom = 58
    plot_width = width - left - right
    plot_height = height - top - bottom
    points = [_point(index, len(entries), entry, left, top, plot_width, plot_height) for index, entry in enumerate(entries)]
    polyline = " ".join(f"{x},{y}" for x, y, _entry in points)
    circles = "\n".join(_circle_svg(x, y, entry) for x, y, entry in points)
    labels = "\n".join(_point_label_svg(x, y, entry) for x, y, entry in points)
    latest_score = _int(summary.get("latest_score"))
    status = html.escape(str(summary.get("latest_status", "unknown")).upper())
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="OpenOps readiness history">
  <rect width="{width}" height="{height}" fill="#f8fafc"/>
  <text x="{left}" y="28" font-family="Arial, sans-serif" font-size="20" font-weight="700" fill="#17202a">OpenOps Readiness History</text>
  <text x="{width - right}" y="28" font-family="Arial, sans-serif" font-size="14" text-anchor="end" fill="#566573">Latest {latest_score} / {status}</text>
  <line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_height}" stroke="#9aa6b2" stroke-width="1"/>
  <line x1="{left}" y1="{top + plot_height}" x2="{left + plot_width}" y2="{top + plot_height}" stroke="#9aa6b2" stroke-width="1"/>
  <line x1="{left}" y1="{top}" x2="{left + plot_width}" y2="{top}" stroke="#d5dde5" stroke-width="1"/>
  <line x1="{left}" y1="{top + plot_height / 2:.1f}" x2="{left + plot_width}" y2="{top + plot_height / 2:.1f}" stroke="#d5dde5" stroke-width="1"/>
  <text x="{left - 10}" y="{top + 4}" font-family="Arial, sans-serif" font-size="11" text-anchor="end" fill="#566573">100</text>
  <text x="{left - 10}" y="{top + plot_height / 2 + 4:.1f}" font-family="Arial, sans-serif" font-size="11" text-anchor="end" fill="#566573">50</text>
  <text x="{left - 10}" y="{top + plot_height + 4}" font-family="Arial, sans-serif" font-size="11" text-anchor="end" fill="#566573">0</text>
  <polyline points="{polyline}" fill="none" stroke="#2874a6" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
{circles}
{labels}
</svg>
"""


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


def _point(
    index: int,
    count: int,
    entry: dict[str, Any],
    left: int,
    top: int,
    plot_width: int,
    plot_height: int,
) -> tuple[float, float, dict[str, Any]]:
    if count <= 1:
        x = left + plot_width / 2
    else:
        x = left + (plot_width * index / (count - 1))
    score = max(0, min(100, _int(entry.get("score"))))
    y = top + plot_height - (plot_height * score / 100)
    return round(x, 1), round(y, 1), entry


def _circle_svg(x: float, y: float, entry: dict[str, Any]) -> str:
    status = str(entry.get("status", "fail"))
    color = "#1e8449" if status == "pass" else "#b03a2e"
    return f'  <circle cx="{x}" cy="{y}" r="5" fill="{color}" stroke="#ffffff" stroke-width="2"/>'


def _point_label_svg(x: float, y: float, entry: dict[str, Any]) -> str:
    source = html.escape(str(entry.get("source") or entry.get("report_generated_at") or "run"))
    score = _int(entry.get("score"))
    label_y = y - 12 if y > 70 else y + 22
    return (
        f'  <text x="{x}" y="{label_y:.1f}" font-family="Arial, sans-serif" '
        f'font-size="11" text-anchor="middle" fill="#17202a">{score} {source}</text>'
    )
