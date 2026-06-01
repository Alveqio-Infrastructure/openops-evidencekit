from __future__ import annotations

from typing import Any


def create_report_badge(report: dict[str, Any], label: str = "openops") -> dict[str, Any]:
    summary = report.get("summary", {})
    status = _string_value(summary.get("status"), fallback="unknown")
    score = _int_value(summary.get("score"))
    message = f"{status} {score}" if score is not None else status
    return {
        "schemaVersion": 1,
        "label": label,
        "message": message,
        "color": _badge_color(status, score),
    }


def _badge_color(status: str, score: int | None) -> str:
    if status == "fail":
        return "red"
    if status != "pass" or score is None:
        return "lightgrey"
    if score >= 95:
        return "brightgreen"
    if score >= 85:
        return "green"
    if score >= 70:
        return "yellowgreen"
    if score >= 50:
        return "yellow"
    return "orange"


def _string_value(value: Any, *, fallback: str) -> str:
    return value if isinstance(value, str) and value else fallback


def _int_value(value: Any) -> int | None:
    return value if isinstance(value, int) else None
