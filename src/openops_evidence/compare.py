from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


STATUS_RANK = {
    "pass": 0,
    "warn": 1,
    "fail": 2,
}


def compare_reports(base: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    base_results = _results_by_id(base)
    current_results = _results_by_id(current)
    base_ids = set(base_results)
    current_ids = set(current_results)

    added = [
        _compact_result(current_results[item_id])
        for item_id in sorted(current_ids - base_ids)
    ]
    removed = [
        _compact_result(base_results[item_id])
        for item_id in sorted(base_ids - current_ids)
    ]
    changed = []
    unchanged_count = 0

    for item_id in sorted(base_ids & current_ids):
        before = base_results[item_id]
        after = current_results[item_id]
        if _result_changed(before, after):
            changed.append(
                {
                    "id": item_id,
                    "title": str(after.get("title") or before.get("title") or item_id),
                    "before": _compact_result(before),
                    "after": _compact_result(after),
                    "change_type": _change_type(before, after),
                }
            )
        else:
            unchanged_count += 1

    regressions = [item for item in changed if item["change_type"] == "regression"]
    improvements = [item for item in changed if item["change_type"] == "improvement"]
    neutral_changes = [item for item in changed if item["change_type"] == "changed"]
    base_summary = base.get("summary", {})
    current_summary = current.get("summary", {})
    base_score = _integer_or_none(base_summary.get("score"))
    current_score = _integer_or_none(current_summary.get("score"))

    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": {
            "base_generated_at": base.get("generated_at"),
            "current_generated_at": current.get("generated_at"),
            "base_status": base_summary.get("status"),
            "current_status": current_summary.get("status"),
            "base_score": base_score,
            "current_score": current_score,
            "score_delta": (
                None
                if base_score is None or current_score is None
                else current_score - base_score
            ),
            "added_count": len(added),
            "removed_count": len(removed),
            "changed_count": len(changed),
            "regressions_count": len(regressions),
            "improvements_count": len(improvements),
            "neutral_changes_count": len(neutral_changes),
            "unchanged_count": unchanged_count,
        },
        "regressions": regressions,
        "improvements": improvements,
        "neutral_changes": neutral_changes,
        "added": added,
        "removed": removed,
    }


def render_comparison_markdown(comparison: dict[str, Any]) -> str:
    summary = comparison.get("summary", {})
    lines = [
        "# OpenOps Report Comparison",
        "",
        f"- Generated: `{comparison.get('generated_at', 'unknown')}`",
        f"- Base: `{summary.get('base_status', 'unknown')}` score `{_display(summary.get('base_score'))}`",
        f"- Current: `{summary.get('current_status', 'unknown')}` score `{_display(summary.get('current_score'))}`",
        f"- Score delta: `{_display(summary.get('score_delta'))}`",
        f"- Regressions: **{summary.get('regressions_count', 0)}**",
        f"- Improvements: **{summary.get('improvements_count', 0)}**",
        f"- Added checks: {summary.get('added_count', 0)}",
        f"- Removed checks: {summary.get('removed_count', 0)}",
        "",
    ]
    lines.extend(_change_section("Regressions", comparison.get("regressions", [])))
    lines.extend(_change_section("Improvements", comparison.get("improvements", [])))
    lines.extend(_change_section("Neutral Changes", comparison.get("neutral_changes", [])))
    lines.extend(_result_section("Added Checks", comparison.get("added", [])))
    lines.extend(_result_section("Removed Checks", comparison.get("removed", [])))
    return "\n".join(lines).rstrip() + "\n"


def _results_by_id(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    results = {}
    for item in report.get("results", []):
        if isinstance(item, dict) and item.get("id"):
            results[str(item["id"])] = item
    return results


def _result_changed(before: dict[str, Any], after: dict[str, Any]) -> bool:
    keys = ("status", "severity", "required", "expected", "observed_count", "error")
    return any(before.get(key) != after.get(key) for key in keys)


def _change_type(before: dict[str, Any], after: dict[str, Any]) -> str:
    before_rank = STATUS_RANK.get(str(before.get("status")), 1)
    after_rank = STATUS_RANK.get(str(after.get("status")), 1)
    if after_rank > before_rank:
        return "regression"
    if after_rank < before_rank:
        return "improvement"
    return "changed"


def _compact_result(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "title": item.get("title"),
        "status": item.get("status"),
        "severity": item.get("severity"),
        "required": item.get("required"),
        "observed_count": item.get("observed_count"),
        "remediation": item.get("remediation"),
    }


def _integer_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) else None


def _change_section(title: str, items: list[dict[str, Any]]) -> list[str]:
    lines = [f"## {title}", ""]
    if not items:
        lines.extend(["None.", ""])
        return lines
    for item in items:
        before = item.get("before", {})
        after = item.get("after", {})
        lines.extend(
            [
                f"### `{item.get('id')}` {item.get('title')}",
                "",
                f"- Status: `{before.get('status')}` -> `{after.get('status')}`",
                f"- Severity: `{before.get('severity')}` -> `{after.get('severity')}`",
                f"- Observed values: `{before.get('observed_count')}` -> "
                f"`{after.get('observed_count')}`",
                "- Remediation: "
                f"{after.get('remediation') or before.get('remediation') or 'No remediation text provided.'}",
                "",
            ]
        )
    return lines


def _result_section(title: str, items: list[dict[str, Any]]) -> list[str]:
    lines = [f"## {title}", ""]
    if not items:
        lines.extend(["None.", ""])
        return lines
    for item in items:
        lines.append(
            f"- `{item.get('id')}` {item.get('title')} "
            f"({item.get('status')}, {item.get('severity')})"
        )
    lines.append("")
    return lines


def _display(value: Any) -> Any:
    return "n/a" if value is None else value
