from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


SUCCESS_OUTCOMES = {"ok", "pass", "passed", "success", "successful", "verified"}
FAIL_OUTCOMES = {"fail", "failed", "error", "blocked", "unsuccessful"}


def create_restore_report(
    evidence: dict[str, Any],
    *,
    max_drill_age_days: int | None = 90,
    max_backup_age_days: int | None = 2,
    now: datetime | None = None,
) -> dict[str, Any]:
    backup = _backup_signal(evidence)
    reference_time = (
        now
        or _parse_iso_datetime(str(evidence.get("generated_at") or ""))
        or datetime.now(UTC)
    ).astimezone(UTC)
    restore_tests = _restore_tests(backup, max_drill_age_days=max_drill_age_days, now=reference_time)
    backup_success = _timestamp_evaluation(
        backup.get("last_success_at") if backup else None,
        max_age_days=max_backup_age_days,
        now=reference_time,
    )
    checks = [
        _backup_signal_check(backup),
        _backup_success_check(backup_success),
        _repository_check(backup),
        _restore_recorded_check(restore_tests),
        _restore_current_check(restore_tests),
        _restore_success_check(restore_tests),
    ]
    failed = [check for check in checks if check["status"] == "fail"]
    warnings = [check for check in checks if check["status"] == "warn"]
    passed = [check for check in checks if check["status"] == "pass"]
    latest_restore = _latest_restore_test(restore_tests)
    repository_count = _int_or_none(backup.get("repository_count") if backup else None)
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "source_generated_at": evidence.get("generated_at"),
            "source": evidence.get("metadata", {}).get("source", ""),
            "organization": evidence.get("metadata", {}).get("organization", ""),
            "environment": evidence.get("metadata", {}).get("environment", ""),
            "evaluated_at": reference_time.isoformat(),
            "max_drill_age_days": max_drill_age_days,
            "max_backup_age_days": max_backup_age_days,
        },
        "summary": {
            "status": "fail" if failed else "warn" if warnings else "pass",
            "tool": str(backup.get("tool") or "") if backup else "",
            "repository_count": repository_count,
            "last_success_at": str(backup.get("last_success_at") or "") if backup else "",
            "last_success_age_days": backup_success["age_days"],
            "restore_tests_total": len(restore_tests),
            "successful_restore_tests": len([item for item in restore_tests if item["outcome"] == "pass"]),
            "failed_restore_tests": len([item for item in restore_tests if item["status"] == "failed"]),
            "stale_restore_tests": len([item for item in restore_tests if item["status"] == "stale"]),
            "unknown_restore_tests": len([item for item in restore_tests if item["status"] == "unknown"]),
            "invalid_timestamp_count": len([item for item in restore_tests if item["status"] == "invalid"]),
            "future_restore_tests": len([item for item in restore_tests if item["status"] == "future"]),
            "latest_restore_test_at": latest_restore["tested_at"] if latest_restore else "",
            "latest_restore_test_age_days": latest_restore["age_days"] if latest_restore else None,
            "protected_hosts_count": len(_string_list(backup.get("protected_hosts") if backup else [])),
            "protected_paths_count": len(_string_list(backup.get("protected_paths") if backup else [])),
            "checks_total": len(checks),
            "checks_passed": len(passed),
            "checks_warn": len(warnings),
            "checks_failed": len(failed),
        },
        "checks": checks,
        "restore_tests": restore_tests,
    }


def render_restore_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps Restore Assurance Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Evaluated at: {format_markdown_code(metadata.get('evaluated_at', 'unknown'))}",
        f"- Max backup age days: {escape_markdown_text(metadata.get('max_backup_age_days') if metadata.get('max_backup_age_days') is not None else '-')}",
        f"- Max restore drill age days: {escape_markdown_text(metadata.get('max_drill_age_days') if metadata.get('max_drill_age_days') is not None else '-')}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Backup tool: {escape_markdown_text(summary.get('tool') or '-')}",
        f"- Last successful backup: {format_markdown_code(summary.get('last_success_at') or '-')}",
        f"- Restore tests: **{escape_markdown_text(summary.get('restore_tests_total', 0))}**",
        f"- Latest restore test: {format_markdown_code(summary.get('latest_restore_test_at') or '-')}",
        "",
        "## Checks",
        "",
        "| Check | Status | Severity | Reason | Recommended action |",
        "| --- | --- | --- | --- | --- |",
    ]
    for check in report.get("checks", []):
        lines.append(
            "| "
            f"{format_markdown_code(check.get('id', ''))} {escape_markdown_text(check.get('title') or '')} | "
            f"{escape_markdown_text(check.get('status') or '-')} | "
            f"{escape_markdown_text(check.get('severity') or '-')} | "
            f"{escape_markdown_text(check.get('reason') or '-')} | "
            f"{escape_markdown_text(check.get('recommended_action') or '-')} |"
        )
    lines.extend(["", "## Restore Tests", ""])
    restore_tests = report.get("restore_tests", [])
    if not restore_tests:
        lines.extend(["No restore drill evidence was found.", ""])
    else:
        lines.extend(
            [
                "| ID | Status | Outcome | Target | Tested at | Age days | Verifier | Reason |",
                "| --- | --- | --- | --- | --- | ---: | --- | --- |",
            ]
        )
        for item in restore_tests:
            lines.append(
                "| "
                f"{format_markdown_code(item.get('id') or '-')} | "
                f"{escape_markdown_text(item.get('status') or '-')} | "
                f"{escape_markdown_text(item.get('outcome') or '-')} | "
                f"{escape_markdown_text(item.get('target') or '-')} | "
                f"{format_markdown_code(item.get('tested_at') or '-')} | "
                f"{escape_markdown_text(item.get('age_days') if item.get('age_days') is not None else '-')} | "
                f"{escape_markdown_text(item.get('verifier') or '-')} | "
                f"{escape_markdown_text(item.get('reason') or '-')} |"
            )
        lines.append("")
    lines.extend(
        [
            "## Interpretation",
            "",
            "- `pass`: current backup and restore drill evidence is present.",
            "- `warn`: restore drill evidence exists but is stale, future-dated, unknown, or incomplete.",
            "- `fail`: backup evidence is missing, last successful backup is missing, restore proof is missing, or a restore test failed.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_restore_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "record_type",
            "id",
            "title",
            "status",
            "severity",
            "path",
            "outcome",
            "target",
            "tested_at",
            "age_days",
            "max_age_days",
            "timestamp_valid",
            "verifier",
            "reason",
            "recommended_action",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for check in report.get("checks", []):
        writer.writerow(
            {
                "record_type": "check",
                "id": check.get("id", ""),
                "title": check.get("title", ""),
                "status": check.get("status", ""),
                "severity": check.get("severity", ""),
                "path": check.get("path", ""),
                "outcome": "",
                "target": "",
                "tested_at": "",
                "age_days": "",
                "max_age_days": "",
                "timestamp_valid": "",
                "verifier": "",
                "reason": check.get("reason", ""),
                "recommended_action": check.get("recommended_action", ""),
            }
        )
    for item in report.get("restore_tests", []):
        writer.writerow(
            {
                "record_type": "restore_test",
                "id": item.get("id", ""),
                "title": "",
                "status": item.get("status", ""),
                "severity": "",
                "path": item.get("path", ""),
                "outcome": item.get("outcome", ""),
                "target": item.get("target", ""),
                "tested_at": item.get("tested_at", ""),
                "age_days": item.get("age_days") if item.get("age_days") is not None else "",
                "max_age_days": item.get("max_age_days") if item.get("max_age_days") is not None else "",
                "timestamp_valid": item.get("timestamp_valid", ""),
                "verifier": item.get("verifier", ""),
                "reason": item.get("reason", ""),
                "recommended_action": "",
            }
        )
    return output.getvalue()


def _backup_signal(evidence: dict[str, Any]) -> dict[str, Any]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return {}
    backup = signals.get("backup")
    return backup if isinstance(backup, dict) else {}


def _backup_signal_check(backup: dict[str, Any]) -> dict[str, Any]:
    present = bool(backup)
    return _check(
        "backup_signal_present",
        "Backup signal is present",
        "pass" if present else "fail",
        "critical",
        "signals.backup",
        "Backup evidence is present." if present else "signals.backup is missing or empty.",
        "Collect backup evidence from a supported collector or record reviewed backup facts.",
    )


def _backup_success_check(evaluation: dict[str, Any]) -> dict[str, Any]:
    status = evaluation["status"]
    if status == "missing":
        check_status = "fail"
        reason = "No last successful backup timestamp was recorded."
    elif status in {"invalid", "future", "stale"}:
        check_status = "warn"
        reason = evaluation["reason"]
    else:
        check_status = "pass"
        reason = "A recent successful backup timestamp is recorded."
    return _check(
        "last_successful_backup",
        "Recent successful backup is recorded",
        check_status,
        "critical",
        "signals.backup.last_success_at",
        reason,
        "Record the last successful backup timestamp and refresh stale backup evidence.",
    )


def _repository_check(backup: dict[str, Any]) -> dict[str, Any]:
    count = _int_or_none(backup.get("repository_count") if backup else None)
    snapshot_count = _int_or_none(backup.get("snapshot_count") if backup else None)
    archive_count = _int_or_none(backup.get("archive_count") if backup else None)
    if count is not None and count > 0:
        status = "pass"
        reason = f"{count} backup repository/repositories are recorded."
    elif (snapshot_count is not None and snapshot_count > 0) or (archive_count is not None and archive_count > 0):
        status = "pass"
        reason = "Backup artifacts are recorded."
    else:
        status = "warn"
        reason = "No backup repository, snapshot, or archive count was recorded."
    return _check(
        "backup_repository_recorded",
        "Backup repository or backup artifacts are recorded",
        status,
        "medium",
        "signals.backup.repository_count",
        reason,
        "Record repository_count, snapshot_count, or archive_count in backup evidence.",
    )


def _restore_recorded_check(restore_tests: list[dict[str, Any]]) -> dict[str, Any]:
    present = len(restore_tests) > 0
    return _check(
        "restore_drill_recorded",
        "Restore drill evidence is recorded",
        "pass" if present else "fail",
        "critical",
        "signals.backup.restore_test_at",
        "Restore drill evidence is present." if present else "No restore drill evidence was found.",
        "Run a restore drill and record restore_test_at or restore_tests evidence.",
    )


def _restore_current_check(restore_tests: list[dict[str, Any]]) -> dict[str, Any]:
    if not restore_tests:
        return _check(
            "restore_drill_current",
            "Restore drill evidence is current",
            "fail",
            "critical",
            "signals.backup.restore_tests",
            "No restore drill evidence was found.",
            "Run a restore drill and record the tested_at timestamp.",
        )
    current = [item for item in restore_tests if item["status"] == "current"]
    if current:
        return _check(
            "restore_drill_current",
            "Restore drill evidence is current",
            "pass",
            "critical",
            "signals.backup.restore_tests",
            "At least one current restore drill was found.",
            "Keep restore drill evidence current.",
        )
    return _check(
        "restore_drill_current",
        "Restore drill evidence is current",
        "warn",
        "critical",
        "signals.backup.restore_tests",
        "Restore drill evidence exists but no current successful drill was found.",
        "Refresh stale, invalid, future-dated, or unknown restore drill evidence.",
    )


def _restore_success_check(restore_tests: list[dict[str, Any]]) -> dict[str, Any]:
    failed = [item for item in restore_tests if item["status"] == "failed"]
    unknown = [item for item in restore_tests if item["status"] == "unknown"]
    if failed:
        return _check(
            "restore_drill_successful",
            "Restore drill outcome is successful",
            "fail",
            "critical",
            "signals.backup.restore_tests",
            f"{len(failed)} restore drill(s) failed.",
            "Treat failed restore drills as incidents until the restore path is proven.",
        )
    if unknown:
        return _check(
            "restore_drill_successful",
            "Restore drill outcome is successful",
            "warn",
            "critical",
            "signals.backup.restore_tests",
            f"{len(unknown)} restore drill(s) have unknown outcome.",
            "Record explicit pass/fail outcome for every restore drill.",
        )
    return _check(
        "restore_drill_successful",
        "Restore drill outcome is successful",
        "pass" if restore_tests else "fail",
        "critical",
        "signals.backup.restore_tests",
        "Restore drill outcomes are successful." if restore_tests else "No restore drill evidence was found.",
        "Record a successful restore drill outcome.",
    )


def _restore_tests(backup: dict[str, Any], *, max_drill_age_days: int | None, now: datetime) -> list[dict[str, Any]]:
    tests: list[dict[str, Any]] = []
    raw_tests = backup.get("restore_tests") if backup else None
    if isinstance(raw_tests, list):
        for index, item in enumerate(raw_tests):
            if isinstance(item, dict):
                tests.append(_restore_test_record(item, index=index, max_drill_age_days=max_drill_age_days, now=now))
    if backup and isinstance(backup.get("restore_test_at"), str):
        tests.append(
            _restore_test_record(
                {
                    "id": "restore_test_at",
                    "tested_at": backup.get("restore_test_at"),
                    "status": "pass",
                    "source": "signals.backup.restore_test_at",
                },
                index=len(tests),
                max_drill_age_days=max_drill_age_days,
                now=now,
            )
        )
    return sorted(tests, key=lambda item: (item.get("tested_at") or "", item.get("id") or ""), reverse=True)


def _restore_test_record(
    item: dict[str, Any],
    *,
    index: int,
    max_drill_age_days: int | None,
    now: datetime,
) -> dict[str, Any]:
    tested_at = _first_string(item, "tested_at", "restored_at", "completed_at", "restore_test_at")
    timestamp = _timestamp_evaluation(tested_at, max_age_days=max_drill_age_days, now=now)
    outcome = _outcome(item)
    if outcome == "fail":
        status = "failed"
        reason = "Restore drill outcome is failed."
    elif timestamp["status"] in {"missing", "invalid", "future", "stale"}:
        status = "invalid" if timestamp["status"] == "missing" else timestamp["status"]
        reason = timestamp["reason"]
    elif outcome == "unknown":
        status = "unknown"
        reason = "Restore drill outcome is not explicit."
    else:
        status = "current"
        reason = "Restore drill is current and successful."
    return {
        "id": str(item.get("id") or f"restore-test-{index + 1}"),
        "status": status,
        "outcome": outcome,
        "target": _first_string(item, "target", "service", "asset", "scope"),
        "tested_at": tested_at or "",
        "age_days": timestamp["age_days"],
        "max_age_days": max_drill_age_days,
        "timestamp_valid": timestamp["timestamp_valid"],
        "verifier": _first_string(item, "verifier", "reviewer", "owner"),
        "path": str(item.get("source") or "signals.backup.restore_tests"),
        "reason": reason,
    }


def _timestamp_evaluation(value: Any, *, max_age_days: int | None, now: datetime) -> dict[str, Any]:
    if not isinstance(value, str) or not value:
        return {
            "status": "missing",
            "age_days": None,
            "timestamp_valid": False,
            "reason": "Timestamp is missing.",
        }
    parsed = _parse_iso_datetime(value)
    if parsed is None:
        return {
            "status": "invalid",
            "age_days": None,
            "timestamp_valid": False,
            "reason": "Timestamp value could not be parsed as ISO 8601.",
        }
    if parsed > now:
        return {
            "status": "future",
            "age_days": None,
            "timestamp_valid": True,
            "reason": "Timestamp is in the future.",
        }
    age_days = max(0, (now - parsed).days)
    stale = max_age_days is not None and age_days > max_age_days
    return {
        "status": "stale" if stale else "current",
        "age_days": age_days,
        "timestamp_valid": True,
        "reason": f"Timestamp is older than {max_age_days} day(s)." if stale else "Timestamp is current.",
    }


def _outcome(item: dict[str, Any]) -> str:
    raw = _first_string(item, "outcome", "result", "status")
    normalized = raw.strip().lower()
    if normalized in SUCCESS_OUTCOMES:
        return "pass"
    if normalized in FAIL_OUTCOMES:
        return "fail"
    return "unknown"


def _latest_restore_test(restore_tests: list[dict[str, Any]]) -> dict[str, Any] | None:
    dated = [item for item in restore_tests if item.get("tested_at")]
    return dated[0] if dated else None


def _check(
    check_id: str,
    title: str,
    status: str,
    severity: str,
    path: str,
    reason: str,
    recommended_action: str,
) -> dict[str, Any]:
    return {
        "id": check_id,
        "title": title,
        "status": status,
        "severity": severity,
        "path": path,
        "reason": reason,
        "recommended_action": recommended_action,
    }


def _parse_iso_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _first_string(item: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = item.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item]


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and value >= 0 else None
