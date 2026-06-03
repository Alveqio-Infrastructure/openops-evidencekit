from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


def create_monitoring_report(evidence: dict[str, Any], *, max_alert_test_age_days: int = 90) -> dict[str, Any]:
    evaluated_at = _reference_time(evidence)
    monitoring = _monitoring_signal(evidence)
    down_targets = _down_target_records(monitoring)
    checks = [
        _monitoring_signal_check(monitoring),
        _targets_present_check(monitoring),
        _targets_healthy_check(monitoring, down_targets),
        _alert_channels_check(monitoring),
        _alert_test_check(monitoring, evaluated_at=evaluated_at, max_age_days=max_alert_test_age_days),
    ]
    failed = [check for check in checks if check["status"] == "fail"]
    warnings = [check for check in checks if check["status"] == "warn"]
    passed = [check for check in checks if check["status"] == "pass"]
    targets = _int_value(monitoring.get("targets"))
    targets_total = _int_value(monitoring.get("targets_total") or monitoring.get("monitors_total"))
    targets_up = _int_value(monitoring.get("targets_up"))
    targets_down = _targets_down(monitoring, down_targets)
    alert_channels = _alert_channels(monitoring)
    last_alert_test_at, last_alert_test_age_days = _alert_test_age(
        monitoring,
        evaluated_at=evaluated_at,
    )
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "source_generated_at": evidence.get("generated_at"),
            "evaluated_at": evaluated_at.isoformat(),
            "max_alert_test_age_days": max_alert_test_age_days,
            "source": evidence.get("metadata", {}).get("source", ""),
            "organization": evidence.get("metadata", {}).get("organization", ""),
            "environment": evidence.get("metadata", {}).get("environment", ""),
        },
        "summary": {
            "status": "fail" if failed else "warn" if warnings else "pass",
            "system": str(monitoring.get("system") or ""),
            "targets": targets,
            "targets_total": targets_total,
            "targets_up": targets_up,
            "targets_down": targets_down,
            "down_targets_count": len(down_targets),
            "alert_channels_total": len(alert_channels),
            "last_alert_test_at": last_alert_test_at,
            "last_alert_test_age_days": last_alert_test_age_days,
            "checks_total": len(checks),
            "checks_passed": len(passed),
            "checks_warn": len(warnings),
            "checks_failed": len(failed),
        },
        "checks": checks,
        "down_targets": down_targets,
    }


def render_monitoring_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps Monitoring Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Evaluated at: {format_markdown_code(metadata.get('evaluated_at', 'unknown'))}",
        f"- Max alert test age: **{escape_markdown_text(metadata.get('max_alert_test_age_days', '-'))} day(s)**",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- System: **{escape_markdown_text(summary.get('system') or 'unknown')}**",
        f"- Targets: **{escape_markdown_text(_display(summary.get('targets')))}**",
        f"- Down targets: **{escape_markdown_text(summary.get('targets_down', 0))}**",
        f"- Alert channels: **{escape_markdown_text(summary.get('alert_channels_total', 0))}**",
        "",
        "## Checks",
        "",
        "| Check | Status | Severity | Reason | Recommended action |",
        "| --- | --- | --- | --- | --- |",
    ]
    for check in report.get("checks", []):
        lines.append(
            "| "
            f"{format_markdown_code(check.get('id') or '-')} {escape_markdown_text(check.get('title') or '')} | "
            f"{escape_markdown_text(check.get('status') or '-')} | "
            f"{escape_markdown_text(check.get('severity') or '-')} | "
            f"{escape_markdown_text(check.get('reason') or '-')} | "
            f"{escape_markdown_text(check.get('recommended_action') or '-')} |"
        )
    lines.extend(["", "## Down Targets", ""])
    down_targets = report.get("down_targets", [])
    if not down_targets:
        lines.extend(["No down target evidence was found.", ""])
    else:
        lines.extend(["| Target | Status | Reason |", "| --- | --- | --- |"])
        for target in down_targets:
            lines.append(
                "| "
                f"{format_markdown_code(target.get('target') or '-')} | "
                f"{escape_markdown_text(target.get('status') or '-')} | "
                f"{escape_markdown_text(target.get('reason') or '-')} |"
            )
        lines.append("")
    lines.extend(
        [
            "## Interpretation",
            "",
            "- `pass`: monitoring targets are present, no down targets are known, alert channels exist, and alert tests are current.",
            "- `warn`: alert routing or alert-test evidence is incomplete or stale.",
            "- `fail`: monitoring evidence is missing, no targets are recorded, or known down targets exist.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_monitoring_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "record_type",
            "id",
            "title",
            "target",
            "status",
            "severity",
            "path",
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
                "target": "",
                "status": check.get("status", ""),
                "severity": check.get("severity", ""),
                "path": check.get("path", ""),
                "reason": check.get("reason", ""),
                "recommended_action": check.get("recommended_action", ""),
            }
        )
    for target in report.get("down_targets", []):
        writer.writerow(
            {
                "record_type": "down_target",
                "id": "",
                "title": "",
                "target": target.get("target", ""),
                "status": target.get("status", ""),
                "severity": "high",
                "path": "signals.monitoring.down_targets",
                "reason": target.get("reason", ""),
                "recommended_action": "Restore the target or document the accepted outage.",
            }
        )
    return output.getvalue()


def _monitoring_signal(evidence: dict[str, Any]) -> dict[str, Any]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return {}
    monitoring = signals.get("monitoring")
    return monitoring if isinstance(monitoring, dict) else {}


def _monitoring_signal_check(monitoring: dict[str, Any]) -> dict[str, Any]:
    present = bool(monitoring)
    return _check(
        "monitoring_signal_present",
        "Monitoring signal is present",
        "pass" if present else "fail",
        "critical",
        "signals.monitoring",
        "Monitoring evidence is present." if present else "signals.monitoring is missing or empty.",
        "Record monitoring system, targets, alert channels, and alert test evidence.",
    )


def _targets_present_check(monitoring: dict[str, Any]) -> dict[str, Any]:
    targets = _int_value(monitoring.get("targets") or monitoring.get("targets_total") or monitoring.get("monitors_total"))
    present = targets is not None and targets > 0
    return _check(
        "monitoring_targets_present",
        "Monitoring targets are recorded",
        "pass" if present else "fail",
        "critical",
        "signals.monitoring.targets",
        f"{targets} monitoring target(s) recorded." if present else "No monitoring targets were recorded.",
        "Record at least one monitored target from Prometheus, Uptime Kuma, or another monitoring system.",
    )


def _targets_healthy_check(monitoring: dict[str, Any], down_targets: list[dict[str, str]]) -> dict[str, Any]:
    targets_down = _targets_down(monitoring, down_targets)
    if targets_down > 0:
        status = "fail"
        reason = f"{targets_down} monitoring target(s) are down."
    else:
        status = "pass"
        reason = "No down monitoring targets were recorded."
    return _check(
        "monitoring_targets_healthy",
        "Monitoring targets are healthy",
        status,
        "high",
        "signals.monitoring.targets_down",
        reason,
        "Restore down targets, suppress intentional maintenance, or document accepted outages.",
    )


def _alert_channels_check(monitoring: dict[str, Any]) -> dict[str, Any]:
    channels = _alert_channels(monitoring)
    return _check(
        "alert_channels_present",
        "Alert channels are recorded",
        "pass" if channels else "warn",
        "medium",
        "signals.monitoring.alert_channels",
        f"Alert channels recorded: {', '.join(channels)}." if channels else "No alert channel evidence was recorded.",
        "Record notification channels such as email, Matrix, Slack, PagerDuty, or webhook routes.",
    )


def _alert_test_check(monitoring: dict[str, Any], *, evaluated_at: datetime, max_age_days: int) -> dict[str, Any]:
    last_alert_test_at, age_days = _alert_test_age(monitoring, evaluated_at=evaluated_at)
    if last_alert_test_at == "":
        status = "warn"
        reason = "No alert test timestamp was recorded."
    elif age_days is None:
        status = "warn"
        reason = "Alert test timestamp is invalid."
    elif age_days < 0:
        status = "warn"
        reason = "Alert test timestamp is in the future."
    elif age_days > max_age_days:
        status = "warn"
        reason = f"Last alert test is {age_days} day(s) old."
    else:
        status = "pass"
        reason = f"Last alert test is {age_days} day(s) old."
    return _check(
        "alert_test_current",
        "Alert test evidence is current",
        status,
        "medium",
        "signals.monitoring.last_alert_test_at",
        reason,
        "Run a synthetic alert test and record its timestamp.",
    )


def _down_target_records(monitoring: dict[str, Any]) -> list[dict[str, str]]:
    raw_targets = monitoring.get("down_targets")
    if not isinstance(raw_targets, list):
        return []
    records = []
    for index, item in enumerate(raw_targets):
        if isinstance(item, dict):
            target = str(item.get("target") or item.get("name") or item.get("instance") or f"target-{index + 1}")
            reason = str(item.get("reason") or item.get("health") or "Target is reported down.")
        else:
            target = str(item)
            reason = "Target is reported down."
        records.append({"target": target, "status": "down", "reason": reason})
    return records


def _targets_down(monitoring: dict[str, Any], down_targets: list[dict[str, str]]) -> int:
    value = _int_value(monitoring.get("targets_down"))
    if value is None:
        value = _int_value(monitoring.get("monitors_down"))
    if value is not None:
        return value
    return len(down_targets)


def _alert_channels(monitoring: dict[str, Any]) -> list[str]:
    channels = monitoring.get("alert_channels")
    if not isinstance(channels, list):
        return []
    return [str(channel) for channel in channels if isinstance(channel, str) and channel]


def _alert_test_age(monitoring: dict[str, Any], *, evaluated_at: datetime) -> tuple[str, int | None]:
    value = monitoring.get("last_alert_test_at")
    if not isinstance(value, str) or not value:
        return "", None
    parsed = _parse_datetime(value)
    if parsed is None:
        return value, None
    return parsed.isoformat(), (evaluated_at - parsed).days


def _reference_time(evidence: dict[str, Any]) -> datetime:
    generated_at = evidence.get("generated_at")
    if isinstance(generated_at, str):
        parsed = _parse_datetime(generated_at)
        if parsed is not None:
            return parsed
    return datetime.now(UTC)


def _parse_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _int_value(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


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


def _display(value: Any) -> str:
    return "unknown" if value is None else str(value)
