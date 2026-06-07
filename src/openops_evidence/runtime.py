from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from .reports import escape_markdown_text, format_markdown_code


def create_runtime_report(evidence: dict[str, Any]) -> dict[str, Any]:
    runtime = _runtime_signal(evidence)
    docker = runtime.get("docker") if isinstance(runtime.get("docker"), dict) else {}
    systemd = runtime.get("systemd") if isinstance(runtime.get("systemd"), dict) else {}
    exited_containers = _string_list(docker.get("exited_containers"))
    restart_policy_missing = _string_list(docker.get("restart_policy_missing"))
    failed_timers = _string_list(systemd.get("failed_timers"))
    checks = [
        _runtime_signal_check(runtime),
        _docker_container_check(docker, exited_containers),
        _docker_restart_policy_check(restart_policy_missing),
        _systemd_timer_check(systemd, failed_timers),
    ]
    failed = [check for check in checks if check["status"] == "fail"]
    warnings = [check for check in checks if check["status"] == "warn"]
    passed = [check for check in checks if check["status"] == "pass"]
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": {
            "created_by": "openops-evidencekit",
            "source_generated_at": evidence.get("generated_at"),
            "source": evidence.get("metadata", {}).get("source", ""),
            "organization": evidence.get("metadata", {}).get("organization", ""),
            "environment": evidence.get("metadata", {}).get("environment", ""),
        },
        "summary": {
            "status": "fail" if failed else "warn" if warnings else "pass",
            "containers_total": _int_value(docker.get("containers_total")),
            "containers_running": _int_value(docker.get("containers_running")),
            "containers_exited": _int_value(docker.get("containers_exited")),
            "restart_policy_missing_count": len(restart_policy_missing),
            "timers_total": _int_value(systemd.get("timers_total")),
            "timers_active": _int_value(systemd.get("timers_active")),
            "timers_failed": _int_value(systemd.get("timers_failed")) or len(failed_timers),
            "checks_total": len(checks),
            "checks_passed": len(passed),
            "checks_warn": len(warnings),
            "checks_failed": len(failed),
        },
        "checks": checks,
        "exited_containers": exited_containers,
        "restart_policy_missing": restart_policy_missing,
        "failed_timers": failed_timers,
    }


def render_runtime_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    metadata = report.get("metadata", {})
    lines = [
        "# OpenOps Runtime Report",
        "",
        f"- Generated: {format_markdown_code(report.get('generated_at', 'unknown'))}",
        f"- Source evidence: {format_markdown_code(metadata.get('source_generated_at', 'unknown'))}",
        f"- Status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Containers: **{escape_markdown_text(_display(summary.get('containers_total')))}**",
        f"- Exited containers: **{escape_markdown_text(_display(summary.get('containers_exited')))}**",
        f"- Missing restart policy: **{escape_markdown_text(summary.get('restart_policy_missing_count', 0))}**",
        f"- systemd timers: **{escape_markdown_text(_display(summary.get('timers_total')))}**",
        f"- Failed timers: **{escape_markdown_text(summary.get('timers_failed', 0))}**",
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
    _append_list_section(lines, "Exited Containers", report.get("exited_containers", []))
    _append_list_section(lines, "Running Containers Without Restart Policy", report.get("restart_policy_missing", []))
    _append_list_section(lines, "Failed systemd Timers", report.get("failed_timers", []))
    lines.extend(
        [
            "## Interpretation",
            "",
            "- `pass`: runtime evidence exists and no stopped containers, missing restart policies, or failed timers were found.",
            "- `warn`: runtime evidence is incomplete or Docker containers need operator review.",
            "- `fail`: runtime evidence is missing or systemd timers are failed.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_runtime_csv(report: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["record_type", "id", "title", "name", "status", "severity", "path", "reason", "recommended_action"],
        lineterminator="\n",
    )
    writer.writeheader()
    for check in report.get("checks", []):
        writer.writerow(
            {
                "record_type": "check",
                "id": check.get("id", ""),
                "title": check.get("title", ""),
                "name": "",
                "status": check.get("status", ""),
                "severity": check.get("severity", ""),
                "path": check.get("path", ""),
                "reason": check.get("reason", ""),
                "recommended_action": check.get("recommended_action", ""),
            }
        )
    for record_type, path, names in (
        ("exited_container", "signals.runtime.docker.exited_containers", report.get("exited_containers", [])),
        ("restart_policy_missing", "signals.runtime.docker.restart_policy_missing", report.get("restart_policy_missing", [])),
        ("failed_timer", "signals.runtime.systemd.failed_timers", report.get("failed_timers", [])),
    ):
        for name in names:
            writer.writerow(
                {
                    "record_type": record_type,
                    "id": "",
                    "title": "",
                    "name": name,
                    "status": "review",
                    "severity": "medium" if record_type != "failed_timer" else "high",
                    "path": path,
                    "reason": "Runtime item needs operator review.",
                    "recommended_action": "Confirm expected state or remediate runtime evidence.",
                }
            )
    return output.getvalue()


def _runtime_signal(evidence: dict[str, Any]) -> dict[str, Any]:
    signals = evidence.get("signals")
    if not isinstance(signals, dict):
        return {}
    runtime = signals.get("runtime")
    return runtime if isinstance(runtime, dict) else {}


def _runtime_signal_check(runtime: dict[str, Any]) -> dict[str, Any]:
    present = bool(runtime)
    return _check(
        "runtime_signal_present",
        "Runtime signal is present",
        "pass" if present else "fail",
        "critical",
        "signals.runtime",
        "Runtime evidence is present." if present else "signals.runtime is missing or empty.",
        "Collect runtime evidence from Docker, systemd, or another runtime source.",
    )


def _docker_container_check(docker: dict[str, Any], exited_containers: list[str]) -> dict[str, Any]:
    total = _int_value(docker.get("containers_total"))
    if not docker:
        status = "warn"
        reason = "No Docker runtime evidence was recorded."
    elif exited_containers:
        status = "warn"
        reason = f"{len(exited_containers)} exited container(s) need review."
    else:
        status = "pass"
        reason = f"{_display(total)} Docker container(s) recorded without exited containers."
    return _check(
        "docker_containers_reviewed",
        "Docker containers are reviewed",
        status,
        "medium",
        "signals.runtime.docker",
        reason,
        "Confirm exited containers are intentional or restart the affected workload.",
    )


def _docker_restart_policy_check(restart_policy_missing: list[str]) -> dict[str, Any]:
    return _check(
        "docker_restart_policy_present",
        "Running containers have restart policies",
        "warn" if restart_policy_missing else "pass",
        "medium",
        "signals.runtime.docker.restart_policy_missing",
        f"{len(restart_policy_missing)} running container(s) have no restart policy."
        if restart_policy_missing
        else "No running containers without restart policy were recorded.",
        "Set an explicit restart policy for long-running containers or document why restart is disabled.",
    )


def _systemd_timer_check(systemd: dict[str, Any], failed_timers: list[str]) -> dict[str, Any]:
    failed_count = _int_value(systemd.get("timers_failed")) or len(failed_timers)
    if not systemd:
        status = "warn"
        reason = "No systemd timer evidence was recorded."
    elif failed_count > 0:
        status = "fail"
        reason = f"{failed_count} systemd timer(s) are failed."
    else:
        status = "pass"
        reason = "No failed systemd timers were recorded."
    return _check(
        "systemd_timers_healthy",
        "systemd timers are healthy",
        status,
        "high",
        "signals.runtime.systemd.failed_timers",
        reason,
        "Inspect failed timers with systemctl and record remediation or accepted maintenance state.",
    )


def _check(check_id: str, title: str, status: str, severity: str, path: str, reason: str, recommended_action: str) -> dict[str, Any]:
    return {
        "id": check_id,
        "title": title,
        "status": status,
        "severity": severity,
        "path": path,
        "reason": reason,
        "recommended_action": recommended_action,
    }


def _append_list_section(lines: list[str], title: str, values: Any) -> None:
    lines.extend(["", f"## {title}", ""])
    names = _string_list(values)
    if not names:
        lines.extend(["No records.", ""])
        return
    for name in names:
        lines.append(f"- {format_markdown_code(name)}")
    lines.append("")


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item]


def _int_value(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _display(value: Any) -> str:
    return "unknown" if value is None else str(value)
