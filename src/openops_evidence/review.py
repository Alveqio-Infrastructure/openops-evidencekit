from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .actions import create_action_plan, render_action_plan_csv, render_action_plan_markdown
from .badges import create_report_badge
from .briefs import create_report_brief, render_brief_markdown
from .bundle import create_bundle_manifest
from .gates import evaluate_report_gate, render_gate_markdown
from .inventory import create_evidence_inventory, render_inventory_csv, render_inventory_markdown
from .io import dump_json, write_text
from .policy import (
    create_policy_matrix,
    evaluate_policy,
    parse_policy,
    render_policy_matrix_csv,
    render_policy_matrix_markdown,
)
from .privacy import render_privacy_scan_markdown, scan_privacy
from .reports import (
    escape_markdown_text,
    format_markdown_code,
    render_junit,
    render_markdown,
    render_prometheus,
    render_sarif,
)
from .scorecard import create_report_scorecard, render_scorecard_csv, render_scorecard_html, render_scorecard_markdown


def create_review_pack(
    evidence: dict[str, Any],
    policy_document: dict[str, Any],
    output_dir: str | Path,
    *,
    waiver_document: dict[str, Any] | None = None,
    name: str = "openops-review-pack",
    max_findings: int = 5,
    min_score: int | None = None,
    max_failed: int | None = None,
    max_warnings: int | None = None,
    max_critical: int | None = None,
    max_high: int | None = None,
    ignore_report_status: bool = False,
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    checks = parse_policy(policy_document)
    report = evaluate_policy(evidence, checks)
    inventory = create_evidence_inventory(evidence)
    policy_matrix = create_policy_matrix(checks)
    scorecard = create_report_scorecard(report)
    brief = create_report_brief(report, max_findings=max_findings)
    action_plan = create_action_plan(report, waiver_document=waiver_document)
    badge = create_report_badge(report)
    gate = evaluate_report_gate(
        report,
        min_score=min_score,
        max_failed=max_failed,
        max_warnings=max_warnings,
        max_critical=max_critical,
        max_high=max_high,
        ignore_report_status=ignore_report_status,
    )
    artifacts: list[dict[str, Any]] = []

    def add_artifact(filename: str, content: str, title: str, description: str) -> Path:
        path = output / filename
        write_text(path, content)
        artifacts.append(
            {
                "path": path,
                "filename": filename,
                "title": title,
                "description": description,
            }
        )
        return path

    add_artifact("inventory.json", dump_json(inventory), "Evidence inventory", "Machine-readable asset and signal inventory.")
    add_artifact("inventory.md", render_inventory_markdown(inventory), "Evidence inventory", "Wiki-friendly asset and signal inventory.")
    add_artifact("inventory.csv", render_inventory_csv(inventory), "Evidence inventory", "Spreadsheet-friendly inventory export.")
    add_artifact("policy-matrix.json", dump_json(policy_matrix), "Policy matrix", "Machine-readable policy coverage map.")
    add_artifact("policy-matrix.md", render_policy_matrix_markdown(policy_matrix), "Policy matrix", "Reviewable policy coverage table.")
    add_artifact("policy-matrix.csv", render_policy_matrix_csv(policy_matrix), "Policy matrix", "Spreadsheet-friendly policy coverage export.")
    add_artifact("scorecard.json", dump_json(scorecard), "Domain scorecard", "Machine-readable domain summary.")
    add_artifact("scorecard.md", render_scorecard_markdown(scorecard), "Domain scorecard", "Human-readable domain summary.")
    add_artifact("scorecard.csv", render_scorecard_csv(scorecard), "Domain scorecard", "Spreadsheet-friendly domain summary.")
    add_artifact("scorecard.html", render_scorecard_html(scorecard), "Domain scorecard", "Self-contained HTML dashboard.")
    add_artifact("report.json", dump_json(report), "Readiness report", "Canonical check result JSON.")
    add_artifact("report.md", render_markdown(report), "Readiness report", "Human-readable report.")
    add_artifact("report.junit.xml", render_junit(report), "JUnit report", "CI test-result output.")
    add_artifact("report.sarif.json", render_sarif(report), "SARIF report", "Security and code-scanning compatible findings.")
    add_artifact("report.prom", render_prometheus(report), "Prometheus metrics", "Text metrics for dashboards and scraping.")
    add_artifact("executive-brief.json", dump_json(brief), "Executive brief", "Machine-readable stakeholder summary.")
    add_artifact("executive-brief.md", render_brief_markdown(brief), "Executive brief", "Stakeholder-ready Markdown summary.")
    add_artifact("action-plan.json", dump_json(action_plan), "Action plan", "Machine-readable remediation queue.")
    add_artifact("action-plan.md", render_action_plan_markdown(action_plan), "Action plan", "Prioritized remediation plan.")
    add_artifact("action-plan.csv", render_action_plan_csv(action_plan), "Action plan", "Spreadsheet-friendly remediation queue.")
    add_artifact("readiness-badge.json", dump_json(badge), "Readiness badge", "Shields-compatible endpoint JSON.")
    add_artifact("gate-result.json", dump_json(gate), "Gate result", "Machine-readable CI gate decision.")
    add_artifact("gate-result.md", render_gate_markdown(gate), "Gate result", "Human-readable CI gate decision.")

    privacy_scan = scan_privacy([artifact["path"] for artifact in artifacts])
    _relativize_privacy_paths(privacy_scan, output)
    add_artifact("privacy-scan.json", dump_json(privacy_scan), "Privacy scan", "Machine-readable scan of generated artifacts.")
    add_artifact("privacy-scan.md", render_privacy_scan_markdown(privacy_scan), "Privacy scan", "Human-readable scan of generated artifacts.")

    readme = render_review_pack_readme(
        report=report,
        gate=gate,
        privacy_scan=privacy_scan,
        artifacts=artifacts,
    )
    add_artifact("README.md", readme, "Review index", "Entry point for the generated review pack.")

    manifest_paths = [str(artifact["path"]) for artifact in artifacts]
    manifest = create_bundle_manifest(manifest_paths, name=name, base_dir=str(output))
    manifest_path = output / "manifest.json"
    write_text(manifest_path, dump_json(manifest))
    return {
        "schema_version": "0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "output_dir": str(output),
        "manifest_path": str(manifest_path),
        "artifact_count": len(artifacts) + 1,
        "report": report,
        "gate": gate,
        "privacy_scan": privacy_scan,
        "manifest": manifest,
    }


def render_review_pack_readme(
    *,
    report: dict[str, Any],
    gate: dict[str, Any],
    privacy_scan: dict[str, Any],
    artifacts: list[dict[str, Any]],
) -> str:
    summary = report.get("summary", {})
    gate_summary = gate.get("summary", {})
    privacy_summary = privacy_scan.get("summary", {})
    lines = [
        "# OpenOps Review Pack",
        "",
        f"- Generated: {format_markdown_code(datetime.now(UTC).isoformat())}",
        f"- Report status: **{escape_markdown_text(str(summary.get('status', 'unknown')).upper())}**",
        f"- Readiness score: **{escape_markdown_text(summary.get('score', 'n/a'))}**",
        f"- Gate status: **{escape_markdown_text(str(gate_summary.get('status', 'unknown')).upper())}**",
        f"- Privacy scan findings: **{escape_markdown_text(privacy_summary.get('findings_count', 0))}**",
        "",
        "This folder is a generated readiness review handoff. It does not include raw evidence by default.",
        "Review the privacy scan and source evidence before sharing outside the operating team.",
        "",
        "## Contents",
        "",
        "| Artifact | Purpose |",
        "| --- | --- |",
    ]
    for artifact in artifacts:
        lines.append(
            "| "
            f"{format_markdown_code(artifact['filename'])} | "
            f"{escape_markdown_text(artifact['description'])} |"
        )
    lines.extend(
        [
            f"| {format_markdown_code('manifest.json')} | Hash manifest for generated artifacts. |",
            "",
            "## Suggested Review Order",
            "",
            "1. Read `executive-brief.md` for the management summary.",
            "2. Use `scorecard.md` to see which operational domains need attention.",
            "3. Open `report.md` and `gate-result.md` for the technical decision.",
            "4. Use `action-plan.md` or `action-plan.csv` to assign remediation work.",
            "5. Check `privacy-scan.md` before sending the pack to anyone else.",
            "6. Verify `manifest.json` before archiving or publishing the pack.",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _relativize_privacy_paths(scan: dict[str, Any], base_dir: Path) -> None:
    base = base_dir.resolve()
    for finding in scan.get("findings", []):
        raw_path = finding.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            continue
        path = Path(raw_path)
        try:
            finding["path"] = path.resolve().relative_to(base).as_posix()
        except ValueError:
            continue
