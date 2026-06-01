from __future__ import annotations

import html
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .actions import create_action_plan, render_action_plan_csv, render_action_plan_markdown
from .badges import create_report_badge
from .briefs import create_report_brief, render_brief_markdown
from .bundle import create_bundle_manifest
from .catalog import (
    create_service_catalog_report,
    render_service_catalog_csv,
    render_service_catalog_markdown,
)
from .coverage import create_coverage_report, render_coverage_csv, render_coverage_markdown
from .evidence_diff import compare_evidence, render_evidence_diff_csv, render_evidence_diff_markdown
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
from .scope import create_scope_report, render_scope_csv, render_scope_markdown


def create_review_pack(
    evidence: dict[str, Any],
    policy_document: dict[str, Any],
    output_dir: str | Path,
    *,
    waiver_document: dict[str, Any] | None = None,
    scope_document: dict[str, Any] | None = None,
    catalog_document: dict[str, Any] | None = None,
    base_evidence: dict[str, Any] | None = None,
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
    evidence_drift = compare_evidence(base_evidence, evidence) if base_evidence is not None else None
    scope_report = create_scope_report(evidence, scope_document) if scope_document is not None else None
    service_catalog = create_service_catalog_report(evidence, catalog_document) if catalog_document is not None else None
    policy_matrix = create_policy_matrix(checks)
    coverage = create_coverage_report(evidence, checks)
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
    if evidence_drift is not None:
        add_artifact("evidence-drift.json", dump_json(evidence_drift), "Evidence drift", "Machine-readable evidence drift report.")
        add_artifact("evidence-drift.md", render_evidence_diff_markdown(evidence_drift), "Evidence drift", "Human-readable evidence drift report.")
        add_artifact("evidence-drift.csv", render_evidence_diff_csv(evidence_drift), "Evidence drift", "Spreadsheet-friendly evidence drift report.")
    if scope_report is not None:
        add_artifact("scope-report.json", dump_json(scope_report), "Scope report", "Machine-readable scope boundary report.")
        add_artifact("scope-report.md", render_scope_markdown(scope_report), "Scope report", "Human-readable scope boundary report.")
        add_artifact("scope-report.csv", render_scope_csv(scope_report), "Scope report", "Spreadsheet-friendly scope boundary report.")
    if service_catalog is not None:
        add_artifact(
            "service-catalog.json",
            dump_json(service_catalog),
            "Service catalog",
            "Machine-readable service ownership and evidence coverage report.",
        )
        add_artifact(
            "service-catalog.md",
            render_service_catalog_markdown(service_catalog),
            "Service catalog",
            "Human-readable service ownership and evidence coverage report.",
        )
        add_artifact(
            "service-catalog.csv",
            render_service_catalog_csv(service_catalog),
            "Service catalog",
            "Spreadsheet-friendly service catalog report.",
        )
    add_artifact("policy-matrix.json", dump_json(policy_matrix), "Policy matrix", "Machine-readable policy coverage map.")
    add_artifact("policy-matrix.md", render_policy_matrix_markdown(policy_matrix), "Policy matrix", "Reviewable policy coverage table.")
    add_artifact("policy-matrix.csv", render_policy_matrix_csv(policy_matrix), "Policy matrix", "Spreadsheet-friendly policy coverage export.")
    add_artifact("policy-coverage.json", dump_json(coverage), "Policy coverage", "Machine-readable evidence-domain coverage report.")
    add_artifact("policy-coverage.md", render_coverage_markdown(coverage), "Policy coverage", "Human-readable evidence-domain coverage report.")
    add_artifact("policy-coverage.csv", render_coverage_csv(coverage), "Policy coverage", "Spreadsheet-friendly coverage export.")
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
    index_html = render_review_pack_html(
        report=report,
        gate=gate,
        privacy_scan=privacy_scan,
        artifacts=artifacts,
    )
    add_artifact("index.html", index_html, "Review dashboard", "Browser-friendly entry point for the generated review pack.")

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
        "evidence_drift": evidence_drift,
        "scope_report": scope_report,
        "service_catalog": service_catalog,
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
    suggested_steps = [
        "Read `executive-brief.md` for the management summary.",
        "Use `scorecard.md` to see which operational domains need attention.",
    ]
    if any(artifact.get("filename") == "scope-report.md" for artifact in artifacts):
        suggested_steps.append("Check `scope-report.md` for in-scope, out-of-scope, and unclassified evidence.")
    if any(artifact.get("filename") == "service-catalog.md" for artifact in artifacts):
        suggested_steps.append("Review `service-catalog.md` for service ownership, criticality, assets, and runbook gaps.")
    if any(artifact.get("filename") == "evidence-drift.md" for artifact in artifacts):
        suggested_steps.append("Review `evidence-drift.md` for asset and signal-domain changes since the base evidence.")
    suggested_steps.extend(
        [
            "Open `report.md` and `gate-result.md` for the technical decision.",
            "Use `action-plan.md` or `action-plan.csv` to assign remediation work.",
            "Check `privacy-scan.md` before sending the pack to anyone else.",
            "Verify `manifest.json` before archiving or publishing the pack.",
        ]
    )
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
        ]
    )
    for index, step in enumerate(suggested_steps, start=1):
        lines.append(f"{index}. {step}")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_review_pack_html(
    *,
    report: dict[str, Any],
    gate: dict[str, Any],
    privacy_scan: dict[str, Any],
    artifacts: list[dict[str, Any]],
) -> str:
    summary = report.get("summary", {})
    gate_summary = gate.get("summary", {})
    privacy_summary = privacy_scan.get("summary", {})
    artifact_rows = "\n".join(_artifact_row_html(item) for item in artifacts)
    quick_links = _quick_links_html(artifacts)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>OpenOps Review Pack</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f8fafc;
      --panel: #ffffff;
      --text: #17202a;
      --muted: #566573;
      --line: #d5dde5;
      --accent: #2874a6;
      --pass: #1e8449;
      --fail: #b03a2e;
    }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    main {{
      max-width: 1120px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: 30px;
      line-height: 1.15;
    }}
    h2 {{
      margin: 32px 0 12px;
      font-size: 20px;
    }}
    .subtle {{
      color: var(--muted);
      margin: 0 0 24px;
    }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 12px;
      margin: 0 0 20px;
    }}
    .metric {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }}
    .metric span {{
      color: var(--muted);
      display: block;
      font-size: 13px;
    }}
    .metric strong {{
      display: block;
      font-size: 24px;
      margin-top: 4px;
    }}
    .status-pass {{ color: var(--pass); }}
    .status-fail {{ color: var(--fail); }}
    .quick {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin: 18px 0 28px;
    }}
    .quick a {{
      background: var(--accent);
      border-radius: 6px;
      color: #ffffff;
      font-weight: 600;
      padding: 10px 12px;
      text-decoration: none;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--panel);
      border: 1px solid var(--line);
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 10px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      color: var(--muted);
      font-size: 13px;
      font-weight: 600;
    }}
    a {{
      color: #1f618d;
    }}
  </style>
</head>
<body>
  <main>
    <h1>OpenOps Review Pack</h1>
    <p class="subtle">Generated {_escape(datetime.now(UTC).isoformat())}. Raw evidence is not included by default.</p>
    <section class="metrics">
      <div class="metric"><span>Report status</span><strong class="{_status_class(summary.get('status'))}">{_escape(str(summary.get('status', 'unknown')).upper())}</strong></div>
      <div class="metric"><span>Readiness score</span><strong>{_escape(summary.get('score', 'n/a'))}</strong></div>
      <div class="metric"><span>Gate status</span><strong class="{_status_class(gate_summary.get('status'))}">{_escape(str(gate_summary.get('status', 'unknown')).upper())}</strong></div>
      <div class="metric"><span>Privacy findings</span><strong>{_escape(privacy_summary.get('findings_count', 0))}</strong></div>
    </section>
    <nav class="quick" aria-label="Review shortcuts">
{quick_links}
    </nav>
    <h2>Artifacts</h2>
    <table>
      <thead><tr><th>Artifact</th><th>Purpose</th></tr></thead>
      <tbody>
{artifact_rows}
      </tbody>
    </table>
  </main>
</body>
</html>
"""


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


def _artifact_row_html(artifact: dict[str, Any]) -> str:
    filename = str(artifact.get("filename") or "")
    description = str(artifact.get("description") or "")
    return (
        "        <tr>"
        f"<td><a href=\"{_escape(filename)}\">{_escape(filename)}</a></td>"
        f"<td>{_escape(description)}</td>"
        "</tr>"
    )


def _quick_links_html(artifacts: list[dict[str, Any]]) -> str:
    filenames = {str(artifact.get("filename") or "") for artifact in artifacts}
    links = [
        ("executive-brief.md", "Executive Brief"),
        ("scorecard.html", "Scorecard"),
        ("scope-report.md", "Scope Report"),
        ("service-catalog.md", "Service Catalog"),
        ("evidence-drift.md", "Evidence Drift"),
        ("report.md", "Report"),
        ("action-plan.md", "Action Plan"),
        ("privacy-scan.md", "Privacy Scan"),
    ]
    lines = [
        f"      <a href=\"{_escape(filename)}\">{_escape(label)}</a>"
        for filename, label in links
        if filename in filenames
    ]
    lines.append("      <a href=\"manifest.json\">Manifest</a>")
    return "\n".join(lines)


def _status_class(value: Any) -> str:
    return "status-pass" if str(value) == "pass" else "status-fail"


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)
