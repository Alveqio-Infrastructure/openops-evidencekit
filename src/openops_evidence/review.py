from __future__ import annotations

import html
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .access import create_access_report, render_access_csv, render_access_markdown
from .actions import create_action_plan, render_action_plan_csv, render_action_plan_markdown
from .badges import create_report_badge
from .briefs import create_report_brief, render_brief_markdown
from .bundle import create_bundle_manifest
from .catalog import (
    create_service_catalog_report,
    render_service_catalog_csv,
    render_service_catalog_markdown,
)
from .checklist import create_review_checklist, render_review_checklist_csv, render_review_checklist_markdown
from .completeness import create_completeness_report, render_completeness_csv, render_completeness_markdown
from .coverage import create_coverage_report, render_coverage_csv, render_coverage_markdown
from .evidence_diff import compare_evidence, render_evidence_diff_csv, render_evidence_diff_markdown
from .freshness import create_freshness_report, render_freshness_csv, render_freshness_markdown
from .gates import evaluate_report_gate, render_gate_markdown
from .incident import create_incident_report, render_incident_csv, render_incident_markdown
from .inventory import create_evidence_inventory, render_inventory_csv, render_inventory_markdown
from .io import dump_json, write_text
from .mail import create_mail_report, render_mail_csv, render_mail_markdown
from .monitoring import create_monitoring_report, render_monitoring_csv, render_monitoring_markdown
from .policy import (
    Check,
    create_policy_matrix,
    evaluate_policy,
    parse_policy,
    render_policy_matrix_csv,
    render_policy_matrix_markdown,
)
from .privacy import render_privacy_scan_markdown, scan_privacy
from .quality import create_evidence_quality_report, render_quality_csv, render_quality_markdown
from .reports import (
    escape_markdown_text,
    format_markdown_code,
    render_junit,
    render_markdown,
    render_prometheus,
    render_sarif,
)
from .risk import create_risk_register, render_risk_register_csv, render_risk_register_markdown
from .review_summary import create_review_summary, render_review_summary_markdown
from .restore import create_restore_report, render_restore_csv, render_restore_markdown
from .runbooks import create_runbook_report, render_runbook_csv, render_runbook_markdown
from .runtime import create_runtime_report, render_runtime_csv, render_runtime_markdown
from .scorecard import create_report_scorecard, render_scorecard_csv, render_scorecard_html, render_scorecard_markdown
from .service_level import create_service_level_report, render_service_level_csv, render_service_level_markdown
from .scope import create_scope_report, render_scope_csv, render_scope_markdown
from .tls import create_tls_report, render_tls_csv, render_tls_markdown


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
    freshness_max_age_days: int | None = 30,
    restore_max_drill_age_days: int | None = 90,
    restore_max_backup_age_days: int | None = 2,
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    checks = parse_policy(policy_document)
    report = evaluate_policy(evidence, checks)
    quality_report = create_evidence_quality_report(evidence)
    inventory = create_evidence_inventory(evidence)
    freshness_report = create_freshness_report(evidence, max_age_days=freshness_max_age_days)
    restore_report = create_restore_report(
        evidence,
        max_drill_age_days=restore_max_drill_age_days,
        max_backup_age_days=restore_max_backup_age_days,
    )
    mail_report = create_mail_report(evidence) if _has_mail_context(evidence, checks) else None
    tls_report = create_tls_report(evidence) if _has_tls_context(evidence, checks) else None
    access_report = create_access_report(evidence) if _has_access_context(evidence, checks) else None
    monitoring_report = create_monitoring_report(evidence) if _has_monitoring_context(evidence, checks) else None
    runtime_report = create_runtime_report(evidence) if _has_runtime_context(evidence, checks) else None
    incident_report = create_incident_report(evidence, catalog_document=catalog_document) if _has_incident_context(evidence, catalog_document, checks) else None
    evidence_drift = compare_evidence(base_evidence, evidence) if base_evidence is not None else None
    scope_report = create_scope_report(evidence, scope_document) if scope_document is not None else None
    service_catalog = create_service_catalog_report(evidence, catalog_document) if catalog_document is not None else None
    service_level_report = create_service_level_report(evidence, catalog_document) if catalog_document is not None else None
    runbook_report = create_runbook_report(evidence, catalog_document=catalog_document) if catalog_document is not None else None
    policy_matrix = create_policy_matrix(checks)
    completeness_report = create_completeness_report(evidence, checks)
    coverage = create_coverage_report(evidence, checks)
    scorecard = create_report_scorecard(report)
    brief = create_report_brief(report, max_findings=max_findings)
    action_plan = create_action_plan(report, waiver_document=waiver_document)
    risk_register = create_risk_register(report, waiver_document=waiver_document)
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
    add_artifact("quality-report.json", dump_json(quality_report), "Evidence quality", "Machine-readable evidence hygiene report.")
    add_artifact("quality-report.md", render_quality_markdown(quality_report), "Evidence quality", "Human-readable evidence hygiene report.")
    add_artifact("quality-report.csv", render_quality_csv(quality_report), "Evidence quality", "Spreadsheet-friendly evidence hygiene report.")
    add_artifact("freshness-report.json", dump_json(freshness_report), "Evidence freshness", "Machine-readable evidence timestamp freshness report.")
    add_artifact("freshness-report.md", render_freshness_markdown(freshness_report), "Evidence freshness", "Human-readable evidence timestamp freshness report.")
    add_artifact("freshness-report.csv", render_freshness_csv(freshness_report), "Evidence freshness", "Spreadsheet-friendly timestamp freshness export.")
    add_artifact("restore-report.json", dump_json(restore_report), "Restore assurance", "Machine-readable backup and restore drill assurance report.")
    add_artifact("restore-report.md", render_restore_markdown(restore_report), "Restore assurance", "Human-readable backup and restore drill assurance report.")
    add_artifact("restore-report.csv", render_restore_csv(restore_report), "Restore assurance", "Spreadsheet-friendly restore assurance export.")
    if mail_report is not None:
        add_artifact("mail-report.json", dump_json(mail_report), "Mail domain report", "Machine-readable SPF, DKIM, and DMARC report.")
        add_artifact("mail-report.md", render_mail_markdown(mail_report), "Mail domain report", "Human-readable SPF, DKIM, and DMARC report.")
        add_artifact("mail-report.csv", render_mail_csv(mail_report), "Mail domain report", "Spreadsheet-friendly mail domain report.")
    if tls_report is not None:
        add_artifact("tls-report.json", dump_json(tls_report), "TLS certificate report", "Machine-readable TLS certificate expiry report.")
        add_artifact("tls-report.md", render_tls_markdown(tls_report), "TLS certificate report", "Human-readable TLS certificate expiry report.")
        add_artifact("tls-report.csv", render_tls_csv(tls_report), "TLS certificate report", "Spreadsheet-friendly TLS certificate report.")
    if access_report is not None:
        add_artifact("access-report.json", dump_json(access_report), "Access exposure report", "Machine-readable administrative access exposure report.")
        add_artifact("access-report.md", render_access_markdown(access_report), "Access exposure report", "Human-readable administrative access exposure report.")
        add_artifact("access-report.csv", render_access_csv(access_report), "Access exposure report", "Spreadsheet-friendly administrative access report.")
    if monitoring_report is not None:
        add_artifact("monitoring-report.json", dump_json(monitoring_report), "Monitoring report", "Machine-readable monitoring target and alert report.")
        add_artifact("monitoring-report.md", render_monitoring_markdown(monitoring_report), "Monitoring report", "Human-readable monitoring target and alert report.")
        add_artifact("monitoring-report.csv", render_monitoring_csv(monitoring_report), "Monitoring report", "Spreadsheet-friendly monitoring report.")
    if runtime_report is not None:
        add_artifact("runtime-report.json", dump_json(runtime_report), "Runtime report", "Machine-readable runtime container and timer report.")
        add_artifact("runtime-report.md", render_runtime_markdown(runtime_report), "Runtime report", "Human-readable runtime container and timer report.")
        add_artifact("runtime-report.csv", render_runtime_csv(runtime_report), "Runtime report", "Spreadsheet-friendly runtime report.")
    if incident_report is not None:
        add_artifact("incident-report.json", dump_json(incident_report), "Incident readiness report", "Machine-readable incident response readiness report.")
        add_artifact("incident-report.md", render_incident_markdown(incident_report), "Incident readiness report", "Human-readable incident response readiness report.")
        add_artifact("incident-report.csv", render_incident_csv(incident_report), "Incident readiness report", "Spreadsheet-friendly incident response report.")
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
    if service_level_report is not None:
        add_artifact(
            "service-level-report.json",
            dump_json(service_level_report),
            "Service level report",
            "Machine-readable service-level and SLO report.",
        )
        add_artifact(
            "service-level-report.md",
            render_service_level_markdown(service_level_report),
            "Service level report",
            "Human-readable service-level and SLO report.",
        )
        add_artifact(
            "service-level-report.csv",
            render_service_level_csv(service_level_report),
            "Service level report",
            "Spreadsheet-friendly service-level and SLO report.",
        )
    if runbook_report is not None:
        add_artifact("runbook-report.json", dump_json(runbook_report), "Runbook report", "Machine-readable runbook coverage report.")
        add_artifact("runbook-report.md", render_runbook_markdown(runbook_report), "Runbook report", "Human-readable runbook coverage report.")
        add_artifact("runbook-report.csv", render_runbook_csv(runbook_report), "Runbook report", "Spreadsheet-friendly runbook coverage report.")
    add_artifact("policy-matrix.json", dump_json(policy_matrix), "Policy matrix", "Machine-readable policy coverage map.")
    add_artifact("policy-matrix.md", render_policy_matrix_markdown(policy_matrix), "Policy matrix", "Reviewable policy coverage table.")
    add_artifact("policy-matrix.csv", render_policy_matrix_csv(policy_matrix), "Policy matrix", "Spreadsheet-friendly policy coverage export.")
    add_artifact("completeness-report.json", dump_json(completeness_report), "Evidence completeness", "Machine-readable policy evidence completeness report.")
    add_artifact("completeness-report.md", render_completeness_markdown(completeness_report), "Evidence completeness", "Human-readable policy evidence completeness report.")
    add_artifact("completeness-report.csv", render_completeness_csv(completeness_report), "Evidence completeness", "Spreadsheet-friendly policy evidence completeness report.")
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
    add_artifact("risk-register.json", dump_json(risk_register), "Risk register", "Machine-readable open and accepted risk register.")
    add_artifact("risk-register.md", render_risk_register_markdown(risk_register), "Risk register", "Human-readable open and accepted risk register.")
    add_artifact("risk-register.csv", render_risk_register_csv(risk_register), "Risk register", "Spreadsheet-friendly risk register export.")
    add_artifact("readiness-badge.json", dump_json(badge), "Readiness badge", "Shields-compatible endpoint JSON.")
    add_artifact("gate-result.json", dump_json(gate), "Gate result", "Machine-readable CI gate decision.")
    add_artifact("gate-result.md", render_gate_markdown(gate), "Gate result", "Human-readable CI gate decision.")

    privacy_scan = scan_privacy([artifact["path"] for artifact in artifacts])
    _relativize_privacy_paths(privacy_scan, output)
    add_artifact("privacy-scan.json", dump_json(privacy_scan), "Privacy scan", "Machine-readable scan of generated artifacts.")
    add_artifact("privacy-scan.md", render_privacy_scan_markdown(privacy_scan), "Privacy scan", "Human-readable scan of generated artifacts.")
    review_summary = create_review_summary(
        report=report,
        gate=gate,
        privacy_scan=privacy_scan,
        quality_report=quality_report,
        completeness_report=completeness_report,
        freshness_report=freshness_report,
        restore_report=restore_report,
        mail_report=mail_report,
        tls_report=tls_report,
        access_report=access_report,
        monitoring_report=monitoring_report,
        runtime_report=runtime_report,
        incident_report=incident_report,
        risk_register=risk_register,
        scope_report=scope_report,
        evidence_drift=evidence_drift,
        service_catalog=service_catalog,
        service_level_report=service_level_report,
        runbook_report=runbook_report,
    )
    add_artifact("review-summary.json", dump_json(review_summary), "Review summary", "Machine-readable review decision summary.")
    add_artifact("review-summary.md", render_review_summary_markdown(review_summary), "Review summary", "One-page handoff decision summary.")
    review_checklist = create_review_checklist(review_summary, artifacts)
    add_artifact("review-checklist.json", dump_json(review_checklist), "Review checklist", "Machine-readable reviewer handoff checklist.")
    add_artifact("review-checklist.md", render_review_checklist_markdown(review_checklist), "Review checklist", "Human-readable reviewer handoff checklist.")
    add_artifact("review-checklist.csv", render_review_checklist_csv(review_checklist), "Review checklist", "Spreadsheet-friendly reviewer checklist.")
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
        "quality_report": quality_report,
        "completeness_report": completeness_report,
        "freshness_report": freshness_report,
        "restore_report": restore_report,
        "mail_report": mail_report,
        "tls_report": tls_report,
        "access_report": access_report,
        "monitoring_report": monitoring_report,
        "runtime_report": runtime_report,
        "incident_report": incident_report,
        "risk_register": risk_register,
        "review_summary": review_summary,
        "review_checklist": review_checklist,
        "evidence_drift": evidence_drift,
        "scope_report": scope_report,
        "service_catalog": service_catalog,
        "service_level_report": service_level_report,
        "runbook_report": runbook_report,
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
        "Read `review-summary.md` for the handoff decision.",
        "Use `review-checklist.md` to track reviewer sign-off tasks.",
        "Read `executive-brief.md` for the management summary.",
        "Use `scorecard.md` to see which operational domains need attention.",
        "Use `quality-report.md` to catch evidence hygiene problems before sharing.",
        "Use `completeness-report.md` to find missing policy evidence before retesting.",
    ]
    if any(artifact.get("filename") == "scope-report.md" for artifact in artifacts):
        suggested_steps.append("Check `scope-report.md` for in-scope, out-of-scope, and unclassified evidence.")
    if any(artifact.get("filename") == "freshness-report.md" for artifact in artifacts):
        suggested_steps.append("Check `freshness-report.md` before relying on old evidence timestamps.")
    if any(artifact.get("filename") == "restore-report.md" for artifact in artifacts):
        suggested_steps.append("Use `restore-report.md` to confirm backup recency and restore drill proof.")
    if any(artifact.get("filename") == "mail-report.md" for artifact in artifacts):
        suggested_steps.append("Check `mail-report.md` for SPF, DKIM, and DMARC evidence.")
    if any(artifact.get("filename") == "tls-report.md" for artifact in artifacts):
        suggested_steps.append("Use `tls-report.md` to review certificate expiry and renewal risk.")
    if any(artifact.get("filename") == "access-report.md" for artifact in artifacts):
        suggested_steps.append("Use `access-report.md` to review public SSH, MFA, and admin entrypoints.")
    if any(artifact.get("filename") == "monitoring-report.md" for artifact in artifacts):
        suggested_steps.append("Use `monitoring-report.md` to review targets, down targets, alert channels, and alert test freshness.")
    if any(artifact.get("filename") == "runtime-report.md" for artifact in artifacts):
        suggested_steps.append("Use `runtime-report.md` to review stopped containers, restart policies, and failed timers.")
    if any(artifact.get("filename") == "incident-report.md" for artifact in artifacts):
        suggested_steps.append("Use `incident-report.md` to review escalation contacts, incident runbooks, alerts, restore proof, and emergency access.")
    if any(artifact.get("filename") == "service-catalog.md" for artifact in artifacts):
        suggested_steps.append("Review `service-catalog.md` for service ownership, criticality, assets, and runbook gaps.")
    if any(artifact.get("filename") == "service-level-report.md" for artifact in artifacts):
        suggested_steps.append("Review `service-level-report.md` for service-level targets, missing SLO evidence, and error-budget risk.")
    if any(artifact.get("filename") == "runbook-report.md" for artifact in artifacts):
        suggested_steps.append("Use `runbook-report.md` to confirm required runbooks are present and current.")
    if any(artifact.get("filename") == "evidence-drift.md" for artifact in artifacts):
        suggested_steps.append("Review `evidence-drift.md` for asset and signal-domain changes since the base evidence.")
    suggested_steps.extend(
        [
            "Open `report.md` and `gate-result.md` for the technical decision.",
            "Use `action-plan.md` or `action-plan.csv` to assign remediation work.",
            "Use `risk-register.md` to review open, accepted, and expired accepted risks.",
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
        ("review-summary.md", "Review Summary"),
        ("review-checklist.md", "Checklist"),
        ("scorecard.html", "Scorecard"),
        ("quality-report.md", "Quality"),
        ("completeness-report.md", "Completeness"),
        ("freshness-report.md", "Freshness"),
        ("restore-report.md", "Restore"),
        ("mail-report.md", "Mail"),
        ("tls-report.md", "TLS"),
        ("access-report.md", "Access"),
        ("monitoring-report.md", "Monitoring"),
        ("runtime-report.md", "Runtime"),
        ("incident-report.md", "Incident"),
        ("scope-report.md", "Scope Report"),
        ("service-catalog.md", "Service Catalog"),
        ("service-level-report.md", "Service Levels"),
        ("runbook-report.md", "Runbook Report"),
        ("evidence-drift.md", "Evidence Drift"),
        ("report.md", "Report"),
        ("action-plan.md", "Action Plan"),
        ("risk-register.md", "Risk Register"),
        ("privacy-scan.md", "Privacy Scan"),
    ]
    lines = [
        f"      <a href=\"{_escape(filename)}\">{_escape(label)}</a>"
        for filename, label in links
        if filename in filenames
    ]
    lines.append("      <a href=\"manifest.json\">Manifest</a>")
    return "\n".join(lines)


def _has_mail_context(evidence: dict[str, Any], checks: list[Check]) -> bool:
    signals = evidence.get("signals")
    if isinstance(signals, dict) and isinstance(signals.get("mail"), dict):
        return True
    return any(check.path.startswith("signals.mail") for check in checks)


def _has_tls_context(evidence: dict[str, Any], checks: list[Check]) -> bool:
    signals = evidence.get("signals")
    if isinstance(signals, dict) and isinstance(signals.get("tls"), dict):
        return True
    return any(check.path.startswith("signals.tls") for check in checks)


def _has_access_context(evidence: dict[str, Any], checks: list[Check]) -> bool:
    signals = evidence.get("signals")
    if isinstance(signals, dict) and isinstance(signals.get("access"), dict):
        return True
    return any(check.path.startswith("signals.access") for check in checks)


def _has_monitoring_context(evidence: dict[str, Any], checks: list[Check]) -> bool:
    signals = evidence.get("signals")
    if isinstance(signals, dict) and isinstance(signals.get("monitoring"), dict):
        return True
    return any(check.path.startswith("signals.monitoring") for check in checks)


def _has_runtime_context(evidence: dict[str, Any], checks: list[Check]) -> bool:
    signals = evidence.get("signals")
    if isinstance(signals, dict) and isinstance(signals.get("runtime"), dict):
        return True
    return any(check.path.startswith("signals.runtime") for check in checks)


def _has_incident_context(
    evidence: dict[str, Any],
    catalog_document: dict[str, Any] | None,
    checks: list[Check],
) -> bool:
    if catalog_document is not None:
        return True
    return any("incident" in check.id.lower() or "incident" in check.title.lower() for check in checks)


def _status_class(value: Any) -> str:
    return "status-pass" if str(value) == "pass" else "status-fail"


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)
