from __future__ import annotations

import argparse
import sys
from importlib import resources
from pathlib import Path
from typing import Any

from . import __version__
from .access import create_access_report, render_access_csv, render_access_markdown
from .actions import create_action_plan, render_action_plan_csv, render_action_plan_markdown
from .attestations import create_review_attestation, render_attestation_csv, render_attestation_markdown
from .badges import create_report_badge
from .briefs import create_report_brief, render_brief_markdown
from .bundle import (
    DEFAULT_SIGNING_KEY_ENV,
    create_bundle_manifest,
    create_bundle_archive,
    create_bundle_signature,
    load_signing_key,
    verify_bundle_manifest,
    verify_bundle_signature,
)
from .catalog import (
    create_service_catalog_report,
    render_service_catalog_csv,
    render_service_catalog_markdown,
    validate_catalog_document,
)
from .compare import compare_reports, render_comparison_markdown
from .completeness import create_completeness_report, render_completeness_csv, render_completeness_markdown
from .collectors import (
    collect_borg_archives,
    collect_docker_containers,
    collect_docs_directory,
    collect_fixture,
    collect_local,
    collect_apt_upgrades,
    collect_prometheus_targets,
    collect_nmap_xml,
    collect_restic_snapshots,
    collect_systemd_timers,
    collect_tls,
    collect_trivy_json,
    collect_uptime_kuma_export,
    collect_ufw_status,
)
from .coverage import create_coverage_report, render_coverage_csv, render_coverage_markdown
from .evidence_diff import compare_evidence, render_evidence_diff_csv, render_evidence_diff_markdown
from .exposure import create_exposure_report, render_exposure_csv, render_exposure_markdown
from .firewall import create_firewall_report, render_firewall_csv, render_firewall_markdown
from .freshness import create_freshness_report, render_freshness_csv, render_freshness_markdown
from .gates import evaluate_report_gate, render_gate_markdown
from .history import append_report_history, render_history_csv, render_history_markdown, render_history_svg
from .incident import create_incident_report, render_incident_csv, render_incident_markdown
from .inventory import create_evidence_inventory, render_inventory_csv, render_inventory_markdown
from .io import UserFacingError, dump_json, load_json, load_structured, write_text
from .mail import create_mail_report, render_mail_csv, render_mail_markdown
from .monitoring import create_monitoring_report, render_monitoring_csv, render_monitoring_markdown
from .patching import create_patch_report, render_patch_csv, render_patch_markdown
from .merge import merge_evidence
from .policy import (
    create_policy_matrix,
    evaluate_policy,
    parse_policy,
    render_policy_matrix_csv,
    render_policy_matrix_markdown,
    render_policy_operator_list,
    validate_policy_document,
)
from .policypacks import get_policy_pack, render_policy_pack_list, read_policy_pack
from .privacy import render_privacy_scan_markdown, scan_privacy
from .quality import create_evidence_quality_report, render_quality_csv, render_quality_markdown
from .redact import redact_document
from .questionnaire import create_policy_questionnaire, render_questionnaire_csv, render_questionnaire_markdown
from .reports import (
    render_bookstack_markdown,
    render_html,
    render_junit,
    render_markdown,
    render_prometheus,
    render_sarif,
)
from .review import create_review_pack
from .restore import create_restore_report, render_restore_csv, render_restore_markdown
from .risk import create_risk_register, render_risk_register_csv, render_risk_register_markdown
from .runbooks import create_runbook_report, render_runbook_csv, render_runbook_markdown
from .runtime import create_runtime_report, render_runtime_csv, render_runtime_markdown
from .scaffold import create_evidence_scaffold
from .schema import (
    validate_action_plan,
    validate_access_report,
    validate_badge,
    validate_bundle_manifest,
    validate_bundle_signature,
    validate_bundle_verification,
    validate_completeness_report,
    validate_evidence,
    validate_evidence_drift,
    validate_exposure_report,
    validate_firewall_report,
    validate_executive_brief,
    validate_freshness_report,
    validate_gate_result,
    validate_incident_report,
    validate_inventory,
    validate_mail_report,
    validate_monitoring_report,
    validate_patch_report,
    validate_policy_matrix,
    validate_privacy_scan,
    validate_policy_coverage,
    validate_questionnaire,
    validate_quality_report,
    validate_report,
    validate_report_comparison,
    validate_report_history,
    validate_review_attestation,
    validate_review_checklist,
    validate_review_summary,
    validate_restore_report,
    validate_risk_register,
    validate_runtime_report,
    validate_runbook_report,
    validate_scorecard,
    validate_service_level_report,
    validate_service_catalog_report,
    validate_scope_report,
    validate_tls_report,
    validate_vulnerability_report,
)
from .scorecard import create_report_scorecard, render_scorecard_csv, render_scorecard_html, render_scorecard_markdown
from .service_level import create_service_level_report, render_service_level_csv, render_service_level_markdown
from .scope import create_scope_report, render_scope_csv, render_scope_markdown, validate_scope_document
from .tickets import export_action_plan_tickets
from .tls import create_tls_report, render_tls_csv, render_tls_markdown
from .vulnerabilities import create_vulnerability_report, render_vulnerability_csv, render_vulnerability_markdown
from .waivers import validate_waiver_document


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except UserFacingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openops-evidence",
        description="Collect, check, compare, redact, and report infrastructure operations evidence.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(required=True)

    collect = sub.add_parser("collect", help="Collect evidence")
    collect_sub = collect.add_subparsers(required=True)
    local = collect_sub.add_parser("local", help="Collect local host metadata")
    local.add_argument("-o", "--output", default="-")
    local.set_defaults(func=cmd_collect_local)
    fixture = collect_sub.add_parser("fixture", help="Copy a fixture evidence file")
    fixture.add_argument("path")
    fixture.add_argument("-o", "--output", default="-")
    fixture.set_defaults(func=cmd_collect_fixture)
    restic = collect_sub.add_parser("restic-snapshots", help="Collect backup evidence from restic snapshots --json")
    restic.add_argument("path")
    restic.add_argument("-o", "--output", default="-")
    restic.set_defaults(func=cmd_collect_restic)
    borg = collect_sub.add_parser("borg-archives", help="Collect backup evidence from borg list --json")
    borg.add_argument("path")
    borg.add_argument("-o", "--output", default="-")
    borg.set_defaults(func=cmd_collect_borg)
    kuma = collect_sub.add_parser("uptime-kuma", help="Collect monitoring evidence from an Uptime Kuma export")
    kuma.add_argument("path")
    kuma.add_argument("-o", "--output", default="-")
    kuma.set_defaults(func=cmd_collect_uptime_kuma)
    prometheus = collect_sub.add_parser("prometheus-targets", help="Collect monitoring evidence from Prometheus /api/v1/targets JSON")
    prometheus.add_argument("path")
    prometheus.add_argument("-o", "--output", default="-")
    prometheus.set_defaults(func=cmd_collect_prometheus)
    apt = collect_sub.add_parser("apt-upgrades", help="Collect patch evidence from apt list --upgradable output")
    apt.add_argument("path")
    apt.add_argument("-o", "--output", default="-")
    apt.set_defaults(func=cmd_collect_apt)
    ufw = collect_sub.add_parser("ufw-status", help="Collect firewall evidence from ufw status output")
    ufw.add_argument("path")
    ufw.add_argument("-o", "--output", default="-")
    ufw.set_defaults(func=cmd_collect_ufw)
    nmap = collect_sub.add_parser("nmap-xml", help="Collect exposure evidence from Nmap XML output")
    nmap.add_argument("path")
    nmap.add_argument("-o", "--output", default="-")
    nmap.set_defaults(func=cmd_collect_nmap)
    trivy = collect_sub.add_parser("trivy-json", help="Collect vulnerability evidence from Trivy JSON output")
    trivy.add_argument("path")
    trivy.add_argument("-o", "--output", default="-")
    trivy.set_defaults(func=cmd_collect_trivy)
    systemd = collect_sub.add_parser("systemd-timers", help="Collect runtime evidence from systemd timer JSON")
    systemd.add_argument("path")
    systemd.add_argument("-o", "--output", default="-")
    systemd.set_defaults(func=cmd_collect_systemd)
    docker = collect_sub.add_parser("docker-containers", help="Collect runtime evidence from Docker JSON or JSON lines")
    docker.add_argument("path")
    docker.add_argument("-o", "--output", default="-")
    docker.set_defaults(func=cmd_collect_docker)
    docs = collect_sub.add_parser("docs", help="Collect documentation inventory evidence from a directory")
    docs.add_argument("directory")
    docs.add_argument("--required", action="append", default=[])
    docs.add_argument("--max-age-days", type=int)
    docs.add_argument("-o", "--output", default="-")
    docs.set_defaults(func=cmd_collect_docs)
    tls = collect_sub.add_parser("tls", help="Collect TLS certificate evidence for a host")
    tls.add_argument("hostname")
    tls.add_argument("--port", type=int, default=443)
    tls.add_argument("--timeout", type=float, default=5.0)
    tls.add_argument("-o", "--output", default="-")
    tls.set_defaults(func=cmd_collect_tls)

    check = sub.add_parser("check", help="Evaluate evidence against a policy")
    check.add_argument("-i", "--input", required=True)
    check.add_argument("-p", "--policy", required=True)
    check.add_argument("-o", "--output", default="-")
    check.set_defaults(func=cmd_check)

    policy = sub.add_parser("policy", help="Inspect bundled policy packs")
    policy_sub = policy.add_subparsers(required=True)
    policy_list = policy_sub.add_parser("list", help="List bundled policy packs")
    policy_list.add_argument("-f", "--format", choices=["table", "json"], default="table")
    policy_list.set_defaults(func=cmd_policy_list)
    policy_operators = policy_sub.add_parser("operators", help="List supported policy operators")
    policy_operators.add_argument("-f", "--format", choices=["table", "json"], default="table")
    policy_operators.set_defaults(func=cmd_policy_operators)
    policy_show = policy_sub.add_parser("show", help="Write a bundled policy pack")
    policy_show.add_argument("name")
    policy_show.add_argument("-o", "--output", default="-")
    policy_show.set_defaults(func=cmd_policy_show)
    policy_validate = policy_sub.add_parser("validate", help="Validate a policy TOML or JSON file")
    policy_validate.add_argument("path")
    policy_validate.set_defaults(func=cmd_policy_validate)
    policy_matrix = policy_sub.add_parser("matrix", help="Render a policy coverage matrix")
    policy_matrix.add_argument("path")
    policy_matrix.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    policy_matrix.add_argument("-o", "--output", default="-")
    policy_matrix.set_defaults(func=cmd_policy_matrix)

    coverage = sub.add_parser("coverage", help="Inspect policy coverage over evidence domains")
    coverage_sub = coverage.add_subparsers(required=True)
    coverage_report = coverage_sub.add_parser("report", help="Compare evidence signal domains with policy checks")
    coverage_report.add_argument("-i", "--input", required=True)
    coverage_report.add_argument("-p", "--policy", required=True)
    coverage_report.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    coverage_report.add_argument("-o", "--output", default="-")
    coverage_report.set_defaults(func=cmd_coverage_report)

    questionnaire = sub.add_parser("questionnaire", help="Create evidence request questionnaires from policies")
    questionnaire_sub = questionnaire.add_subparsers(required=True)
    questionnaire_policy = questionnaire_sub.add_parser("policy", help="Render questions from a policy file")
    questionnaire_policy.add_argument("path")
    questionnaire_policy.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    questionnaire_policy.add_argument("-o", "--output", default="-")
    questionnaire_policy.set_defaults(func=cmd_questionnaire_policy)

    scaffold = sub.add_parser("scaffold", help="Create editable starter artifacts")
    scaffold_sub = scaffold.add_subparsers(required=True)
    scaffold_evidence = scaffold_sub.add_parser("evidence", help="Create evidence JSON placeholders from a policy")
    scaffold_evidence.add_argument("policy")
    scaffold_evidence.add_argument("--organization", default="")
    scaffold_evidence.add_argument("--environment", default="")
    scaffold_evidence.add_argument("--source", default="policy-scaffold")
    scaffold_evidence.add_argument("-o", "--output", default="-")
    scaffold_evidence.set_defaults(func=cmd_scaffold_evidence)

    waiver = sub.add_parser("waiver", help="Inspect risk acceptance waivers")
    waiver_sub = waiver.add_subparsers(required=True)
    waiver_validate = waiver_sub.add_parser("validate", help="Validate a waiver TOML or JSON file")
    waiver_validate.add_argument("path")
    waiver_validate.set_defaults(func=cmd_waiver_validate)

    inventory = sub.add_parser("inventory", help="Create inventory views from evidence")
    inventory_sub = inventory.add_subparsers(required=True)
    inventory_evidence = inventory_sub.add_parser("evidence", help="Render assets and signal domains from evidence JSON")
    inventory_evidence.add_argument("-i", "--input", required=True)
    inventory_evidence.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    inventory_evidence.add_argument("-o", "--output", default="-")
    inventory_evidence.set_defaults(func=cmd_inventory_evidence)

    evidence = sub.add_parser("evidence", help="Inspect and compare evidence files")
    evidence_sub = evidence.add_subparsers(required=True)
    evidence_diff = evidence_sub.add_parser("diff", help="Compare two evidence JSON files for asset and signal drift")
    evidence_diff.add_argument("--base", required=True)
    evidence_diff.add_argument("--current", required=True)
    evidence_diff.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="json")
    evidence_diff.add_argument("--fail-on-drift", action="store_true")
    evidence_diff.add_argument("-o", "--output", default="-")
    evidence_diff.set_defaults(func=cmd_evidence_diff)
    evidence_quality = evidence_sub.add_parser("quality", help="Render evidence hygiene checks")
    evidence_quality.add_argument("-i", "--input", required=True)
    evidence_quality.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    evidence_quality.add_argument("--fail-on-warn", action="store_true")
    evidence_quality.add_argument("-o", "--output", default="-")
    evidence_quality.set_defaults(func=cmd_evidence_quality)
    evidence_completeness = evidence_sub.add_parser("completeness", help="Render policy evidence completeness")
    evidence_completeness.add_argument("-i", "--input", required=True)
    evidence_completeness.add_argument("-p", "--policy", required=True)
    evidence_completeness.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    evidence_completeness.add_argument("--fail-on-missing", action="store_true")
    evidence_completeness.add_argument("-o", "--output", default="-")
    evidence_completeness.set_defaults(func=cmd_evidence_completeness)

    scope = sub.add_parser("scope", help="Check review scope against evidence")
    scope_sub = scope.add_subparsers(required=True)
    scope_validate = scope_sub.add_parser("validate", help="Validate a scope TOML or JSON file")
    scope_validate.add_argument("path")
    scope_validate.set_defaults(func=cmd_scope_validate)
    scope_report = scope_sub.add_parser("report", help="Render scope coverage from evidence and scope")
    scope_report.add_argument("-i", "--input", required=True)
    scope_report.add_argument("-s", "--scope", required=True)
    scope_report.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    scope_report.add_argument("--fail-on-warn", action="store_true")
    scope_report.add_argument("-o", "--output", default="-")
    scope_report.set_defaults(func=cmd_scope_report)

    catalog = sub.add_parser("catalog", help="Check a service catalog against evidence")
    catalog_sub = catalog.add_subparsers(required=True)
    catalog_validate = catalog_sub.add_parser("validate", help="Validate a service catalog TOML or JSON file")
    catalog_validate.add_argument("path")
    catalog_validate.set_defaults(func=cmd_catalog_validate)
    catalog_report = catalog_sub.add_parser("report", help="Render service ownership and evidence coverage")
    catalog_report.add_argument("-i", "--input", required=True)
    catalog_report.add_argument("-c", "--catalog", required=True)
    catalog_report.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    catalog_report.add_argument("--fail-on-warn", action="store_true")
    catalog_report.add_argument("-o", "--output", default="-")
    catalog_report.set_defaults(func=cmd_catalog_report)

    runbook = sub.add_parser("runbook", help="Inspect runbook coverage and freshness")
    runbook_sub = runbook.add_subparsers(required=True)
    runbook_report = runbook_sub.add_parser("report", help="Render runbook freshness and service coverage")
    runbook_report.add_argument("-i", "--input", required=True)
    runbook_report.add_argument("-c", "--catalog")
    runbook_report.add_argument("--max-age-days", type=int)
    runbook_report.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    runbook_report.add_argument("--fail-on-warn", action="store_true")
    runbook_report.add_argument("-o", "--output", default="-")
    runbook_report.set_defaults(func=cmd_runbook_report)

    freshness = sub.add_parser("freshness", help="Inspect timestamp freshness in evidence")
    freshness_sub = freshness.add_subparsers(required=True)
    freshness_report = freshness_sub.add_parser("report", help="Render evidence timestamp freshness")
    freshness_report.add_argument("-i", "--input", required=True)
    freshness_report.add_argument("--max-age-days", type=int, default=30)
    freshness_report.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    freshness_report.add_argument("--fail-on-warn", action="store_true")
    freshness_report.add_argument("-o", "--output", default="-")
    freshness_report.set_defaults(func=cmd_freshness_report)

    restore = sub.add_parser("restore", help="Inspect backup and restore drill assurance")
    restore_sub = restore.add_subparsers(required=True)
    restore_report = restore_sub.add_parser("report", help="Render restore drill and backup recency evidence")
    restore_report.add_argument("-i", "--input", required=True)
    restore_report.add_argument("--max-drill-age-days", type=int, default=90)
    restore_report.add_argument("--max-backup-age-days", type=int, default=2)
    restore_report.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    restore_report.add_argument("--fail-on-warn", action="store_true")
    restore_report.add_argument("-o", "--output", default="-")
    restore_report.set_defaults(func=cmd_restore_report)

    mail = sub.add_parser("mail", help="Inspect mail domain authentication evidence")
    mail_sub = mail.add_subparsers(required=True)
    mail_report = mail_sub.add_parser("report", help="Render SPF, DKIM, and DMARC evidence")
    mail_report.add_argument("-i", "--input", required=True)
    mail_report.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    mail_report.add_argument("--fail-on-warn", action="store_true")
    mail_report.add_argument("-o", "--output", default="-")
    mail_report.set_defaults(func=cmd_mail_report)

    tls_report_root = sub.add_parser("tls", help="Inspect TLS certificate expiry evidence")
    tls_sub = tls_report_root.add_subparsers(required=True)
    tls_report = tls_sub.add_parser("report", help="Render TLS certificate expiry evidence")
    tls_report.add_argument("-i", "--input", required=True)
    tls_report.add_argument("--warn-days", type=int, default=30)
    tls_report.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    tls_report.add_argument("--fail-on-warn", action="store_true")
    tls_report.add_argument("-o", "--output", default="-")
    tls_report.set_defaults(func=cmd_tls_report)

    access = sub.add_parser("access", help="Inspect administrative access exposure evidence")
    access_sub = access.add_subparsers(required=True)
    access_report = access_sub.add_parser("report", help="Render SSH, MFA, and admin entrypoint evidence")
    access_report.add_argument("-i", "--input", required=True)
    access_report.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    access_report.add_argument("--fail-on-warn", action="store_true")
    access_report.add_argument("-o", "--output", default="-")
    access_report.set_defaults(func=cmd_access_report)

    monitoring = sub.add_parser("monitoring", help="Inspect monitoring target and alert evidence")
    monitoring_sub = monitoring.add_subparsers(required=True)
    monitoring_report = monitoring_sub.add_parser("report", help="Render monitoring target and alert evidence")
    monitoring_report.add_argument("-i", "--input", required=True)
    monitoring_report.add_argument("--max-alert-test-age-days", type=int, default=90)
    monitoring_report.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    monitoring_report.add_argument("--fail-on-warn", action="store_true")
    monitoring_report.add_argument("-o", "--output", default="-")
    monitoring_report.set_defaults(func=cmd_monitoring_report)

    exposure = sub.add_parser("exposure", help="Inspect public network exposure evidence")
    exposure_sub = exposure.add_subparsers(required=True)
    exposure_report = exposure_sub.add_parser("report", help="Render open port and risky service exposure evidence")
    exposure_report.add_argument("-i", "--input", required=True)
    exposure_report.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    exposure_report.add_argument("--fail-on-warn", action="store_true")
    exposure_report.add_argument("-o", "--output", default="-")
    exposure_report.set_defaults(func=cmd_exposure_report)

    patch = sub.add_parser("patch", help="Inspect package update and reboot evidence")
    patch_sub = patch.add_subparsers(required=True)
    patch_report = patch_sub.add_parser("report", help="Render package update and reboot evidence")
    patch_report.add_argument("-i", "--input", required=True)
    patch_report.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    patch_report.add_argument("--fail-on-warn", action="store_true")
    patch_report.add_argument("-o", "--output", default="-")
    patch_report.set_defaults(func=cmd_patch_report)

    vulnerability = sub.add_parser("vulnerability", help="Inspect vulnerability scan evidence")
    vulnerability_sub = vulnerability.add_subparsers(required=True)
    vulnerability_report = vulnerability_sub.add_parser("report", help="Render vulnerability scan evidence")
    vulnerability_report.add_argument("-i", "--input", required=True)
    vulnerability_report.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    vulnerability_report.add_argument("--fail-on-warn", action="store_true")
    vulnerability_report.add_argument("-o", "--output", default="-")
    vulnerability_report.set_defaults(func=cmd_vulnerability_report)

    firewall = sub.add_parser("firewall", help="Inspect firewall policy and rule evidence")
    firewall_sub = firewall.add_subparsers(required=True)
    firewall_report = firewall_sub.add_parser("report", help="Render firewall status and rule evidence")
    firewall_report.add_argument("-i", "--input", required=True)
    firewall_report.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    firewall_report.add_argument("--fail-on-warn", action="store_true")
    firewall_report.add_argument("-o", "--output", default="-")
    firewall_report.set_defaults(func=cmd_firewall_report)

    runtime = sub.add_parser("runtime", help="Inspect Docker and systemd runtime evidence")
    runtime_sub = runtime.add_subparsers(required=True)
    runtime_report = runtime_sub.add_parser("report", help="Render runtime container and timer evidence")
    runtime_report.add_argument("-i", "--input", required=True)
    runtime_report.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    runtime_report.add_argument("--fail-on-warn", action="store_true")
    runtime_report.add_argument("-o", "--output", default="-")
    runtime_report.set_defaults(func=cmd_runtime_report)

    service_level = sub.add_parser("service-level", help="Inspect service-level and SLO evidence")
    service_level_sub = service_level.add_subparsers(required=True)
    service_level_report = service_level_sub.add_parser("report", help="Render service-level evidence from monitoring and catalog data")
    service_level_report.add_argument("-i", "--input", required=True)
    service_level_report.add_argument("-c", "--catalog", required=True)
    service_level_report.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    service_level_report.add_argument("--fail-on-warn", action="store_true")
    service_level_report.add_argument("-o", "--output", default="-")
    service_level_report.set_defaults(func=cmd_service_level_report)

    incident = sub.add_parser("incident", help="Inspect incident response readiness evidence")
    incident_sub = incident.add_subparsers(required=True)
    incident_report = incident_sub.add_parser("report", help="Render incident response readiness evidence")
    incident_report.add_argument("-i", "--input", required=True)
    incident_report.add_argument("-c", "--catalog")
    incident_report.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="markdown")
    incident_report.add_argument("--fail-on-warn", action="store_true")
    incident_report.add_argument("-o", "--output", default="-")
    incident_report.set_defaults(func=cmd_incident_report)

    compare = sub.add_parser("compare", help="Compare two report JSON files")
    compare.add_argument("--base", required=True)
    compare.add_argument("--current", required=True)
    compare.add_argument("-f", "--format", choices=["json", "markdown"], default="json")
    compare.add_argument("--fail-on-regression", action="store_true")
    compare.add_argument("-o", "--output", default="-")
    compare.set_defaults(func=cmd_compare)

    history = sub.add_parser("history", help="Track readiness report history over time")
    history_sub = history.add_subparsers(required=True)
    history_append = history_sub.add_parser("append", help="Append a report summary to a history JSON file")
    history_append.add_argument("-i", "--input", required=True)
    history_append.add_argument("--history", help="Existing history JSON; defaults to --output when it already exists")
    history_append.add_argument("--source", default="")
    history_append.add_argument("--note", default="")
    history_append.add_argument("-o", "--output", default="-")
    history_append.set_defaults(func=cmd_history_append)
    history_render = history_sub.add_parser("render", help="Render a report history")
    history_render.add_argument("-i", "--input", required=True)
    history_render.add_argument("-f", "--format", choices=["json", "markdown", "csv", "svg"], default="markdown")
    history_render.add_argument("-o", "--output", default="-")
    history_render.set_defaults(func=cmd_history_render)

    brief = sub.add_parser("brief", help="Create stakeholder-friendly report briefs")
    brief_sub = brief.add_subparsers(required=True)
    brief_report = brief_sub.add_parser("report", help="Create an executive brief from a report JSON file")
    brief_report.add_argument("-i", "--input", required=True)
    brief_report.add_argument("-f", "--format", choices=["json", "markdown"], default="markdown")
    brief_report.add_argument("--max-findings", type=int, default=5)
    brief_report.add_argument("-o", "--output", default="-")
    brief_report.set_defaults(func=cmd_brief_report)

    scorecard = sub.add_parser("scorecard", help="Create domain scorecards from reports")
    scorecard_sub = scorecard.add_subparsers(required=True)
    scorecard_report = scorecard_sub.add_parser("report", help="Group report checks by evidence domain")
    scorecard_report.add_argument("-i", "--input", required=True)
    scorecard_report.add_argument("-f", "--format", choices=["json", "markdown", "csv", "html"], default="markdown")
    scorecard_report.add_argument("-o", "--output", default="-")
    scorecard_report.set_defaults(func=cmd_scorecard_report)

    plan = sub.add_parser("plan", help="Create a prioritized remediation action plan from a report")
    plan.add_argument("-i", "--input", required=True)
    plan.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="json")
    plan.add_argument("--fail-only", action="store_true")
    plan.add_argument("--include-pass", action="store_true")
    plan.add_argument("--waivers", help="TOML or JSON file with accepted risk waivers")
    plan.add_argument("-o", "--output", default="-")
    plan.set_defaults(func=cmd_plan)

    risk = sub.add_parser("risk", help="Create risk registers from reports")
    risk_sub = risk.add_subparsers(required=True)
    risk_register = risk_sub.add_parser("register", help="Render open and accepted risks from a report")
    risk_register.add_argument("-i", "--input", required=True)
    risk_register.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="json")
    risk_register.add_argument("--include-pass", action="store_true")
    risk_register.add_argument("--waivers", help="TOML or JSON file with accepted risk waivers")
    risk_register.add_argument("--fail-on-open", action="store_true")
    risk_register.add_argument("-o", "--output", default="-")
    risk_register.set_defaults(func=cmd_risk_register)

    gate = sub.add_parser("gate", help="Evaluate CI gate conditions against generated artifacts")
    gate_sub = gate.add_subparsers(required=True)
    gate_report = gate_sub.add_parser("report", help="Evaluate thresholds against a report JSON file")
    gate_report.add_argument("-i", "--input", required=True)
    gate_report.add_argument("-f", "--format", choices=["json", "markdown"], default="json")
    gate_report.add_argument("--min-score", type=int)
    gate_report.add_argument("--max-failed", type=int)
    gate_report.add_argument("--max-warnings", type=int)
    gate_report.add_argument("--max-critical", type=int)
    gate_report.add_argument("--max-high", type=int)
    gate_report.add_argument("--ignore-report-status", action="store_true")
    gate_report.add_argument("-o", "--output", default="-")
    gate_report.set_defaults(func=cmd_gate_report)

    review = sub.add_parser("review", help="Create complete readiness review packs")
    review_sub = review.add_subparsers(required=True)
    review_create = review_sub.add_parser("create", help="Create a review folder from evidence and policy")
    review_create.add_argument("-i", "--input", required=True)
    review_create.add_argument("-p", "--policy", required=True)
    review_create.add_argument("-o", "--output-dir", required=True)
    review_create.add_argument("--name", default="openops-review-pack")
    review_create.add_argument("--waivers", help="TOML or JSON file with accepted risk waivers")
    review_create.add_argument("--scope", help="TOML or JSON file declaring in-scope and out-of-scope evidence")
    review_create.add_argument("--catalog", help="TOML or JSON file declaring service ownership and expected evidence")
    review_create.add_argument("--base-evidence", help="Previous evidence JSON file for optional drift reporting")
    review_create.add_argument("--max-findings", type=int, default=5)
    review_create.add_argument("--min-score", type=int)
    review_create.add_argument("--max-failed", type=int)
    review_create.add_argument("--max-warnings", type=int)
    review_create.add_argument("--max-critical", type=int)
    review_create.add_argument("--max-high", type=int)
    review_create.add_argument("--freshness-max-age-days", type=int, default=30)
    review_create.add_argument("--restore-max-drill-age-days", type=int, default=90)
    review_create.add_argument("--restore-max-backup-age-days", type=int, default=2)
    review_create.add_argument("--ignore-report-status", action="store_true")
    review_create.add_argument("--fail-on-gate", action="store_true")
    review_create.add_argument("--fail-on-drift", action="store_true")
    review_create.add_argument("--fail-on-scope-warn", action="store_true")
    review_create.add_argument("--fail-on-catalog-warn", action="store_true")
    review_create.add_argument("--fail-on-runbook-warn", action="store_true")
    review_create.add_argument("--fail-on-freshness-warn", action="store_true")
    review_create.add_argument("--fail-on-restore-warn", action="store_true")
    review_create.add_argument("--fail-on-mail-warn", action="store_true")
    review_create.add_argument("--fail-on-tls-warn", action="store_true")
    review_create.add_argument("--fail-on-access-warn", action="store_true")
    review_create.add_argument("--fail-on-monitoring-warn", action="store_true")
    review_create.add_argument("--fail-on-incident-warn", action="store_true")
    review_create.add_argument("--fail-on-open-risk", action="store_true")
    review_create.add_argument("--archive", help="Optional ZIP archive path for the generated review pack")
    review_create.set_defaults(func=cmd_review_create)

    attest = sub.add_parser("attest", help="Create review sign-off attestations")
    attest_sub = attest.add_subparsers(required=True)
    attest_review = attest_sub.add_parser("review", help="Create a review attestation from a manifest and optional summaries")
    attest_review.add_argument("--manifest", required=True)
    attest_review.add_argument("--approver", required=True)
    attest_review.add_argument("--role", required=True)
    attest_review.add_argument("--statement", required=True)
    attest_review.add_argument("--review-id", default="")
    attest_review.add_argument("--report")
    attest_review.add_argument("--gate")
    attest_review.add_argument("--scope-report")
    attest_review.add_argument("--evidence-drift")
    attest_review.add_argument("--privacy-scan")
    attest_review.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="json")
    attest_review.add_argument("--fail-on-warn", action="store_true")
    attest_review.add_argument("-o", "--output", default="-")
    attest_review.set_defaults(func=cmd_attest_review)

    badge = sub.add_parser("badge", help="Create status badge artifacts")
    badge_sub = badge.add_subparsers(required=True)
    badge_report = badge_sub.add_parser("report", help="Create a Shields-compatible badge JSON from a report")
    badge_report.add_argument("-i", "--input", required=True)
    badge_report.add_argument("--label", default="openops")
    badge_report.add_argument("-o", "--output", default="-")
    badge_report.set_defaults(func=cmd_badge_report)

    ticket = sub.add_parser("ticket", help="Export action plans into ticket-friendly files")
    ticket_sub = ticket.add_subparsers(required=True)
    ticket_export = ticket_sub.add_parser("export", help="Export action plan items as Markdown ticket files")
    ticket_export.add_argument("-i", "--input", required=True)
    ticket_export.add_argument("-o", "--output-dir", required=True)
    ticket_export.add_argument("--include-waived", action="store_true")
    ticket_export.set_defaults(func=cmd_ticket_export)

    merge = sub.add_parser("merge", help="Merge multiple evidence JSON files")
    merge.add_argument("inputs", nargs="+")
    merge.add_argument("-o", "--output", default="-")
    merge.set_defaults(func=cmd_merge)

    bundle = sub.add_parser("bundle", help="Create and inspect evidence bundles")
    bundle_sub = bundle.add_subparsers(required=True)
    manifest = bundle_sub.add_parser("manifest", help="Create a hash manifest for evidence artifacts")
    manifest.add_argument("inputs", nargs="+")
    manifest.add_argument("--name", default="openops-evidence-bundle")
    manifest.add_argument("--base-dir")
    manifest.add_argument("-o", "--output", default="-")
    manifest.set_defaults(func=cmd_bundle_manifest)
    verify = bundle_sub.add_parser("verify", help="Verify artifact hashes from a bundle manifest")
    verify.add_argument("manifest")
    verify.add_argument("--base-dir")
    verify.add_argument("--fail-on-mismatch", action="store_true")
    verify.add_argument("-o", "--output", default="-")
    verify.set_defaults(func=cmd_bundle_verify)
    archive = bundle_sub.add_parser("archive", help="Create a ZIP archive from a verified bundle manifest")
    archive.add_argument("manifest")
    archive.add_argument("--base-dir")
    archive.add_argument("--no-manifest", action="store_true")
    archive.add_argument("-o", "--output", required=True)
    archive.set_defaults(func=cmd_bundle_archive)
    sign = bundle_sub.add_parser("sign", help="Create a detached signature for a bundle manifest")
    sign.add_argument("manifest")
    sign.add_argument("--key-env", default=DEFAULT_SIGNING_KEY_ENV)
    sign.add_argument("--key-file")
    sign.add_argument("--key-id")
    sign.add_argument("-o", "--output", default="-")
    sign.set_defaults(func=cmd_bundle_sign)
    verify_signature = bundle_sub.add_parser("verify-signature", help="Verify a detached bundle manifest signature")
    verify_signature.add_argument("manifest")
    verify_signature.add_argument("signature")
    verify_signature.add_argument("--key-env", default=DEFAULT_SIGNING_KEY_ENV)
    verify_signature.add_argument("--key-file")
    verify_signature.add_argument("--fail-on-invalid", action="store_true")
    verify_signature.add_argument("-o", "--output", default="-")
    verify_signature.set_defaults(func=cmd_bundle_verify_signature)

    validate = sub.add_parser("validate", help="Validate generated JSON artifacts")
    validate.add_argument("-i", "--input", required=True)
    validate.add_argument(
        "-t",
        "--type",
        choices=[
            "evidence",
            "report",
            "action-plan",
            "risk-register",
            "executive-brief",
            "evidence-drift",
            "review-attestation",
            "review-summary",
            "review-checklist",
            "restore-report",
            "mail-report",
            "tls-report",
            "access-report",
            "monitoring-report",
            "exposure-report",
            "firewall-report",
            "patch-report",
            "vulnerability-report",
            "runtime-report",
            "service-level-report",
            "incident-report",
            "gate-result",
            "badge",
            "policy-matrix",
            "policy-coverage",
            "questionnaire",
            "quality-report",
            "inventory",
            "privacy-scan",
            "history",
            "scorecard",
            "scope-report",
            "service-catalog",
            "runbook-report",
            "freshness-report",
            "bundle",
            "bundle-verification",
            "bundle-signature",
            "comparison",
            "completeness-report",
        ],
        default="evidence",
    )
    validate.set_defaults(func=cmd_validate)

    privacy = sub.add_parser("privacy", help="Scan artifacts for likely sensitive data")
    privacy_sub = privacy.add_subparsers(required=True)
    privacy_scan = privacy_sub.add_parser("scan", help="Scan files or directories before sharing")
    privacy_scan.add_argument("paths", nargs="+")
    privacy_scan.add_argument("-f", "--format", choices=["json", "markdown"], default="json")
    privacy_scan.add_argument("--fail-on-findings", action="store_true")
    privacy_scan.add_argument("-o", "--output", default="-")
    privacy_scan.set_defaults(func=cmd_privacy_scan)

    report = sub.add_parser("report", help="Render a check report")
    report.add_argument("-i", "--input", required=True)
    report.add_argument(
        "-f",
        "--format",
        choices=["markdown", "bookstack", "html", "junit", "sarif", "prometheus"],
        default="markdown",
    )
    report.add_argument("-o", "--output", default="-")
    report.set_defaults(func=cmd_report)

    redact = sub.add_parser("redact", help="Redact sensitive values from evidence")
    redact.add_argument("-i", "--input", required=True)
    redact.add_argument("-o", "--output", default="-")
    redact.add_argument("--redact-hostnames", action="store_true")
    redact.set_defaults(func=cmd_redact)

    init = sub.add_parser("init", help="Create starter policy and evidence files")
    init.add_argument("directory", nargs="?", default=".")
    init.add_argument("--policy-pack", default="baseline")
    init.add_argument(
        "--github-actions",
        action="store_true",
        help="Also create a GitHub Actions readiness workflow",
    )
    init.set_defaults(func=cmd_init)
    return parser


def cmd_collect_local(args: argparse.Namespace) -> int:
    write_text(args.output, dump_json(collect_local()))
    return 0


def cmd_collect_fixture(args: argparse.Namespace) -> int:
    write_text(args.output, dump_json(collect_fixture(args.path)))
    return 0


def cmd_collect_restic(args: argparse.Namespace) -> int:
    write_text(args.output, dump_json(collect_restic_snapshots(args.path)))
    return 0


def cmd_collect_borg(args: argparse.Namespace) -> int:
    write_text(args.output, dump_json(collect_borg_archives(args.path)))
    return 0


def cmd_collect_uptime_kuma(args: argparse.Namespace) -> int:
    write_text(args.output, dump_json(collect_uptime_kuma_export(args.path)))
    return 0


def cmd_collect_prometheus(args: argparse.Namespace) -> int:
    write_text(args.output, dump_json(collect_prometheus_targets(args.path)))
    return 0


def cmd_collect_apt(args: argparse.Namespace) -> int:
    write_text(args.output, dump_json(collect_apt_upgrades(args.path)))
    return 0


def cmd_collect_ufw(args: argparse.Namespace) -> int:
    write_text(args.output, dump_json(collect_ufw_status(args.path)))
    return 0


def cmd_collect_trivy(args: argparse.Namespace) -> int:
    write_text(args.output, dump_json(collect_trivy_json(args.path)))
    return 0


def cmd_collect_nmap(args: argparse.Namespace) -> int:
    write_text(args.output, dump_json(collect_nmap_xml(args.path)))
    return 0


def cmd_collect_systemd(args: argparse.Namespace) -> int:
    write_text(args.output, dump_json(collect_systemd_timers(args.path)))
    return 0


def cmd_collect_docker(args: argparse.Namespace) -> int:
    write_text(args.output, dump_json(collect_docker_containers(args.path)))
    return 0


def cmd_collect_docs(args: argparse.Namespace) -> int:
    evidence = collect_docs_directory(args.directory, args.required, args.max_age_days)
    write_text(args.output, dump_json(evidence))
    return 0


def cmd_collect_tls(args: argparse.Namespace) -> int:
    write_text(args.output, dump_json(collect_tls(args.hostname, args.port, args.timeout)))
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    policy_raw = load_structured(args.policy)
    policy_errors = validate_policy_document(policy_raw)
    if policy_errors:
        raise UserFacingError("Policy validation failed:\n- " + "\n- ".join(policy_errors))
    checks = parse_policy(policy_raw)
    report = evaluate_policy(evidence, checks)
    write_text(args.output, dump_json(report))
    return 1 if report["summary"]["status"] == "fail" else 0


def cmd_policy_list(args: argparse.Namespace) -> int:
    write_text("-", render_policy_pack_list(args.format))
    return 0


def cmd_policy_operators(args: argparse.Namespace) -> int:
    write_text("-", render_policy_operator_list(args.format))
    return 0


def cmd_policy_show(args: argparse.Namespace) -> int:
    write_text(args.output, read_policy_pack(args.name))
    return 0


def cmd_policy_validate(args: argparse.Namespace) -> int:
    policy_raw = load_structured(args.path)
    errors = validate_policy_document(policy_raw)
    if errors:
        print("invalid")
        for error in errors:
            print(f"- {error}")
        return 1
    print("valid")
    return 0


def cmd_policy_matrix(args: argparse.Namespace) -> int:
    policy_raw = load_structured(args.path)
    errors = validate_policy_document(policy_raw)
    if errors:
        raise UserFacingError("Policy validation failed:\n- " + "\n- ".join(errors))
    matrix = create_policy_matrix(parse_policy(policy_raw))
    if args.format == "json":
        write_text(args.output, dump_json(matrix))
    elif args.format == "csv":
        write_text(args.output, render_policy_matrix_csv(matrix))
    else:
        write_text(args.output, render_policy_matrix_markdown(matrix))
    return 0


def cmd_coverage_report(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    policy_raw = load_structured(args.policy)
    policy_errors = validate_policy_document(policy_raw)
    if policy_errors:
        raise UserFacingError("Policy validation failed:\n- " + "\n- ".join(policy_errors))
    coverage = create_coverage_report(evidence, parse_policy(policy_raw))
    if args.format == "json":
        rendered = dump_json(coverage)
    elif args.format == "csv":
        rendered = render_coverage_csv(coverage)
    else:
        rendered = render_coverage_markdown(coverage)
    write_text(args.output, rendered)
    return 0


def cmd_questionnaire_policy(args: argparse.Namespace) -> int:
    policy_raw = load_structured(args.path)
    policy_errors = validate_policy_document(policy_raw)
    if policy_errors:
        raise UserFacingError("Policy validation failed:\n- " + "\n- ".join(policy_errors))
    questionnaire = create_policy_questionnaire(parse_policy(policy_raw))
    if args.format == "json":
        rendered = dump_json(questionnaire)
    elif args.format == "csv":
        rendered = render_questionnaire_csv(questionnaire)
    else:
        rendered = render_questionnaire_markdown(questionnaire)
    write_text(args.output, rendered)
    return 0


def cmd_scaffold_evidence(args: argparse.Namespace) -> int:
    policy_raw = load_structured(args.policy)
    policy_errors = validate_policy_document(policy_raw)
    if policy_errors:
        raise UserFacingError("Policy validation failed:\n- " + "\n- ".join(policy_errors))
    evidence = create_evidence_scaffold(
        parse_policy(policy_raw),
        source=args.source,
        organization=args.organization,
        environment=args.environment,
        policy_metadata=policy_raw.get("metadata") if isinstance(policy_raw.get("metadata"), dict) else None,
    )
    write_text(args.output, dump_json(evidence))
    return 0


def cmd_waiver_validate(args: argparse.Namespace) -> int:
    waiver_raw = load_structured(args.path)
    errors = validate_waiver_document(waiver_raw)
    if errors:
        print("invalid")
        for error in errors:
            print(f"- {error}")
        return 1
    print("valid")
    return 0


def cmd_inventory_evidence(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    inventory = create_evidence_inventory(evidence)
    if args.format == "json":
        rendered = dump_json(inventory)
    elif args.format == "csv":
        rendered = render_inventory_csv(inventory)
    else:
        rendered = render_inventory_markdown(inventory)
    write_text(args.output, rendered)
    return 0


def cmd_scope_validate(args: argparse.Namespace) -> int:
    scope_raw = load_structured(args.path)
    errors = validate_scope_document(scope_raw)
    if errors:
        print("invalid")
        for error in errors:
            print(f"- {error}")
        return 1
    print("valid")
    return 0


def cmd_scope_report(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    scope_raw = load_structured(args.scope)
    scope_errors = validate_scope_document(scope_raw)
    if scope_errors:
        raise UserFacingError("Scope validation failed:\n- " + "\n- ".join(scope_errors))
    report = create_scope_report(evidence, scope_raw)
    if args.format == "json":
        rendered = dump_json(report)
    elif args.format == "csv":
        rendered = render_scope_csv(report)
    else:
        rendered = render_scope_markdown(report)
    write_text(args.output, rendered)
    if args.fail_on_warn and report["summary"]["status"] == "warn":
        return 1
    return 0


def cmd_catalog_validate(args: argparse.Namespace) -> int:
    catalog_raw = load_structured(args.path)
    errors = validate_catalog_document(catalog_raw)
    if errors:
        print("invalid")
        for error in errors:
            print(f"- {error}")
        return 1
    print("valid")
    return 0


def cmd_catalog_report(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    catalog_raw = load_structured(args.catalog)
    catalog_errors = validate_catalog_document(catalog_raw)
    if catalog_errors:
        raise UserFacingError("Service catalog validation failed:\n- " + "\n- ".join(catalog_errors))
    report = create_service_catalog_report(evidence, catalog_raw)
    if args.format == "json":
        rendered = dump_json(report)
    elif args.format == "csv":
        rendered = render_service_catalog_csv(report)
    else:
        rendered = render_service_catalog_markdown(report)
    write_text(args.output, rendered)
    if args.fail_on_warn and report["summary"]["status"] == "warn":
        return 1
    return 0


def cmd_runbook_report(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    if args.max_age_days is not None and args.max_age_days < 0:
        raise UserFacingError("--max-age-days must be at least 0")
    catalog_document = None
    if args.catalog:
        catalog_document = load_structured(args.catalog)
        catalog_errors = validate_catalog_document(catalog_document)
        if catalog_errors:
            raise UserFacingError("Service catalog validation failed:\n- " + "\n- ".join(catalog_errors))
    report = create_runbook_report(
        evidence,
        catalog_document=catalog_document,
        max_age_days=args.max_age_days,
    )
    if args.format == "json":
        rendered = dump_json(report)
    elif args.format == "csv":
        rendered = render_runbook_csv(report)
    else:
        rendered = render_runbook_markdown(report)
    write_text(args.output, rendered)
    if args.fail_on_warn and report["summary"]["status"] == "warn":
        return 1
    return 0


def cmd_freshness_report(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    if args.max_age_days is not None and args.max_age_days < 0:
        raise UserFacingError("--max-age-days must be at least 0")
    report = create_freshness_report(evidence, max_age_days=args.max_age_days)
    if args.format == "json":
        rendered = dump_json(report)
    elif args.format == "csv":
        rendered = render_freshness_csv(report)
    else:
        rendered = render_freshness_markdown(report)
    write_text(args.output, rendered)
    if args.fail_on_warn and report["summary"]["status"] == "warn":
        return 1
    return 0


def cmd_restore_report(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    if args.max_drill_age_days is not None and args.max_drill_age_days < 0:
        raise UserFacingError("--max-drill-age-days must be at least 0")
    if args.max_backup_age_days is not None and args.max_backup_age_days < 0:
        raise UserFacingError("--max-backup-age-days must be at least 0")
    report = create_restore_report(
        evidence,
        max_drill_age_days=args.max_drill_age_days,
        max_backup_age_days=args.max_backup_age_days,
    )
    if args.format == "json":
        rendered = dump_json(report)
    elif args.format == "csv":
        rendered = render_restore_csv(report)
    else:
        rendered = render_restore_markdown(report)
    write_text(args.output, rendered)
    if args.fail_on_warn and report["summary"]["status"] != "pass":
        return 1
    return 0


def cmd_mail_report(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    report = create_mail_report(evidence)
    if args.format == "json":
        rendered = dump_json(report)
    elif args.format == "csv":
        rendered = render_mail_csv(report)
    else:
        rendered = render_mail_markdown(report)
    write_text(args.output, rendered)
    if args.fail_on_warn and report["summary"]["status"] != "pass":
        return 1
    return 0


def cmd_tls_report(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    if args.warn_days < 0:
        raise UserFacingError("--warn-days must be at least 0")
    report = create_tls_report(evidence, warn_days=args.warn_days)
    if args.format == "json":
        rendered = dump_json(report)
    elif args.format == "csv":
        rendered = render_tls_csv(report)
    else:
        rendered = render_tls_markdown(report)
    write_text(args.output, rendered)
    if args.fail_on_warn and report["summary"]["status"] != "pass":
        return 1
    return 0


def cmd_access_report(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    report = create_access_report(evidence)
    if args.format == "json":
        rendered = dump_json(report)
    elif args.format == "csv":
        rendered = render_access_csv(report)
    else:
        rendered = render_access_markdown(report)
    write_text(args.output, rendered)
    if args.fail_on_warn and report["summary"]["status"] != "pass":
        return 1
    return 0


def cmd_monitoring_report(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    if args.max_alert_test_age_days < 0:
        raise UserFacingError("--max-alert-test-age-days must be at least 0")
    report = create_monitoring_report(evidence, max_alert_test_age_days=args.max_alert_test_age_days)
    if args.format == "json":
        rendered = dump_json(report)
    elif args.format == "csv":
        rendered = render_monitoring_csv(report)
    else:
        rendered = render_monitoring_markdown(report)
    write_text(args.output, rendered)
    if args.fail_on_warn and report["summary"]["status"] != "pass":
        return 1
    return 0


def cmd_exposure_report(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    report = create_exposure_report(evidence)
    if args.format == "json":
        rendered = dump_json(report)
    elif args.format == "csv":
        rendered = render_exposure_csv(report)
    else:
        rendered = render_exposure_markdown(report)
    write_text(args.output, rendered)
    if args.fail_on_warn and report["summary"]["status"] != "pass":
        return 1
    return 0


def cmd_patch_report(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    report = create_patch_report(evidence)
    if args.format == "json":
        rendered = dump_json(report)
    elif args.format == "csv":
        rendered = render_patch_csv(report)
    else:
        rendered = render_patch_markdown(report)
    write_text(args.output, rendered)
    if args.fail_on_warn and report["summary"]["status"] != "pass":
        return 1
    return 0


def cmd_vulnerability_report(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    report = create_vulnerability_report(evidence)
    if args.format == "json":
        rendered = dump_json(report)
    elif args.format == "csv":
        rendered = render_vulnerability_csv(report)
    else:
        rendered = render_vulnerability_markdown(report)
    write_text(args.output, rendered)
    if args.fail_on_warn and report["summary"]["status"] != "pass":
        return 1
    return 0


def cmd_firewall_report(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    report = create_firewall_report(evidence)
    if args.format == "json":
        rendered = dump_json(report)
    elif args.format == "csv":
        rendered = render_firewall_csv(report)
    else:
        rendered = render_firewall_markdown(report)
    write_text(args.output, rendered)
    if args.fail_on_warn and report["summary"]["status"] != "pass":
        return 1
    return 0


def cmd_runtime_report(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    report = create_runtime_report(evidence)
    if args.format == "json":
        rendered = dump_json(report)
    elif args.format == "csv":
        rendered = render_runtime_csv(report)
    else:
        rendered = render_runtime_markdown(report)
    write_text(args.output, rendered)
    if args.fail_on_warn and report["summary"]["status"] != "pass":
        return 1
    return 0


def cmd_service_level_report(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    catalog_document = load_structured(args.catalog)
    catalog_errors = validate_catalog_document(catalog_document)
    if catalog_errors:
        raise UserFacingError("Service catalog validation failed:\n- " + "\n- ".join(catalog_errors))
    report = create_service_level_report(evidence, catalog_document)
    if args.format == "json":
        rendered = dump_json(report)
    elif args.format == "csv":
        rendered = render_service_level_csv(report)
    else:
        rendered = render_service_level_markdown(report)
    write_text(args.output, rendered)
    if args.fail_on_warn and report["summary"]["status"] != "pass":
        return 1
    return 0


def cmd_incident_report(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    catalog_document = None
    if args.catalog:
        catalog_document = load_structured(args.catalog)
        catalog_errors = validate_catalog_document(catalog_document)
        if catalog_errors:
            raise UserFacingError("Service catalog validation failed:\n- " + "\n- ".join(catalog_errors))
    report = create_incident_report(evidence, catalog_document=catalog_document)
    if args.format == "json":
        rendered = dump_json(report)
    elif args.format == "csv":
        rendered = render_incident_csv(report)
    else:
        rendered = render_incident_markdown(report)
    write_text(args.output, rendered)
    if args.fail_on_warn and report["summary"]["status"] != "pass":
        return 1
    return 0


def cmd_evidence_diff(args: argparse.Namespace) -> int:
    base = load_json(args.base)
    current = load_json(args.current)
    base_errors = validate_evidence(base)
    if base_errors:
        raise UserFacingError("Base evidence validation failed:\n- " + "\n- ".join(base_errors))
    current_errors = validate_evidence(current)
    if current_errors:
        raise UserFacingError("Current evidence validation failed:\n- " + "\n- ".join(current_errors))
    diff = compare_evidence(base, current)
    if args.format == "markdown":
        rendered = render_evidence_diff_markdown(diff)
    elif args.format == "csv":
        rendered = render_evidence_diff_csv(diff)
    else:
        rendered = dump_json(diff)
    write_text(args.output, rendered)
    if args.fail_on_drift and diff["summary"]["status"] == "warn":
        return 1
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    base = load_json(args.base)
    current = load_json(args.current)
    base_errors = validate_report(base)
    current_errors = validate_report(current)
    if base_errors:
        raise UserFacingError(
            "Base report validation failed:\n- " + "\n- ".join(base_errors)
        )
    if current_errors:
        raise UserFacingError(
            "Current report validation failed:\n- " + "\n- ".join(current_errors)
        )
    comparison = compare_reports(base, current)
    if args.format == "markdown":
        write_text(args.output, render_comparison_markdown(comparison))
    else:
        write_text(args.output, dump_json(comparison))
    if args.fail_on_regression and comparison["summary"]["regressions_count"] > 0:
        return 1
    return 0


def cmd_history_append(args: argparse.Namespace) -> int:
    report = load_json(args.input)
    errors = validate_report(report)
    if errors:
        raise UserFacingError("Report validation failed:\n- " + "\n- ".join(errors))
    existing = _load_existing_history(args.history, args.output)
    if existing is not None:
        history_errors = validate_report_history(existing)
        if history_errors:
            raise UserFacingError("Report history validation failed:\n- " + "\n- ".join(history_errors))
    history = append_report_history(existing, report, source=args.source, note=args.note)
    write_text(args.output, dump_json(history))
    return 0


def cmd_history_render(args: argparse.Namespace) -> int:
    history = load_json(args.input)
    errors = validate_report_history(history)
    if errors:
        raise UserFacingError("Report history validation failed:\n- " + "\n- ".join(errors))
    if args.format == "json":
        rendered = dump_json(history)
    elif args.format == "csv":
        rendered = render_history_csv(history)
    elif args.format == "svg":
        rendered = render_history_svg(history)
    else:
        rendered = render_history_markdown(history)
    write_text(args.output, rendered)
    return 0


def cmd_brief_report(args: argparse.Namespace) -> int:
    report = load_json(args.input)
    errors = validate_report(report)
    if errors:
        raise UserFacingError("Report validation failed:\n- " + "\n- ".join(errors))
    if args.max_findings < 0:
        raise UserFacingError("--max-findings must be at least 0")
    brief = create_report_brief(report, max_findings=args.max_findings)
    if args.format == "json":
        rendered = dump_json(brief)
    else:
        rendered = render_brief_markdown(brief)
    write_text(args.output, rendered)
    return 0


def cmd_scorecard_report(args: argparse.Namespace) -> int:
    report = load_json(args.input)
    errors = validate_report(report)
    if errors:
        raise UserFacingError("Report validation failed:\n- " + "\n- ".join(errors))
    scorecard = create_report_scorecard(report)
    if args.format == "json":
        rendered = dump_json(scorecard)
    elif args.format == "csv":
        rendered = render_scorecard_csv(scorecard)
    elif args.format == "html":
        rendered = render_scorecard_html(scorecard)
    else:
        rendered = render_scorecard_markdown(scorecard)
    write_text(args.output, rendered)
    return 0


def _load_existing_history(path: str | None, output: str | None) -> dict[str, Any] | None:
    history_path = Path(path) if path else None
    if history_path is None and output and output != "-":
        candidate = Path(output)
        if candidate.is_file():
            history_path = candidate
    if history_path is None:
        return None
    return load_json(history_path)


def cmd_plan(args: argparse.Namespace) -> int:
    report = load_json(args.input)
    errors = validate_report(report)
    if errors:
        raise UserFacingError("Report validation failed:\n- " + "\n- ".join(errors))
    waiver_document = None
    if args.waivers:
        waiver_document = load_structured(args.waivers)
        waiver_errors = validate_waiver_document(waiver_document)
        if waiver_errors:
            raise UserFacingError("Waiver validation failed:\n- " + "\n- ".join(waiver_errors))
    plan = create_action_plan(
        report,
        fail_only=args.fail_only,
        include_pass=args.include_pass,
        waiver_document=waiver_document,
    )
    if args.format == "markdown":
        write_text(args.output, render_action_plan_markdown(plan))
    elif args.format == "csv":
        write_text(args.output, render_action_plan_csv(plan))
    else:
        write_text(args.output, dump_json(plan))
    return 1 if plan["summary"]["action_required_count"] > 0 else 0


def cmd_risk_register(args: argparse.Namespace) -> int:
    report = load_json(args.input)
    errors = validate_report(report)
    if errors:
        raise UserFacingError("Report validation failed:\n- " + "\n- ".join(errors))
    waiver_document = None
    if args.waivers:
        waiver_document = load_structured(args.waivers)
        waiver_errors = validate_waiver_document(waiver_document)
        if waiver_errors:
            raise UserFacingError("Waiver validation failed:\n- " + "\n- ".join(waiver_errors))
    register = create_risk_register(
        report,
        waiver_document=waiver_document,
        include_pass=args.include_pass,
    )
    if args.format == "markdown":
        write_text(args.output, render_risk_register_markdown(register))
    elif args.format == "csv":
        write_text(args.output, render_risk_register_csv(register))
    else:
        write_text(args.output, dump_json(register))
    if args.fail_on_open and register["summary"]["open_count"] > 0:
        return 1
    return 0


def cmd_evidence_quality(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    report = create_evidence_quality_report(evidence)
    if args.format == "markdown":
        write_text(args.output, render_quality_markdown(report))
    elif args.format == "csv":
        write_text(args.output, render_quality_csv(report))
    else:
        write_text(args.output, dump_json(report))
    if report["summary"]["status"] == "fail":
        return 1
    if args.fail_on_warn and report["summary"]["status"] == "warn":
        return 1
    return 0


def cmd_evidence_completeness(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    policy_raw = load_structured(args.policy)
    policy_errors = validate_policy_document(policy_raw)
    if policy_errors:
        raise UserFacingError("Policy validation failed:\n- " + "\n- ".join(policy_errors))
    report = create_completeness_report(evidence, parse_policy(policy_raw))
    if args.format == "markdown":
        write_text(args.output, render_completeness_markdown(report))
    elif args.format == "csv":
        write_text(args.output, render_completeness_csv(report))
    else:
        write_text(args.output, dump_json(report))
    if args.fail_on_missing and report["summary"]["required_missing"] > 0:
        return 1
    return 0


def cmd_gate_report(args: argparse.Namespace) -> int:
    report = load_json(args.input)
    errors = validate_report(report)
    if errors:
        raise UserFacingError("Report validation failed:\n- " + "\n- ".join(errors))
    _validate_gate_args(args)
    gate = evaluate_report_gate(
        report,
        min_score=args.min_score,
        max_failed=args.max_failed,
        max_warnings=args.max_warnings,
        max_critical=args.max_critical,
        max_high=args.max_high,
        ignore_report_status=args.ignore_report_status,
    )
    if args.format == "markdown":
        write_text(args.output, render_gate_markdown(gate))
    else:
        write_text(args.output, dump_json(gate))
    return 1 if gate["summary"]["status"] == "fail" else 0


def cmd_review_create(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    errors = validate_evidence(evidence)
    if errors:
        raise UserFacingError("Evidence validation failed:\n- " + "\n- ".join(errors))
    policy_raw = load_structured(args.policy)
    policy_errors = validate_policy_document(policy_raw)
    if policy_errors:
        raise UserFacingError("Policy validation failed:\n- " + "\n- ".join(policy_errors))
    waiver_document = None
    if args.waivers:
        waiver_document = load_structured(args.waivers)
        waiver_errors = validate_waiver_document(waiver_document)
        if waiver_errors:
            raise UserFacingError("Waiver validation failed:\n- " + "\n- ".join(waiver_errors))
    scope_document = None
    if args.scope:
        scope_document = load_structured(args.scope)
        scope_errors = validate_scope_document(scope_document)
        if scope_errors:
            raise UserFacingError("Scope validation failed:\n- " + "\n- ".join(scope_errors))
    catalog_document = None
    if args.catalog:
        catalog_document = load_structured(args.catalog)
        catalog_errors = validate_catalog_document(catalog_document)
        if catalog_errors:
            raise UserFacingError("Service catalog validation failed:\n- " + "\n- ".join(catalog_errors))
    base_evidence = None
    if args.base_evidence:
        base_evidence = load_json(args.base_evidence)
        base_errors = validate_evidence(base_evidence)
        if base_errors:
            raise UserFacingError("Base evidence validation failed:\n- " + "\n- ".join(base_errors))
    if args.max_findings < 0:
        raise UserFacingError("--max-findings must be at least 0")
    if args.freshness_max_age_days is not None and args.freshness_max_age_days < 0:
        raise UserFacingError("--freshness-max-age-days must be at least 0")
    if args.restore_max_drill_age_days is not None and args.restore_max_drill_age_days < 0:
        raise UserFacingError("--restore-max-drill-age-days must be at least 0")
    if args.restore_max_backup_age_days is not None and args.restore_max_backup_age_days < 0:
        raise UserFacingError("--restore-max-backup-age-days must be at least 0")
    _validate_gate_args(args)
    pack = create_review_pack(
        evidence,
        policy_raw,
        args.output_dir,
        waiver_document=waiver_document,
        scope_document=scope_document,
        catalog_document=catalog_document,
        base_evidence=base_evidence,
        name=args.name,
        max_findings=args.max_findings,
        min_score=args.min_score,
        max_failed=args.max_failed,
        max_warnings=args.max_warnings,
        max_critical=args.max_critical,
        max_high=args.max_high,
        ignore_report_status=args.ignore_report_status,
        freshness_max_age_days=args.freshness_max_age_days,
        restore_max_drill_age_days=args.restore_max_drill_age_days,
        restore_max_backup_age_days=args.restore_max_backup_age_days,
    )
    print(
        f"created review pack in {pack['output_dir']} "
        f"with {pack['artifact_count']} artifact(s)"
    )
    if args.archive:
        verification = verify_bundle_manifest(pack["manifest"], base_dir=args.output_dir)
        if verification["summary"]["status"] == "fail":
            raise UserFacingError("Review archive refused because manifest verification failed.")
        create_bundle_archive(
            pack["manifest"],
            pack["manifest_path"],
            args.archive,
            base_dir=args.output_dir,
        )
        print(f"created review archive at {args.archive}")
    if args.fail_on_gate and pack["gate"]["summary"]["status"] == "fail":
        return 1
    if (
        args.fail_on_drift
        and pack.get("evidence_drift") is not None
        and pack["evidence_drift"]["summary"]["status"] == "warn"
    ):
        return 1
    if (
        args.fail_on_scope_warn
        and pack.get("scope_report") is not None
        and pack["scope_report"]["summary"]["status"] == "warn"
    ):
        return 1
    if (
        args.fail_on_catalog_warn
        and pack.get("service_catalog") is not None
        and pack["service_catalog"]["summary"]["status"] == "warn"
    ):
        return 1
    if (
        args.fail_on_runbook_warn
        and pack.get("runbook_report") is not None
        and pack["runbook_report"]["summary"]["status"] == "warn"
    ):
        return 1
    if args.fail_on_freshness_warn and pack["freshness_report"]["summary"]["status"] == "warn":
        return 1
    if args.fail_on_restore_warn and pack["restore_report"]["summary"]["status"] != "pass":
        return 1
    if (
        args.fail_on_mail_warn
        and pack.get("mail_report") is not None
        and pack["mail_report"]["summary"]["status"] != "pass"
    ):
        return 1
    if (
        args.fail_on_tls_warn
        and pack.get("tls_report") is not None
        and pack["tls_report"]["summary"]["status"] != "pass"
    ):
        return 1
    if (
        args.fail_on_access_warn
        and pack.get("access_report") is not None
        and pack["access_report"]["summary"]["status"] != "pass"
    ):
        return 1
    if (
        args.fail_on_monitoring_warn
        and pack.get("monitoring_report") is not None
        and pack["monitoring_report"]["summary"]["status"] != "pass"
    ):
        return 1
    if (
        args.fail_on_incident_warn
        and pack.get("incident_report") is not None
        and pack["incident_report"]["summary"]["status"] != "pass"
    ):
        return 1
    if args.fail_on_open_risk and pack["risk_register"]["summary"]["open_count"] > 0:
        return 1
    return 0


def cmd_attest_review(args: argparse.Namespace) -> int:
    manifest = load_json(args.manifest)
    manifest_errors = validate_bundle_manifest(manifest)
    if manifest_errors:
        raise UserFacingError("Bundle manifest validation failed:\n- " + "\n- ".join(manifest_errors))
    report = _optional_validated_json(args.report, validate_report, "Report")
    gate = _optional_validated_json(args.gate, validate_gate_result, "Gate result")
    scope_report = _optional_validated_json(args.scope_report, validate_scope_report, "Scope report")
    evidence_drift = _optional_validated_json(args.evidence_drift, validate_evidence_drift, "Evidence drift")
    privacy_scan = _optional_validated_json(args.privacy_scan, validate_privacy_scan, "Privacy scan")
    attestation = create_review_attestation(
        manifest,
        args.manifest,
        approver=args.approver,
        role=args.role,
        statement=args.statement,
        review_id=args.review_id,
        report=report,
        gate=gate,
        scope_report=scope_report,
        evidence_drift=evidence_drift,
        privacy_scan=privacy_scan,
    )
    if args.format == "markdown":
        rendered = render_attestation_markdown(attestation)
    elif args.format == "csv":
        rendered = render_attestation_csv(attestation)
    else:
        rendered = dump_json(attestation)
    write_text(args.output, rendered)
    if args.fail_on_warn and attestation["summary"]["status"] == "warn":
        return 1
    return 0


def _optional_validated_json(
    path: str | None,
    validator: Any,
    label: str,
) -> dict[str, Any] | None:
    if not path:
        return None
    document = load_json(path)
    errors = validator(document)
    if errors:
        raise UserFacingError(f"{label} validation failed:\n- " + "\n- ".join(errors))
    return document


def cmd_badge_report(args: argparse.Namespace) -> int:
    report = load_json(args.input)
    errors = validate_report(report)
    if errors:
        raise UserFacingError("Report validation failed:\n- " + "\n- ".join(errors))
    badge = create_report_badge(report, label=args.label)
    write_text(args.output, dump_json(badge))
    return 0


def _validate_gate_args(args: argparse.Namespace) -> None:
    if args.min_score is not None and not 0 <= args.min_score <= 100:
        raise UserFacingError("--min-score must be between 0 and 100")
    for name in ("max_failed", "max_warnings", "max_critical", "max_high"):
        value = getattr(args, name)
        if value is not None and value < 0:
            option = name.replace("_", "-")
            raise UserFacingError(f"--{option} must be at least 0")


def cmd_ticket_export(args: argparse.Namespace) -> int:
    plan = load_json(args.input)
    errors = validate_action_plan(plan)
    if errors:
        raise UserFacingError("Action plan validation failed:\n- " + "\n- ".join(errors))
    summary = export_action_plan_tickets(
        plan,
        args.output_dir,
        include_waived=args.include_waived,
    )
    print(f"exported {summary['summary']['ticket_count']} ticket(s) to {args.output_dir}")
    return 0


def cmd_merge(args: argparse.Namespace) -> int:
    documents = []
    for path in args.inputs:
        evidence = load_json(path)
        errors = validate_evidence(evidence)
        if errors:
            raise UserFacingError(f"Evidence validation failed for {path}:\n- " + "\n- ".join(errors))
        documents.append(evidence)
    write_text(args.output, dump_json(merge_evidence(documents)))
    return 0


def cmd_bundle_manifest(args: argparse.Namespace) -> int:
    manifest = create_bundle_manifest(args.inputs, name=args.name, base_dir=args.base_dir)
    write_text(args.output, dump_json(manifest))
    return 0


def cmd_bundle_verify(args: argparse.Namespace) -> int:
    manifest = load_json(args.manifest)
    errors = validate_bundle_manifest(manifest)
    if errors:
        raise UserFacingError("Bundle manifest validation failed:\n- " + "\n- ".join(errors))
    verification = verify_bundle_manifest(manifest, base_dir=args.base_dir)
    write_text(args.output, dump_json(verification))
    if args.fail_on_mismatch and verification["summary"]["status"] == "fail":
        return 1
    return 0


def cmd_bundle_archive(args: argparse.Namespace) -> int:
    manifest = load_json(args.manifest)
    errors = validate_bundle_manifest(manifest)
    if errors:
        raise UserFacingError("Bundle manifest validation failed:\n- " + "\n- ".join(errors))
    verification = verify_bundle_manifest(manifest, base_dir=args.base_dir)
    if verification["summary"]["status"] == "fail":
        raise UserFacingError("Bundle archive refused because manifest verification failed.")
    create_bundle_archive(
        manifest,
        args.manifest,
        args.output,
        base_dir=args.base_dir,
        include_manifest=not args.no_manifest,
    )
    return 0


def cmd_bundle_sign(args: argparse.Namespace) -> int:
    key = load_signing_key(key_file=args.key_file, key_env=args.key_env)
    signature = create_bundle_signature(args.manifest, key, key_id=args.key_id)
    write_text(args.output, dump_json(signature))
    return 0


def cmd_bundle_verify_signature(args: argparse.Namespace) -> int:
    key = load_signing_key(key_file=args.key_file, key_env=args.key_env)
    signature = load_json(args.signature)
    errors = validate_bundle_signature(signature)
    if errors:
        raise UserFacingError("Bundle signature validation failed:\n- " + "\n- ".join(errors))
    verification = verify_bundle_signature(args.manifest, signature, key)
    write_text(args.output, dump_json(verification))
    if args.fail_on_invalid and verification["summary"]["status"] == "fail":
        return 1
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    document = load_json(args.input)
    if args.type == "report":
        errors = validate_report(document)
    elif args.type == "action-plan":
        errors = validate_action_plan(document)
    elif args.type == "risk-register":
        errors = validate_risk_register(document)
    elif args.type == "executive-brief":
        errors = validate_executive_brief(document)
    elif args.type == "evidence-drift":
        errors = validate_evidence_drift(document)
    elif args.type == "review-attestation":
        errors = validate_review_attestation(document)
    elif args.type == "review-summary":
        errors = validate_review_summary(document)
    elif args.type == "review-checklist":
        errors = validate_review_checklist(document)
    elif args.type == "restore-report":
        errors = validate_restore_report(document)
    elif args.type == "mail-report":
        errors = validate_mail_report(document)
    elif args.type == "tls-report":
        errors = validate_tls_report(document)
    elif args.type == "access-report":
        errors = validate_access_report(document)
    elif args.type == "monitoring-report":
        errors = validate_monitoring_report(document)
    elif args.type == "exposure-report":
        errors = validate_exposure_report(document)
    elif args.type == "firewall-report":
        errors = validate_firewall_report(document)
    elif args.type == "patch-report":
        errors = validate_patch_report(document)
    elif args.type == "vulnerability-report":
        errors = validate_vulnerability_report(document)
    elif args.type == "runtime-report":
        errors = validate_runtime_report(document)
    elif args.type == "service-level-report":
        errors = validate_service_level_report(document)
    elif args.type == "incident-report":
        errors = validate_incident_report(document)
    elif args.type == "gate-result":
        errors = validate_gate_result(document)
    elif args.type == "badge":
        errors = validate_badge(document)
    elif args.type == "policy-matrix":
        errors = validate_policy_matrix(document)
    elif args.type == "policy-coverage":
        errors = validate_policy_coverage(document)
    elif args.type == "questionnaire":
        errors = validate_questionnaire(document)
    elif args.type == "quality-report":
        errors = validate_quality_report(document)
    elif args.type == "inventory":
        errors = validate_inventory(document)
    elif args.type == "privacy-scan":
        errors = validate_privacy_scan(document)
    elif args.type == "history":
        errors = validate_report_history(document)
    elif args.type == "scorecard":
        errors = validate_scorecard(document)
    elif args.type == "scope-report":
        errors = validate_scope_report(document)
    elif args.type == "service-catalog":
        errors = validate_service_catalog_report(document)
    elif args.type == "runbook-report":
        errors = validate_runbook_report(document)
    elif args.type == "freshness-report":
        errors = validate_freshness_report(document)
    elif args.type == "bundle":
        errors = validate_bundle_manifest(document)
    elif args.type == "bundle-verification":
        errors = validate_bundle_verification(document)
    elif args.type == "bundle-signature":
        errors = validate_bundle_signature(document)
    elif args.type == "comparison":
        errors = validate_report_comparison(document)
    elif args.type == "completeness-report":
        errors = validate_completeness_report(document)
    else:
        errors = validate_evidence(document)
    if errors:
        print("invalid")
        for error in errors:
            print(f"- {error}")
        return 1
    print("valid")
    return 0


def cmd_privacy_scan(args: argparse.Namespace) -> int:
    scan = scan_privacy(args.paths)
    if args.format == "markdown":
        write_text(args.output, render_privacy_scan_markdown(scan))
    else:
        write_text(args.output, dump_json(scan))
    if args.fail_on_findings and scan["summary"]["findings_count"] > 0:
        return 1
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    report = load_json(args.input)
    errors = validate_report(report)
    if errors:
        raise UserFacingError("Report validation failed:\n- " + "\n- ".join(errors))
    if args.format == "html":
        rendered = render_html(report)
    elif args.format == "junit":
        rendered = render_junit(report)
    elif args.format == "sarif":
        rendered = render_sarif(report)
    elif args.format == "prometheus":
        rendered = render_prometheus(report)
    elif args.format == "bookstack":
        rendered = render_bookstack_markdown(report)
    else:
        rendered = render_markdown(report)
    write_text(args.output, rendered)
    return 0


def cmd_redact(args: argparse.Namespace) -> int:
    evidence = load_json(args.input)
    redacted = redact_document(evidence, redact_hostnames=args.redact_hostnames)
    write_text(args.output, dump_json(redacted))
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.directory)
    target.mkdir(parents=True, exist_ok=True)
    package = "openops_evidence.templates"
    pack = get_policy_pack(args.policy_pack)
    policy = read_policy_pack(args.policy_pack)
    policy_filename = f"policy.{pack['name']}.toml"
    evidence = resources.files(package).joinpath("evidence.sample.json").read_text(encoding="utf-8")
    catalog = resources.files(package).joinpath("service-catalog.sample.toml").read_text(encoding="utf-8")
    (target / policy_filename).write_text(policy, encoding="utf-8")
    (target / "evidence.sample.json").write_text(evidence, encoding="utf-8")
    (target / "service-catalog.sample.toml").write_text(catalog, encoding="utf-8")
    if args.github_actions:
        workflow = (
            resources.files(package)
            .joinpath("github-actions.yml")
            .read_text(encoding="utf-8")
            .replace("__OPENOPS_POLICY_FILE__", policy_filename)
        )
        workflow_path = target / ".github" / "workflows" / "openops-evidence.yml"
        workflow_path.parent.mkdir(parents=True, exist_ok=True)
        workflow_path.write_text(workflow, encoding="utf-8")
    print(f"Created starter files in {target}")
    return 0
