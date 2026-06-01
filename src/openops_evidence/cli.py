from __future__ import annotations

import argparse
import sys
from importlib import resources
from pathlib import Path

from . import __version__
from .actions import create_action_plan, render_action_plan_csv, render_action_plan_markdown
from .bundle import (
    DEFAULT_SIGNING_KEY_ENV,
    create_bundle_manifest,
    create_bundle_archive,
    create_bundle_signature,
    load_signing_key,
    verify_bundle_manifest,
    verify_bundle_signature,
)
from .compare import compare_reports, render_comparison_markdown
from .collectors import (
    collect_borg_archives,
    collect_docker_containers,
    collect_docs_directory,
    collect_fixture,
    collect_local,
    collect_prometheus_targets,
    collect_restic_snapshots,
    collect_systemd_timers,
    collect_tls,
    collect_uptime_kuma_export,
)
from .io import UserFacingError, dump_json, load_json, load_structured, write_text
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
from .redact import redact_document
from .reports import render_bookstack_markdown, render_html, render_junit, render_markdown
from .schema import (
    validate_action_plan,
    validate_bundle_manifest,
    validate_bundle_signature,
    validate_bundle_verification,
    validate_evidence,
    validate_policy_matrix,
    validate_report,
    validate_report_comparison,
)
from .tickets import export_action_plan_tickets
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

    waiver = sub.add_parser("waiver", help="Inspect risk acceptance waivers")
    waiver_sub = waiver.add_subparsers(required=True)
    waiver_validate = waiver_sub.add_parser("validate", help="Validate a waiver TOML or JSON file")
    waiver_validate.add_argument("path")
    waiver_validate.set_defaults(func=cmd_waiver_validate)

    compare = sub.add_parser("compare", help="Compare two report JSON files")
    compare.add_argument("--base", required=True)
    compare.add_argument("--current", required=True)
    compare.add_argument("-f", "--format", choices=["json", "markdown"], default="json")
    compare.add_argument("--fail-on-regression", action="store_true")
    compare.add_argument("-o", "--output", default="-")
    compare.set_defaults(func=cmd_compare)

    plan = sub.add_parser("plan", help="Create a prioritized remediation action plan from a report")
    plan.add_argument("-i", "--input", required=True)
    plan.add_argument("-f", "--format", choices=["json", "markdown", "csv"], default="json")
    plan.add_argument("--fail-only", action="store_true")
    plan.add_argument("--include-pass", action="store_true")
    plan.add_argument("--waivers", help="TOML or JSON file with accepted risk waivers")
    plan.add_argument("-o", "--output", default="-")
    plan.set_defaults(func=cmd_plan)

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
            "policy-matrix",
            "bundle",
            "bundle-verification",
            "bundle-signature",
            "comparison",
        ],
        default="evidence",
    )
    validate.set_defaults(func=cmd_validate)

    report = sub.add_parser("report", help="Render a check report")
    report.add_argument("-i", "--input", required=True)
    report.add_argument("-f", "--format", choices=["markdown", "bookstack", "html", "junit"], default="markdown")
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
    elif args.type == "policy-matrix":
        errors = validate_policy_matrix(document)
    elif args.type == "bundle":
        errors = validate_bundle_manifest(document)
    elif args.type == "bundle-verification":
        errors = validate_bundle_verification(document)
    elif args.type == "bundle-signature":
        errors = validate_bundle_signature(document)
    elif args.type == "comparison":
        errors = validate_report_comparison(document)
    else:
        errors = validate_evidence(document)
    if errors:
        print("invalid")
        for error in errors:
            print(f"- {error}")
        return 1
    print("valid")
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
    evidence = resources.files(package).joinpath("evidence.sample.json").read_text(encoding="utf-8")
    (target / f"policy.{pack['name']}.toml").write_text(policy, encoding="utf-8")
    (target / "evidence.sample.json").write_text(evidence, encoding="utf-8")
    print(f"Created starter files in {target}")
    return 0
