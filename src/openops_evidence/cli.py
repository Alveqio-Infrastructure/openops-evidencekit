from __future__ import annotations

import argparse
import sys
from importlib import resources
from pathlib import Path

from .bundle import create_bundle_manifest
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
from .policy import evaluate_policy, parse_policy
from .redact import redact_document
from .reports import render_bookstack_markdown, render_html, render_markdown
from .schema import validate_bundle_manifest, validate_evidence, validate_report


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
        description="Collect, check, redact, and report infrastructure operations evidence.",
    )
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

    validate = sub.add_parser("validate", help="Validate evidence, report, or bundle JSON")
    validate.add_argument("-i", "--input", required=True)
    validate.add_argument("-t", "--type", choices=["evidence", "report", "bundle"], default="evidence")
    validate.set_defaults(func=cmd_validate)

    report = sub.add_parser("report", help="Render a check report")
    report.add_argument("-i", "--input", required=True)
    report.add_argument("-f", "--format", choices=["markdown", "bookstack", "html"], default="markdown")
    report.add_argument("-o", "--output", default="-")
    report.set_defaults(func=cmd_report)

    redact = sub.add_parser("redact", help="Redact sensitive values from evidence")
    redact.add_argument("-i", "--input", required=True)
    redact.add_argument("-o", "--output", default="-")
    redact.add_argument("--redact-hostnames", action="store_true")
    redact.set_defaults(func=cmd_redact)

    init = sub.add_parser("init", help="Create starter policy and evidence files")
    init.add_argument("directory", nargs="?", default=".")
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
    checks = parse_policy(policy_raw)
    report = evaluate_policy(evidence, checks)
    write_text(args.output, dump_json(report))
    return 1 if report["summary"]["status"] == "fail" else 0


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


def cmd_validate(args: argparse.Namespace) -> int:
    document = load_json(args.input)
    if args.type == "report":
        errors = validate_report(document)
    elif args.type == "bundle":
        errors = validate_bundle_manifest(document)
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
    policy = resources.files(package).joinpath("policy.baseline.toml").read_text(encoding="utf-8")
    evidence = resources.files(package).joinpath("evidence.sample.json").read_text(encoding="utf-8")
    (target / "policy.baseline.toml").write_text(policy, encoding="utf-8")
    (target / "evidence.sample.json").write_text(evidence, encoding="utf-8")
    print(f"Created starter files in {target}")
    return 0
