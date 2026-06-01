# OpenOps EvidenceKit

OpenOps EvidenceKit is a vendor-neutral command line toolkit for collecting,
checking, redacting, and reporting infrastructure operations evidence.

It is designed for small infrastructure teams, managed service providers,
platform teams, associations, agencies, and self-hosters who need repeatable
answers to practical readiness questions:

- Are backups configured and recently successful?
- Has a restore drill been proven?
- Are monitoring targets and alert channels present?
- Are administrative entry points protected?
- Are TLS, mail, inventory, and runbook basics documented?
- Can evidence be shared without leaking secrets or customer data?

The project intentionally keeps the core deterministic. AI systems can help
review reports, suggest remediation, or draft runbooks, but the evidence checks
themselves are plain rules that can be audited and run in CI.

Automation exit codes are documented in [docs/exit-codes.md](docs/exit-codes.md).

## Status

This project is in early alpha. The first release focuses on a stable evidence
shape, a small policy engine, redaction, and human-readable reports.

## Quick Start

Run from a checkout:

```powershell
python -m openops_evidence --version
python -m openops_evidence collect fixture examples/evidence.sample.json -o evidence.local.json
python -m openops_evidence validate -i evidence.local.json
python -m openops_evidence check -i evidence.local.json -p examples/policy.baseline.toml -o report.local.json
python -m openops_evidence report -i report.local.json -f markdown -o report.local.md
```

See [docs/demo-workflow.md](docs/demo-workflow.md) for a complete synthetic
end-to-end run.

Render a wiki-friendly report:

```powershell
python -m openops_evidence report -i report.local.json -f bookstack -o readiness.bookstack.md
```

Compare two reports over time:

```powershell
python -m openops_evidence compare --base previous-report.json --current report.local.json -f markdown -o report.comparison.md
```

Create a hash manifest for the files you plan to share:

```powershell
python -m openops_evidence bundle manifest evidence.redacted.json report.local.json readiness.bookstack.md -o evidence-bundle.manifest.json
python -m openops_evidence bundle verify evidence-bundle.manifest.json --base-dir . -o evidence-bundle.verification.json
```

Sign the reviewed bundle manifest before sharing it:

```powershell
python -m openops_evidence bundle sign evidence-bundle.manifest.json --key-file .secrets/openops-bundle-signing.key --key-id ops-2026 -o evidence-bundle.signature.json
python -m openops_evidence bundle verify-signature evidence-bundle.manifest.json evidence-bundle.signature.json --key-file .secrets/openops-bundle-signing.key --fail-on-invalid -o evidence-bundle.signature-verification.json
```

Merge evidence from multiple sources:

```powershell
python -m openops_evidence merge examples/evidence.sample.json examples/evidence.tls.sample.json -o evidence.merged.json
```

Or inspect a TLS endpoint:

```powershell
python -m openops_evidence collect tls example.com -o tls-evidence.json
```

Turn `restic snapshots --json` output into backup evidence:

```powershell
restic snapshots --json > restic.snapshots.json
python -m openops_evidence collect restic-snapshots restic.snapshots.json -o backup.evidence.json
```

Turn `borg list --json` output into backup evidence:

```powershell
borg list --json /path/to/repo > borg.archives.json
python -m openops_evidence collect borg-archives borg.archives.json -o borg.evidence.json
```

Import an Uptime Kuma backup/export file:

```powershell
python -m openops_evidence collect uptime-kuma uptime-kuma-export.json -o monitoring.evidence.json
```

Import Prometheus target health:

```powershell
curl http://prometheus.example.invalid/api/v1/targets > prometheus.targets.json
python -m openops_evidence collect prometheus-targets prometheus.targets.json -o prometheus.evidence.json
```

Import runtime evidence from systemd and Docker exports:

```powershell
systemctl list-timers --all --output=json > systemd.timers.json
python -m openops_evidence collect systemd-timers systemd.timers.json -o systemd.evidence.json

docker ps -a --format '{{json .}}' > docker.containers.jsonl
python -m openops_evidence collect docker-containers docker.containers.jsonl -o docker.evidence.json
```

Collect documentation inventory and runbook evidence:

```powershell
python -m openops_evidence collect docs ./docs --required inventory.md --required runbooks/backup-restore.md --max-age-days 90 -o docs.evidence.json
```

Use redaction before sharing evidence outside your organization:

```powershell
python -m openops_evidence redact -i evidence.local.json --redact-hostnames -o evidence.redacted.json
```

Read [docs/privacy-model.md](docs/privacy-model.md) before publishing or
sharing evidence bundles. Redaction is a safeguard, not a substitute for review.

Create starter files for a new assessment:

```powershell
python -m openops_evidence init ./my-readiness-check
```

List and export bundled policy packs:

```powershell
python -m openops_evidence policy list
python -m openops_evidence policy operators
python -m openops_evidence policy show security-minimum -o policy.security-minimum.toml
python -m openops_evidence policy show security-minimum@0.1 -o policy.security-minimum.toml
python -m openops_evidence policy validate policy.security-minimum.toml
```

## Core Concepts

EvidenceKit uses three files:

- Evidence JSON: observed facts from infrastructure and documentation.
- Policy TOML: readiness rules that say what "good enough" means.
- Report JSON/Markdown/HTML: evaluated results with findings and remediation.

Use `merge` when evidence comes from multiple collectors or manually reviewed
sources.

JSON Schemas for generated artifacts live in [schemas/](schemas/).
Example inputs and generated artifact shapes are described in
[examples/README.md](examples/README.md).
Bundled policies are described in [docs/policy-packs.md](docs/policy-packs.md).
Bundle manifests are described in [docs/bundle-manifest.md](docs/bundle-manifest.md).
Report comparisons are described in [docs/report-comparison.md](docs/report-comparison.md).

Policy checks are intentionally small:

```toml
[[checks]]
id = "backup_recent"
title = "Recent successful backup exists"
path = "signals.backup.last_success_at"
operator = "within_days"
value = 2
severity = "critical"
required = true
remediation = "Configure backups and record the last successful backup timestamp."
```

## What It Is Not

OpenOps EvidenceKit is not a compliance certification and does not provide legal
or regulatory advice. It helps teams produce clearer operational evidence and
find obvious gaps before they become incidents.

## Roadmap

See [docs/roadmap.md](docs/roadmap.md).

Maintainers should use [docs/release-process.md](docs/release-process.md) for
release checks and [GOVERNANCE.md](GOVERNANCE.md) for maintainer policy.

A short wiki seed for GitHub Wiki or BookStack lives in [docs/wiki/](docs/wiki/).

## License

Apache-2.0. See [LICENSE](LICENSE).
