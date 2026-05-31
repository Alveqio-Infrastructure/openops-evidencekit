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

## Status

This project is in early alpha. The first release focuses on a stable evidence
shape, a small policy engine, redaction, and human-readable reports.

## Quick Start

Run from a checkout:

```powershell
python -m openops_evidence collect fixture examples/evidence.sample.json -o evidence.local.json
python -m openops_evidence validate -i evidence.local.json
python -m openops_evidence check -i evidence.local.json -p examples/policy.baseline.toml -o report.local.json
python -m openops_evidence report -i report.local.json -f markdown -o report.local.md
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

Use redaction before sharing evidence outside your organization:

```powershell
python -m openops_evidence redact -i evidence.local.json --redact-hostnames -o evidence.redacted.json
```

Create starter files for a new assessment:

```powershell
python -m openops_evidence init ./my-readiness-check
```

## Core Concepts

EvidenceKit uses three files:

- Evidence JSON: observed facts from infrastructure and documentation.
- Policy TOML: readiness rules that say what "good enough" means.
- Report JSON/Markdown/HTML: evaluated results with findings and remediation.

Use `merge` when evidence comes from multiple collectors or manually reviewed
sources.

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

## License

Apache-2.0. See [LICENSE](LICENSE).
