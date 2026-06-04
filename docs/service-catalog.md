# Service Catalog Reports

Service catalog reports compare collected evidence with a declared service
catalog. They show whether customer-facing or business-critical services have
owners, expected assets, evidence domains, and runbooks represented in the
current evidence snapshot.

```powershell
python -m openops_evidence catalog validate examples/service-catalog.sample.toml
python -m openops_evidence catalog report -i evidence.local.json -c examples/service-catalog.sample.toml -o service-catalog.md
python -m openops_evidence catalog report -i evidence.local.json -c examples/service-catalog.sample.toml -f json -o service-catalog.json
python -m openops_evidence validate -i service-catalog.json -t service-catalog
python -m openops_evidence catalog report -i evidence.local.json -c examples/service-catalog.sample.toml -f csv -o service-catalog.csv
```

Use `--fail-on-warn` when CI should fail if any cataloged service has missing
assets, evidence domains, runbooks, or if collected evidence assets are not
assigned to any service:

```powershell
python -m openops_evidence catalog report -i evidence.local.json -c examples/service-catalog.sample.toml --fail-on-warn -o service-catalog.md
```

## Catalog Shape

Catalog files can be TOML or JSON. TOML is convenient for hand-maintained
service lists:

```toml
[metadata]
name = "Production service catalog"
owner = "Operations"

[[services]]
id = "public-web"
name = "Public website"
owner = "platform"
criticality = "high"
slo_target_percent = 99.5
assets = ["web-01"]
domains = ["backup", "monitoring", "tls", "docs"]
runbooks = ["backup-restore", "incident-escalation"]
contacts = ["platform@example.invalid"]
```

Each service needs:

- `id`, `name`, and `owner`
- optional `criticality`: `critical`, `high`, `medium`, or `low`
- optional `slo_target_percent` for service-level reports
- at least one of `assets`, `domains`, or `runbooks`
- optional `contacts`

## Status Logic

A service is `pass` when every declared asset, evidence domain, and runbook is
present. It becomes `warn` when at least one expected item is missing.

The overall report is `warn` when any service warns or when collected evidence
contains assets that no catalog service references.

This report is operational evidence. Review the source catalog and evidence
before using the output for customer handoff or audit material.
