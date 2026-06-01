# Examples

This directory contains synthetic data only. The files are safe to use in tests,
documentation, demos, and issue reproduction.

## Evidence Samples

- `evidence.sample.json` shows a small but complete readiness evidence file.
- `evidence.previous.json` provides an older synthetic snapshot for evidence
  drift examples.
- `evidence.tls.sample.json` adds TLS certificate evidence for merge examples.

## Policy Samples

- `policy.baseline.toml` checks practical minimum readiness signals such as
  backups, monitoring, TLS, runbooks, and inventory.
- `policy.security-minimum.toml` focuses on externally visible hygiene and
  administrative access signals.
- `policy.documentation.toml` checks the documentation collector output for
  required and stale files.
- `scope.sample.toml` declares a sample readiness review scope for assets and
  evidence domains.
- `service-catalog.sample.toml` declares synthetic services, owners,
  criticality, assets, evidence domains, runbooks, and contacts.

The same policies are also bundled as package policy packs. Use
`openops-evidence policy list` and `openops-evidence policy show <name>` after
installation.

`openops-evidence init --github-actions` can create a starter repository layout
with these sample shapes and a CI workflow for recurring checks.
`openops-evidence scaffold evidence examples/policy.baseline.toml` can create a
schema-valid Evidence JSON starter from policy paths before real collector data
is available.

## Waiver Samples

- `waivers.sample.toml` shows the accepted-risk file shape used by action plans
  for temporary, owner-approved exceptions.

## Collector Input Samples

- `restic.snapshots.sample.json` mirrors the shape of `restic snapshots --json`.
- `borg.archives.sample.json` mirrors the archive list in `borg list --json`.
- `uptime-kuma.export.sample.json` contains a trimmed Uptime Kuma export shape.
- `prometheus.targets.sample.json` contains a trimmed Prometheus
  `/api/v1/targets` response.
- `systemd.timers.sample.json` contains a trimmed `systemctl list-timers`
  JSON export.
- `docker.containers.sample.jsonl` contains JSON lines produced by
  `docker ps --format '{{json .}}'`.
- `docs-sample/` contains a tiny synthetic inventory and backup restore runbook.

## Regenerating Demo Output

Use the workflow in `docs/demo-workflow.md` to regenerate local evidence,
policy matrices, policy coverage reports, questionnaires, inventories, reports,
evidence scaffolds, scope reports, service catalog reports, runbook coverage
reports, evidence freshness reports, executive briefs, scorecards, history timelines, evidence drift
reports, comparisons, action plans, ticket drafts, review packs, review
attestations, and bundle manifests.
Reports can also be rendered as JUnit XML for CI systems. Generated files are
ignored by git so they can be reviewed without polluting commits.
SARIF output is available for review tools that understand static-analysis
result uploads. Badge JSON is available for README, portal, or dashboard status
widgets that understand Shields-compatible endpoint output. Prometheus text
output is available for monitoring pipelines that ingest textfile metrics.
Run `privacy scan` on generated sharing artifacts before attaching them to
issues, tickets, or public discussions.
Use `gate report` when CI should enforce score, warning, or severity thresholds
that are stricter than the policy's required-failure status alone.
