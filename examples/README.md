# Examples

This directory contains synthetic data only. The files are safe to use in tests,
documentation, demos, and issue reproduction.

## Evidence Samples

- `evidence.sample.json` shows a small but complete readiness evidence file.
- `evidence.tls.sample.json` adds TLS certificate evidence for merge examples.

## Policy Samples

- `policy.baseline.toml` checks practical minimum readiness signals such as
  backups, monitoring, TLS, runbooks, and inventory.
- `policy.security-minimum.toml` focuses on externally visible hygiene and
  administrative access signals.
- `policy.documentation.toml` checks the documentation collector output for
  required and stale files.

The same policies are also bundled as package policy packs. Use
`openops-evidence policy list` and `openops-evidence policy show <name>` after
installation.

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
policy matrices, reports, comparisons, action plans, ticket drafts, and bundle
manifests. Generated files are ignored by git so they can be reviewed without
polluting commits.
