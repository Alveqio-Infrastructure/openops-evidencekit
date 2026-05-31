# Roadmap

OpenOps EvidenceKit is built in layers so small teams can adopt it without
having to deploy a platform first.

## 0.1 Alpha

- Evidence JSON envelope.
- TOML policy checks.
- Local, fixture, and TLS collectors.
- Merge, validate, redact, check, and report commands.
- Markdown, BookStack Markdown, and HTML report output.

## 0.2 Collector Pack

- restic backup evidence.
- Prometheus target evidence.
- Uptime Kuma monitor evidence.
- Borg backup evidence.
- systemd timer evidence.
- Docker container evidence.
- Collector-specific fixture coverage.

## 0.3 Documentation Pack

- BookStack-oriented Markdown export.
- Runbook freshness checks.
- Inventory completeness checks.
- Evidence bundle manifest.
- Bundle manifest validation.
- Local documentation directory collector.
- Wiki seed pages for public project documentation.

## 0.4 Assurance Pack

- Signed evidence bundles.
- JSON Schema distribution.
- Policy pack versioning.
- CI-ready machine output with stable exit codes.

## 1.0

- Stable evidence schema.
- Stable policy operator semantics.
- Backward-compatible report schema.
- Documented maintainer policy for security and governance.
