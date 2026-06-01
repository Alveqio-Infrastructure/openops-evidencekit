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
- Privacy scan for reviewed sharing artifacts.
- Bundle manifest validation.
- Local documentation directory collector.
- Evidence inventory export for assets and signal domains.
- Wiki seed pages for public project documentation.

## 0.4 Assurance Pack

- Signed evidence bundle manifests.
- JSON Schema distribution.
- Policy pack versioning.
- CI-ready machine output with stable exit codes.
- JUnit report export for CI test-result publishing.
- SARIF report export for review tooling.
- Shields-compatible readiness badge export.
- Prometheus text export for monitoring pipelines.
- GitHub Actions starter workflow generation.
- Report gates for score and finding thresholds.
- Report comparison and regression guardrails.
- Report history timeline for recurring readiness reviews.
- SVG trend rendering for readiness history dashboards.
- Executive brief export for stakeholder handoff.
- Scope report export for explicit in-scope and out-of-scope boundaries.
- Review-pack generation for complete readiness handoff folders.
- Domain scorecard export for operational area summaries.
- Action plan ticket export.
- CLI version and exit-code documentation.
- Bundled policy pack discovery and export.
- Policy coverage matrix export.
- Policy coverage gap reports for evidence-domain review.
- Policy questionnaire export for pre-assessment evidence requests.
- Evidence scaffold generation from policy signal paths.
- Bundle manifest verification.
- Policy validation and authoring guardrails.

## 1.0

- Stable evidence schema.
- Stable policy operator semantics.
- Backward-compatible report schema.
- Documented maintainer policy for security and governance.
