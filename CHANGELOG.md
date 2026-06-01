# Changelog

## 0.1.0 - Unreleased

- Add initial CLI for collect, check, report, redact, and init workflows.
- Add baseline readiness policy and synthetic evidence fixture.
- Add deterministic policy engine with path queries and date checks.
- Add Markdown and HTML report renderers.
- Add redaction for common secret keys, email addresses, and IPv4 addresses.
- Add draft JSON Schemas for evidence and report artifacts.
- Add BookStack-oriented Markdown report output.
- Add restic and Borg backup collectors.
- Add Uptime Kuma export collector.
- Add Prometheus target health collector.
- Add systemd timer and Docker container runtime collectors.
- Add local documentation directory collector and documentation policy fixture.
- Add evidence bundle manifest generation and validation.
- Add report comparison output and regression guardrail.
- Add documented automation exit codes and CLI version output.
- Add bundled policy pack listing, export, and init support.
- Add bundle manifest verification for artifact integrity checks.
- Add policy validation for custom policy authoring.
- Add wiki seed pages for public project documentation.
- Add end-to-end CLI workflow test and demo documentation.
- Add detached HMAC-SHA256 signatures for evidence bundle manifests.
- Add explicit `name@version` references for bundled policy packs.
- Add schema-version compatibility checks for generated artifact validators.
- Add a CLI-visible policy operator catalog with stable semantics.
- Enforce the published report summary and result contract in built-in validation.
- Add governance and maintainer policy documentation.
- Cover policy operators and bundle signatures in CI sample workflow checks.
