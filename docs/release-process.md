# Release Process

This project is in early alpha. Releases should stay small, reviewable, and
easy to verify from source.

## Versioning

Use semantic versioning once the first public package is published:

- patch versions for bug fixes and documentation-only corrections
- minor versions for new collectors, policy operators, and report formats
- major versions for incompatible evidence, policy, or report schema changes

Before 1.0, schema changes are allowed, but they must be documented in the
changelog and examples must be updated in the same change.

Artifact validators accept the current `0.1` schema family, including
patch-compatible versions such as `0.1.1`. Incompatible envelope, field type, or
semantic changes require a new major/minor schema version and a migration note.

## Pre-Release Checks

Run these commands from the repository root:

```powershell
$env:PYTHONPATH = "src"
python -m openops_evidence --version
python -m unittest discover -s tests
python -m openops_evidence policy list
python -m openops_evidence policy operators
python -m openops_evidence policy show baseline -o policy.exported.toml
python -m openops_evidence policy validate policy.exported.toml
python -m openops_evidence policy matrix policy.exported.toml -f markdown -o policy.matrix.md
python -m openops_evidence policy matrix policy.exported.toml -f json -o policy.matrix.json
python -m openops_evidence validate -i policy.matrix.json -t policy-matrix
python -m openops_evidence questionnaire policy policy.exported.toml -f json -o questionnaire.json
python -m openops_evidence validate -i questionnaire.json -t questionnaire
python -m openops_evidence questionnaire policy policy.exported.toml -o questionnaire.md
python -m openops_evidence scaffold evidence policy.exported.toml --organization "Example Operations Team" --environment production -o evidence.scaffold.json
python -m openops_evidence validate -i evidence.scaffold.json
python -m openops_evidence init init-demo --github-actions
python -m openops_evidence validate -i examples/evidence.sample.json
python -m openops_evidence collect docs examples/docs-sample --required inventory.md --required runbooks/backup-restore.md --max-age-days 365 -o docs.evidence.json
python -m openops_evidence check -i docs.evidence.json -p examples/policy.documentation.toml -o report.docs.json
python -m openops_evidence inventory evidence -i examples/evidence.sample.json -f json -o inventory.json
python -m openops_evidence validate -i inventory.json -t inventory
python -m openops_evidence inventory evidence -i examples/evidence.sample.json -f markdown -o inventory.md
python -m openops_evidence scope validate examples/scope.sample.toml
python -m openops_evidence scope report -i examples/evidence.sample.json -s examples/scope.sample.toml -f json -o scope-report.json
python -m openops_evidence validate -i scope-report.json -t scope-report
python -m openops_evidence scope report -i examples/evidence.sample.json -s examples/scope.sample.toml -o scope-report.md
python -m openops_evidence catalog validate examples/service-catalog.sample.toml
python -m openops_evidence catalog report -i examples/evidence.sample.json -c examples/service-catalog.sample.toml -f json -o service-catalog.json
python -m openops_evidence validate -i service-catalog.json -t service-catalog
python -m openops_evidence catalog report -i examples/evidence.sample.json -c examples/service-catalog.sample.toml -o service-catalog.md
python -m openops_evidence evidence diff --base examples/evidence.previous.json --current examples/evidence.sample.json -f json -o evidence-drift.json
python -m openops_evidence validate -i evidence-drift.json -t evidence-drift
python -m openops_evidence evidence diff --base examples/evidence.previous.json --current examples/evidence.sample.json -f markdown -o evidence-drift.md
python -m openops_evidence coverage report -i examples/evidence.sample.json -p examples/policy.baseline.toml -f json -o policy-coverage.json
python -m openops_evidence validate -i policy-coverage.json -t policy-coverage
python -m openops_evidence coverage report -i examples/evidence.sample.json -p examples/policy.baseline.toml -o policy-coverage.md
python -m openops_evidence check -i examples/evidence.sample.json -p examples/policy.baseline.toml -o report.local.json
python -m openops_evidence gate report -i report.local.json --min-score 100 --max-warnings 0 -o gate-result.json
python -m openops_evidence validate -i gate-result.json -t gate-result
python -m openops_evidence badge report -i report.local.json -o readiness-badge.json
python -m openops_evidence validate -i readiness-badge.json -t badge
python -m openops_evidence brief report -i report.local.json -f json -o executive-brief.json
python -m openops_evidence validate -i executive-brief.json -t executive-brief
python -m openops_evidence brief report -i report.local.json -o executive-brief.md
python -m openops_evidence scorecard report -i report.local.json -f json -o scorecard.json
python -m openops_evidence validate -i scorecard.json -t scorecard
python -m openops_evidence scorecard report -i report.local.json -o scorecard.md
python -m openops_evidence scorecard report -i report.local.json -f html -o scorecard.html
python -m openops_evidence history append -i report.local.json --source release-check -o readiness-history.json
python -m openops_evidence validate -i readiness-history.json -t history
python -m openops_evidence history render -i readiness-history.json -f markdown -o readiness-history.md
python -m openops_evidence history render -i readiness-history.json -f svg -o readiness-history.svg
python -m openops_evidence compare --base report.local.json --current report.local.json -o report.comparison.json
python -m openops_evidence validate -i report.comparison.json -t comparison
python -m openops_evidence plan -i report.local.json -o action-plan.json
python -m openops_evidence validate -i action-plan.json -t action-plan
python -m openops_evidence waiver validate examples/waivers.sample.toml
python -m openops_evidence plan -i report.local.json --waivers examples/waivers.sample.toml -o action-plan.waived.json
python -m openops_evidence validate -i action-plan.waived.json -t action-plan
python -m openops_evidence ticket export -i action-plan.json -o action-tickets
python -m openops_evidence report -i report.local.json -f markdown -o report.local.md
python -m openops_evidence report -i report.local.json -f junit -o report.local.junit.xml
python -m openops_evidence report -i report.local.json -f sarif -o report.local.sarif.json
python -m openops_evidence report -i report.local.json -f prometheus -o report.local.prom
python -m openops_evidence redact -i examples/evidence.sample.json --redact-hostnames -o evidence.redacted.json
python -m openops_evidence privacy scan evidence.redacted.json report.local.md -o privacy-scan.json
python -m openops_evidence validate -i privacy-scan.json -t privacy-scan
python -m openops_evidence review create -i evidence.redacted.json -p examples/policy.baseline.toml --scope examples/scope.sample.toml --catalog examples/service-catalog.sample.toml --base-evidence examples/evidence.previous.json -o review-pack --archive review-pack.zip --min-score 100 --max-warnings 0
python -m openops_evidence validate -i review-pack/manifest.json -t bundle
python -m openops_evidence bundle manifest evidence.scaffold.json evidence.redacted.json evidence-drift.json questionnaire.json inventory.json scope-report.json service-catalog.json policy-coverage.json report.local.json gate-result.json readiness-badge.json executive-brief.json scorecard.json readiness-history.json readiness-history.svg report.docs.json report.comparison.json report.local.md report.local.sarif.json report.local.prom -o evidence-bundle.manifest.json
python -m openops_evidence validate -i evidence-bundle.manifest.json -t bundle
python -m openops_evidence bundle verify evidence-bundle.manifest.json --base-dir . -o evidence-bundle.verification.json
python -m openops_evidence validate -i evidence-bundle.verification.json -t bundle-verification
python -m openops_evidence bundle archive evidence-bundle.manifest.json --base-dir . -o evidence-bundle.zip
python -m openops_evidence attest review --manifest evidence-bundle.manifest.json --report report.local.json --gate gate-result.json --scope-report scope-report.json --evidence-drift evidence-drift.json --privacy-scan privacy-scan.json --approver "Example Reviewer" --role "Operations" --statement "Reviewed generated artifacts for release checks." -o review-attestation.json
python -m openops_evidence validate -i review-attestation.json -t review-attestation
python -m openops_evidence bundle sign evidence-bundle.manifest.json --key-file .secrets/openops-bundle-signing.key --key-id release-check -o evidence-bundle.signature.json
python -m openops_evidence validate -i evidence-bundle.signature.json -t bundle-signature
python -m openops_evidence bundle verify-signature evidence-bundle.manifest.json evidence-bundle.signature.json --key-file .secrets/openops-bundle-signing.key --fail-on-invalid -o evidence-bundle.signature-verification.json
```

Then inspect:

- `git status --short --ignored`
- generated reports for readability
- generated redacted evidence for accidental sensitive data
- documentation links in `README.md` and `docs/`

## Release Checklist

1. Update `CHANGELOG.md`.
2. Confirm sample artifacts match the current schema.
3. Confirm `schemas/evidence.schema.json`, `schemas/report.schema.json`,
   `schemas/report-history.schema.json`,
   `schemas/executive-brief.schema.json`,
   `schemas/evidence-drift.schema.json`,
   `schemas/review-attestation.schema.json`,
   `schemas/scorecard.schema.json`,
   `schemas/scope-report.schema.json`,
   `schemas/service-catalog.schema.json`,
   `schemas/action-plan.schema.json`, `schemas/gate-result.schema.json`,
   `schemas/badge.schema.json`, `schemas/policy-matrix.schema.json`,
   `schemas/policy-coverage.schema.json`,
   `schemas/questionnaire.schema.json`,
   `schemas/inventory.schema.json`,
   `schemas/privacy-scan.schema.json`, `schemas/waivers.schema.json`,
   `schemas/bundle-manifest.schema.json`,
   `schemas/bundle-signature.schema.json`, `schemas/bundle-verification.schema.json`,
   and `schemas/report-comparison.schema.json` are still aligned with generated output.
4. Run the pre-release checks.
5. Create a signed git tag when signing is available.
6. Publish release notes with a short migration note for any schema or policy
   behavior changes.

## Security Releases

For security fixes, follow `SECURITY.md`. Do not publish exploit details or
sensitive reporter information before a fixed release is available.
