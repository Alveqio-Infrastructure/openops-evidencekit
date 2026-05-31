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

## Pre-Release Checks

Run these commands from the repository root:

```powershell
$env:PYTHONPATH = "src"
python -m openops_evidence --version
python -m unittest discover -s tests
python -m openops_evidence policy list
python -m openops_evidence policy show baseline -o policy.exported.toml
python -m openops_evidence validate -i examples/evidence.sample.json
python -m openops_evidence collect docs examples/docs-sample --required inventory.md --required runbooks/backup-restore.md --max-age-days 365 -o docs.evidence.json
python -m openops_evidence check -i docs.evidence.json -p examples/policy.documentation.toml -o report.docs.json
python -m openops_evidence check -i examples/evidence.sample.json -p examples/policy.baseline.toml -o report.local.json
python -m openops_evidence compare --base report.local.json --current report.local.json -o report.comparison.json
python -m openops_evidence validate -i report.comparison.json -t comparison
python -m openops_evidence report -i report.local.json -f markdown -o report.local.md
python -m openops_evidence redact -i examples/evidence.sample.json --redact-hostnames -o evidence.redacted.json
python -m openops_evidence bundle manifest evidence.redacted.json report.local.json report.docs.json report.comparison.json report.local.md -o evidence-bundle.manifest.json
python -m openops_evidence validate -i evidence-bundle.manifest.json -t bundle
python -m openops_evidence bundle verify evidence-bundle.manifest.json --base-dir . -o evidence-bundle.verification.json
python -m openops_evidence validate -i evidence-bundle.verification.json -t bundle-verification
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
   `schemas/bundle-manifest.schema.json`, `schemas/bundle-verification.schema.json`,
   and `schemas/report-comparison.schema.json` are still aligned with generated
   output.
4. Run the pre-release checks.
5. Create a signed git tag when signing is available.
6. Publish release notes with a short migration note for any schema or policy
   behavior changes.

## Security Releases

For security fixes, follow `SECURITY.md`. Do not publish exploit details or
sensitive reporter information before a fixed release is available.
