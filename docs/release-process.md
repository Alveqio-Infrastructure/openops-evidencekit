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
python -m unittest discover -s tests
python -m openops_evidence validate -i examples/evidence.sample.json
python -m openops_evidence check -i examples/evidence.sample.json -p examples/policy.baseline.toml -o report.local.json
python -m openops_evidence report -i report.local.json -f markdown -o report.local.md
python -m openops_evidence redact -i examples/evidence.sample.json --redact-hostnames -o evidence.redacted.json
```

Then inspect:

- `git status --short --ignored`
- generated reports for readability
- generated redacted evidence for accidental sensitive data
- documentation links in `README.md` and `docs/`

## Release Checklist

1. Update `CHANGELOG.md`.
2. Confirm sample artifacts match the current schema.
3. Confirm `schemas/evidence.schema.json` and `schemas/report.schema.json` are
   still aligned with generated output.
4. Run the pre-release checks.
5. Create a signed git tag when signing is available.
6. Publish release notes with a short migration note for any schema or policy
   behavior changes.

## Security Releases

For security fixes, follow `SECURITY.md`. Do not publish exploit details or
sensitive reporter information before a fixed release is available.
