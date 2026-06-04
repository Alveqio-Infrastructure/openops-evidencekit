# Evidence Completeness Reports

`evidence completeness` compares an Evidence JSON file with a policy and shows
which policy evidence paths are present, missing, or intentionally absent.

```powershell
python -m openops_evidence evidence completeness -i evidence.redacted.json -p policy.baseline.toml -o completeness-report.md
python -m openops_evidence evidence completeness -i evidence.redacted.json -p policy.baseline.toml -f json -o completeness-report.json
python -m openops_evidence validate -i completeness-report.json -t completeness-report
```

Use it before a readiness review when system owners need a concrete list of
missing evidence. The report is check-level, while policy coverage is
domain-level.

Each item records:

- policy check ID and title
- required flag and severity
- evidence path and operator
- observed value count
- evidence status: `present`, `missing`, or `expected_absent`
- reviewer request and remediation text

Review packs generate `completeness-report.json`, `completeness-report.md`, and
`completeness-report.csv` automatically. Pass `--fail-on-missing` when missing
required evidence should fail a local script or CI job.
