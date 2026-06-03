# Evidence Quality Reports

`evidence quality` checks the hygiene of an Evidence JSON file before policy
evaluation, review packs, or external handoffs rely on it.

```powershell
python -m openops_evidence evidence quality -i evidence.redacted.json -o quality-report.md
python -m openops_evidence evidence quality -i evidence.redacted.json -f json -o quality-report.json
python -m openops_evidence validate -i quality-report.json -t quality-report
```

The report checks practical input-quality issues:

- missing `metadata.organization` or `metadata.environment`
- missing signal domains
- duplicate or missing asset IDs
- assets without roles or tags
- backup assets without backup recency or restore drill evidence
- monitoring evidence without alert channels
- documentation evidence without runbooks

The report is also generated automatically in review packs as
`quality-report.json`, `quality-report.md`, and `quality-report.csv`.

Use `--fail-on-warn` when evidence hygiene warnings should fail local scripts or
CI runs. Failed quality checks always return exit code `1`.
