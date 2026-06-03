# Incident Readiness Reports

`incident report` turns existing evidence and an optional service catalog into a
focused incident response handoff artifact.

```powershell
python -m openops_evidence incident report -i evidence.redacted.json -c service-catalog.toml -o incident-report.md
python -m openops_evidence incident report -i evidence.redacted.json -c service-catalog.toml -f json -o incident-report.json
python -m openops_evidence validate -i incident-report.json -t incident-report
python -m openops_evidence incident report -i evidence.redacted.json -c service-catalog.toml -f csv -o incident-report.csv
```

The report checks:

- Incident or escalation runbook evidence exists.
- Critical and high-impact services have escalation contacts.
- Critical and high-impact services reference incident-style runbooks.
- Monitoring alert channels are recorded.
- Restore drill evidence is present.
- Emergency administration is behind controlled access and MFA.

The command can run without a catalog, but it will warn because service
escalation contacts and service-to-runbook coverage cannot be proven. Review
packs include `incident-report.json`, `incident-report.md`, and
`incident-report.csv` automatically when `--catalog` is provided or when policy
checks explicitly reference incident readiness.

Use `--fail-on-warn` for standalone CI checks, or
`review create --fail-on-incident-warn` when incident readiness gaps should fail
after the review pack has been written.
