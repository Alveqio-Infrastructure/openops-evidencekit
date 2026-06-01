# Runbook Coverage Reports

Runbook coverage reports inspect `signals.docs.runbooks` and optionally compare
them with service catalog expectations. They help operators see which required
runbooks are present, missing, stale, or not referenced by any cataloged
service.

```powershell
python -m openops_evidence runbook report -i evidence.local.json -o runbook-report.md
python -m openops_evidence runbook report -i evidence.local.json -c examples/service-catalog.sample.toml -f json -o runbook-report.json
python -m openops_evidence validate -i runbook-report.json -t runbook-report
python -m openops_evidence runbook report -i evidence.local.json -c examples/service-catalog.sample.toml -f csv -o runbook-report.csv
```

Use `--max-age-days` to mark old runbooks as stale:

```powershell
python -m openops_evidence runbook report -i evidence.local.json -c service-catalog.toml --max-age-days 90 --fail-on-warn -o runbook-report.md
```

## Status Logic

Runbooks use these statuses:

- `current`: observed and within the configured age threshold
- `stale`: observed but older than `--max-age-days`
- `missing`: expected by the service catalog but not observed
- `unreferenced`: observed but not referenced by any catalog service
- `warn`: observed but the timestamp could not be parsed

The overall report is `warn` when any runbook is stale, missing,
unreferenced, or has an invalid timestamp.

This report is operational evidence. Review the source documentation and
service catalog before using it for customer handoff or audit material.
