# Service Level Reports

`service-level report` compares service-level evidence from monitoring with the
declared service catalog. It shows whether services meet their configured SLO or
default availability target.

```powershell
python -m openops_evidence service-level report -i evidence.redacted.json -c service-catalog.toml -o service-level-report.md
python -m openops_evidence service-level report -i evidence.redacted.json -c service-catalog.toml -f json -o service-level-report.json
python -m openops_evidence validate -i service-level-report.json -t service-level-report
```

Service-level evidence is read from `signals.monitoring.service_levels`,
`signals.monitoring.slos`, or `signals.monitoring.service_slos`.

```json
{
  "service_id": "public-web",
  "uptime_percent": 99.82,
  "window": "30d",
  "error_budget_remaining_percent": 64.0
}
```

The service catalog can set `slo_target_percent` per service. If no explicit
target is set, EvidenceKit uses default targets by criticality: critical 99.9%,
high 99.5%, medium 99.0%, and low 95.0%.

Review packs generate `service-level-report.json`, `service-level-report.md`,
and `service-level-report.csv` automatically when a service catalog is provided.
Use `--fail-on-warn` when missing or failing SLO evidence should fail local
scripts or CI jobs.
