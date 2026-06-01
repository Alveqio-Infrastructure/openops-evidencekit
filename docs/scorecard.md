# Domain Scorecards

`scorecard report` groups a readiness report by evidence domain. It is useful
when a full check list is too detailed for the first review pass.

```powershell
python -m openops_evidence scorecard report -i report.local.json -o scorecard.md
python -m openops_evidence scorecard report -i report.local.json -f json -o scorecard.json
python -m openops_evidence scorecard report -i report.local.json -f csv -o scorecard.csv
```

Domains are inferred from report result paths. For example,
`signals.backup.last_success_at` is grouped into `backup`, and
`signals.monitoring.targets` is grouped into `monitoring`.

Each domain records:

- status: `fail`, `warn`, or `pass`
- score using the same required-failure weighting as the report
- total, passed, failed, and warning check counts
- critical, high, medium, and low attention counts
- the contributing checks

The JSON output can be validated:

```powershell
python -m openops_evidence validate -i scorecard.json -t scorecard
```

Review packs include `scorecard.json`, `scorecard.md`, and `scorecard.csv`
automatically.
