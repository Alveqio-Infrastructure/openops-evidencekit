# Prometheus Output

`openops-evidence report -f prometheus` renders report JSON as Prometheus text
exposition. This is useful for node-exporter textfile collectors, CI artifact
scrapers, internal dashboards, or a small wrapper service that exposes the latest
readiness result.

```powershell
python -m openops_evidence report -i report.local.json -f prometheus -o report.local.prom
```

The output includes:

- `openops_readiness_score`
- `openops_report_status{status="pass|fail"}`
- `openops_checks_total{result="total|passed|failed|warnings"}`
- `openops_report_generated_at_seconds`
- `openops_check_result{check_id="...",status="...",severity="...",required="..."}`

The metrics are snapshots of the source report. Use normal Prometheus scraping
or textfile collection timestamps to reason about freshness.
