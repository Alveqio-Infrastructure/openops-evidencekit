# Status Badges

`openops-evidence badge report` turns a report JSON file into Shields-compatible
endpoint JSON. This lets teams publish the current readiness status in a README,
internal portal, BookStack page, or static dashboard without scraping Markdown.

```powershell
python -m openops_evidence badge report -i report.local.json -o readiness-badge.json
python -m openops_evidence validate -i readiness-badge.json -t badge
```

The output uses the Shields endpoint shape:

```json
{
  "schemaVersion": 1,
  "label": "openops",
  "message": "pass 100",
  "color": "brightgreen"
}
```

## Color Mapping

- failed reports are `red`
- passing reports with score 95 or higher are `brightgreen`
- passing reports with score 85 or higher are `green`
- passing reports with score 70 or higher are `yellowgreen`
- passing reports with score 50 or higher are `yellow`
- lower passing scores are `orange`

The badge is intentionally compact. Use the full report, gate result, action
plan, and bundle manifest for audit trails and customer handoff.
