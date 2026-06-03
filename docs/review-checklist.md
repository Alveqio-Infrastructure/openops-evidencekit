# Review Checklists

Review checklists are generated inside review packs as
`review-checklist.json`, `review-checklist.md`, and `review-checklist.csv`.
They turn the one-page review summary and generated operational reports into a
concrete reviewer handoff list.

```powershell
python -m openops_evidence review create -i evidence.redacted.json -p policy.baseline.toml --catalog service-catalog.toml -o review-pack
python -m openops_evidence validate -i review-pack/review-checklist.json -t review-checklist
```

Use `review-checklist.md` when a human reviewer needs a simple sign-off list.
Use `review-checklist.csv` when review work is tracked in a spreadsheet, ticket
queue, or customer handoff tracker. Use `review-checklist.json` for automation
that needs to detect whether review work is clean, warning-only, or blocked.

## Status

The checklist summary status is derived from item status:

- `pass` when all known checklist items are clean
- `warn` when one or more optional review areas need attention
- `fail` when a blocking metric, failed gate, privacy finding, open risk, or
  failed operational report needs review

Each item records:

- `id`
- `title`
- `status`
- `required`
- `artifact`
- `reason`

The checklist does not replace the underlying reports. It is a deterministic
handoff layer that points reviewers to the artifacts that need attention.
