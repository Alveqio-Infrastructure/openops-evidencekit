# Evidence Scaffolds

Evidence scaffolds turn a policy into an editable starter Evidence JSON file.
This is useful before an assessment starts: reviewers can see exactly which
`signals.*` fields the policy expects without hand-writing the JSON shape.

```powershell
python -m openops_evidence scaffold evidence policy.baseline.toml --organization "Example Operations Team" --environment production -o evidence.scaffold.json
python -m openops_evidence validate -i evidence.scaffold.json
```

The generated file is schema-valid evidence. It contains empty assets and a
`signals` tree built from policy paths:

```json
{
  "assets": [],
  "signals": {
    "backup": {
      "last_success_at": null,
      "restore_test_at": null
    },
    "monitoring": {
      "alert_channels": [],
      "targets": null
    }
  }
}
```

Placeholders are intentionally `null` or empty arrays. Running the scaffold
against the policy should still fail until real evidence is filled in:

```powershell
python -m openops_evidence check -i evidence.scaffold.json -p policy.baseline.toml -o report.scaffold.json
```

Checks that use the `missing` operator are skipped in the scaffold because the
policy explicitly expects that selected values are absent. Paths outside
`signals.*` are listed in `metadata.skipped_policy_paths` so they remain visible
without producing invalid placeholder assets.
