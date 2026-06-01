# Evidence Drift

Evidence drift reports compare two Evidence JSON files. They show which assets
and top-level `signals.*` domains were added, removed, or changed between runs.

```powershell
python -m openops_evidence evidence diff --base previous-evidence.json --current evidence.local.json -o evidence-drift.json
python -m openops_evidence validate -i evidence-drift.json -t evidence-drift
python -m openops_evidence evidence diff --base previous-evidence.json --current evidence.local.json -f markdown -o evidence-drift.md
python -m openops_evidence evidence diff --base previous-evidence.json --current evidence.local.json -f csv -o evidence-drift.csv
```

Use `--fail-on-drift` when CI should fail if asset or signal-domain drift is
detected:

```powershell
python -m openops_evidence evidence diff --base previous-evidence.json --current evidence.local.json --fail-on-drift
```

The report includes stable summaries and SHA-256 fingerprints. It does not embed
raw signal values from the source evidence. That makes it useful for recurring
readiness reviews, pull requests, and handoff packages where reviewers need to
know that evidence changed without duplicating all collected facts.

Typical review questions:

- Did a production asset appear without a matching scope update?
- Was a retired asset removed from evidence?
- Did a collector start producing a new signal domain?
- Did a signal domain value change even though its field names stayed the same?

Evidence drift complements report comparison. `compare` shows whether policy
results changed. `evidence diff` shows whether the underlying collected evidence
changed.

Review packs can include the same drift artifacts when a previous evidence file
is available:

```powershell
python -m openops_evidence review create -i evidence.local.json -p policy.baseline.toml --base-evidence previous-evidence.json -o review-pack
```
