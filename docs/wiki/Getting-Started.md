# Getting Started

Run the synthetic demo from a checkout:

```powershell
$env:PYTHONPATH = "src"
python -m openops_evidence --version
python -m openops_evidence policy list
python -m openops_evidence collect fixture examples/evidence.sample.json -o evidence.local.json
python -m openops_evidence check -i evidence.local.json -p examples/policy.baseline.toml -o report.local.json
python -m openops_evidence gate report -i report.local.json --min-score 90 -o gate-result.json
python -m openops_evidence report -i report.local.json -f markdown -o report.local.md
python -m openops_evidence report -i report.local.json -f junit -o report.local.junit.xml
python -m openops_evidence report -i report.local.json -f sarif -o report.local.sarif.json
python -m openops_evidence plan -i report.local.json -f markdown -o action-plan.md
python -m openops_evidence plan -i report.local.json -o action-plan.json
python -m openops_evidence waiver validate examples/waivers.sample.toml
python -m openops_evidence ticket export -i action-plan.json -o action-tickets
python -m openops_evidence compare --base report.local.json --current report.local.json -f markdown -o report.comparison.md
```

For a fuller workflow with collectors, redaction, reports, action plans, and a
bundle manifest, use `docs/demo-workflow.md`.

## First Real Assessment

1. Copy `examples/policy.baseline.toml`.
2. Export evidence from backup, monitoring, runtime, and documentation systems.
3. Run collectors against exported files.
4. Merge collector outputs.
5. Redact before sharing.
6. Generate an action plan for remediation work.
7. Compare current reports against a prior review.
8. Keep raw evidence private.
