# Demo Workflow

This demo uses only synthetic data from the repository. It is safe to run and
does not contact production systems.

```powershell
$env:PYTHONPATH = "src"

python -m openops_evidence collect fixture examples/evidence.sample.json -o evidence.local.json
python -m openops_evidence collect restic-snapshots examples/restic.snapshots.sample.json -o restic.evidence.json
python -m openops_evidence collect uptime-kuma examples/uptime-kuma.export.sample.json -o uptime-kuma.evidence.json
python -m openops_evidence collect prometheus-targets examples/prometheus.targets.sample.json -o prometheus.evidence.json

python -m openops_evidence merge evidence.local.json restic.evidence.json uptime-kuma.evidence.json prometheus.evidence.json -o evidence.merged.json
python -m openops_evidence redact -i evidence.merged.json --redact-hostnames -o evidence.redacted.json
python -m openops_evidence validate -i evidence.redacted.json

python -m openops_evidence check -i evidence.local.json -p examples/policy.baseline.toml -o report.local.json
python -m openops_evidence validate -i report.local.json -t report
python -m openops_evidence report -i report.local.json -f markdown -o report.local.md
python -m openops_evidence report -i report.local.json -f bookstack -o readiness.bookstack.md
```

Expected result for the baseline fixture:

```text
Status: PASS
Score: 100
Checks: 10 passed, 0 failed, 0 warnings
```

For real assessments, keep raw evidence private, redact before sharing, and use
your own policy thresholds.
