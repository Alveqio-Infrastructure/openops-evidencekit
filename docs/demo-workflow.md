# Demo Workflow

This demo uses only synthetic data from the repository. It is safe to run and
does not contact production systems.

```powershell
$env:PYTHONPATH = "src"

python -m openops_evidence policy list
python -m openops_evidence policy show baseline -o policy.exported.toml
python -m openops_evidence policy validate policy.exported.toml
python -m openops_evidence policy matrix policy.exported.toml -f markdown -o policy.matrix.md
python -m openops_evidence policy matrix policy.exported.toml -f json -o policy.matrix.json
python -m openops_evidence validate -i policy.matrix.json -t policy-matrix
python -m openops_evidence init init-demo --github-actions

python -m openops_evidence collect fixture examples/evidence.sample.json -o evidence.local.json
python -m openops_evidence collect restic-snapshots examples/restic.snapshots.sample.json -o restic.evidence.json
python -m openops_evidence collect borg-archives examples/borg.archives.sample.json -o borg.evidence.json
python -m openops_evidence collect uptime-kuma examples/uptime-kuma.export.sample.json -o uptime-kuma.evidence.json
python -m openops_evidence collect prometheus-targets examples/prometheus.targets.sample.json -o prometheus.evidence.json
python -m openops_evidence collect systemd-timers examples/systemd.timers.sample.json -o systemd.evidence.json
python -m openops_evidence collect docker-containers examples/docker.containers.sample.jsonl -o docker.evidence.json
python -m openops_evidence collect docs examples/docs-sample --required inventory.md --required runbooks/backup-restore.md --max-age-days 365 -o docs.evidence.json

python -m openops_evidence merge evidence.local.json restic.evidence.json borg.evidence.json uptime-kuma.evidence.json prometheus.evidence.json systemd.evidence.json docker.evidence.json docs.evidence.json -o evidence.merged.json
python -m openops_evidence redact -i evidence.merged.json --redact-hostnames -o evidence.redacted.json
python -m openops_evidence validate -i evidence.redacted.json
python -m openops_evidence privacy scan evidence.redacted.json -o privacy-scan.json
python -m openops_evidence validate -i privacy-scan.json -t privacy-scan

python -m openops_evidence check -i evidence.local.json -p examples/policy.baseline.toml -o report.local.json
python -m openops_evidence check -i docs.evidence.json -p examples/policy.documentation.toml -o report.docs.json
python -m openops_evidence validate -i report.local.json -t report
python -m openops_evidence gate report -i report.local.json --min-score 100 --max-warnings 0 -o gate-result.json
python -m openops_evidence validate -i gate-result.json -t gate-result
python -m openops_evidence badge report -i report.local.json -o readiness-badge.json
python -m openops_evidence validate -i readiness-badge.json -t badge
python -m openops_evidence report -i report.local.json -f markdown -o report.local.md
python -m openops_evidence report -i report.local.json -f junit -o report.local.junit.xml
python -m openops_evidence report -i report.local.json -f sarif -o report.local.sarif.json
python -m openops_evidence report -i report.local.json -f prometheus -o report.local.prom
python -m openops_evidence report -i report.local.json -f bookstack -o readiness.bookstack.md
python -m openops_evidence compare --base report.local.json --current report.local.json -o report.comparison.json
python -m openops_evidence compare --base report.local.json --current report.local.json -f markdown -o report.comparison.md
python -m openops_evidence validate -i report.comparison.json -t comparison
python -m openops_evidence plan -i report.local.json -f markdown -o action-plan.md
python -m openops_evidence waiver validate examples/waivers.sample.toml
python -m openops_evidence plan -i report.local.json --waivers examples/waivers.sample.toml -o action-plan.json
python -m openops_evidence ticket export -i action-plan.json -o action-tickets
python -m openops_evidence bundle manifest evidence.redacted.json report.local.json gate-result.json readiness-badge.json report.docs.json report.local.md report.local.sarif.json report.local.prom readiness.bookstack.md -o evidence-bundle.manifest.json
python -m openops_evidence validate -i evidence-bundle.manifest.json -t bundle
python -m openops_evidence bundle verify evidence-bundle.manifest.json --base-dir . -o evidence-bundle.verification.json
python -m openops_evidence validate -i evidence-bundle.verification.json -t bundle-verification
python -m openops_evidence bundle archive evidence-bundle.manifest.json --base-dir . -o evidence-bundle.zip
```

Expected result for the baseline fixture:

```text
Status: PASS
Score: 100
Checks: 10 passed, 0 failed, 0 warnings
```

For real assessments, keep raw evidence private, redact before sharing, and use
your own policy thresholds.
