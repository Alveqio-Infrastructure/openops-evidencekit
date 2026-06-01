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
python -m openops_evidence questionnaire policy policy.exported.toml -f json -o questionnaire.json
python -m openops_evidence validate -i questionnaire.json -t questionnaire
python -m openops_evidence questionnaire policy policy.exported.toml -o questionnaire.md
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
python -m openops_evidence inventory evidence -i evidence.redacted.json -f json -o inventory.json
python -m openops_evidence validate -i inventory.json -t inventory
python -m openops_evidence inventory evidence -i evidence.redacted.json -f markdown -o inventory.md
python -m openops_evidence coverage report -i evidence.redacted.json -p examples/policy.baseline.toml -f json -o policy-coverage.json
python -m openops_evidence validate -i policy-coverage.json -t policy-coverage
python -m openops_evidence coverage report -i evidence.redacted.json -p examples/policy.baseline.toml -o policy-coverage.md
python -m openops_evidence privacy scan evidence.redacted.json -o privacy-scan.json
python -m openops_evidence validate -i privacy-scan.json -t privacy-scan

python -m openops_evidence check -i evidence.local.json -p examples/policy.baseline.toml -o report.local.json
python -m openops_evidence check -i docs.evidence.json -p examples/policy.documentation.toml -o report.docs.json
python -m openops_evidence validate -i report.local.json -t report
python -m openops_evidence gate report -i report.local.json --min-score 100 --max-warnings 0 -o gate-result.json
python -m openops_evidence validate -i gate-result.json -t gate-result
python -m openops_evidence badge report -i report.local.json -o readiness-badge.json
python -m openops_evidence validate -i readiness-badge.json -t badge
python -m openops_evidence brief report -i report.local.json -f json -o executive-brief.json
python -m openops_evidence validate -i executive-brief.json -t executive-brief
python -m openops_evidence brief report -i report.local.json -o executive-brief.md
python -m openops_evidence scorecard report -i report.local.json -f json -o scorecard.json
python -m openops_evidence validate -i scorecard.json -t scorecard
python -m openops_evidence scorecard report -i report.local.json -o scorecard.md
python -m openops_evidence scorecard report -i report.local.json -f html -o scorecard.html
python -m openops_evidence history append -i report.local.json --source demo -o readiness-history.json
python -m openops_evidence validate -i readiness-history.json -t history
python -m openops_evidence history render -i readiness-history.json -f markdown -o readiness-history.md
python -m openops_evidence history render -i readiness-history.json -f svg -o readiness-history.svg
python -m openops_evidence report -i report.local.json -f markdown -o report.local.md
python -m openops_evidence report -i report.local.json -f junit -o report.local.junit.xml
python -m openops_evidence report -i report.local.json -f sarif -o report.local.sarif.json
python -m openops_evidence report -i report.local.json -f prometheus -o report.local.prom
python -m openops_evidence report -i report.local.json -f bookstack -o readiness.bookstack.md
python -m openops_evidence review create -i evidence.redacted.json -p examples/policy.baseline.toml -o review-pack --min-score 100 --max-warnings 0
python -m openops_evidence validate -i review-pack/manifest.json -t bundle
python -m openops_evidence compare --base report.local.json --current report.local.json -o report.comparison.json
python -m openops_evidence compare --base report.local.json --current report.local.json -f markdown -o report.comparison.md
python -m openops_evidence validate -i report.comparison.json -t comparison
python -m openops_evidence plan -i report.local.json -f markdown -o action-plan.md
python -m openops_evidence waiver validate examples/waivers.sample.toml
python -m openops_evidence plan -i report.local.json --waivers examples/waivers.sample.toml -o action-plan.json
python -m openops_evidence ticket export -i action-plan.json -o action-tickets
python -m openops_evidence bundle manifest evidence.redacted.json questionnaire.json inventory.json policy-coverage.json report.local.json gate-result.json readiness-badge.json executive-brief.json scorecard.json readiness-history.json readiness-history.svg report.docs.json report.local.md report.local.sarif.json report.local.prom readiness.bookstack.md -o evidence-bundle.manifest.json
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
