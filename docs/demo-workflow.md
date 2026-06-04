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
python -m openops_evidence scaffold evidence policy.exported.toml --organization "Example Operations Team" --environment production -o evidence.scaffold.json
python -m openops_evidence validate -i evidence.scaffold.json
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
python -m openops_evidence evidence quality -i evidence.redacted.json -f json -o quality-report.json
python -m openops_evidence validate -i quality-report.json -t quality-report
python -m openops_evidence evidence quality -i evidence.redacted.json -o quality-report.md
python -m openops_evidence evidence completeness -i evidence.redacted.json -p examples/policy.baseline.toml -f json -o completeness-report.json
python -m openops_evidence validate -i completeness-report.json -t completeness-report
python -m openops_evidence evidence completeness -i evidence.redacted.json -p examples/policy.baseline.toml -o completeness-report.md
python -m openops_evidence freshness report -i evidence.redacted.json --max-age-days 30 -f json -o freshness-report.json
python -m openops_evidence validate -i freshness-report.json -t freshness-report
python -m openops_evidence freshness report -i evidence.redacted.json --max-age-days 30 -o freshness-report.md
python -m openops_evidence restore report -i evidence.redacted.json --max-drill-age-days 90 -f json -o restore-report.json
python -m openops_evidence validate -i restore-report.json -t restore-report
python -m openops_evidence restore report -i evidence.redacted.json --max-drill-age-days 90 -o restore-report.md
python -m openops_evidence mail report -i evidence.redacted.json -f json -o mail-report.json
python -m openops_evidence validate -i mail-report.json -t mail-report
python -m openops_evidence mail report -i evidence.redacted.json -o mail-report.md
python -m openops_evidence tls report -i evidence.redacted.json -f json -o tls-report.json
python -m openops_evidence validate -i tls-report.json -t tls-report
python -m openops_evidence tls report -i evidence.redacted.json -o tls-report.md
python -m openops_evidence access report -i evidence.redacted.json -f json -o access-report.json
python -m openops_evidence validate -i access-report.json -t access-report
python -m openops_evidence access report -i evidence.redacted.json -o access-report.md
python -m openops_evidence monitoring report -i evidence.redacted.json -f json -o monitoring-report.json
python -m openops_evidence validate -i monitoring-report.json -t monitoring-report
python -m openops_evidence monitoring report -i evidence.redacted.json -o monitoring-report.md
python -m openops_evidence incident report -i evidence.redacted.json -c examples/service-catalog.sample.toml -f json -o incident-report.json
python -m openops_evidence validate -i incident-report.json -t incident-report
python -m openops_evidence incident report -i evidence.redacted.json -c examples/service-catalog.sample.toml -o incident-report.md
python -m openops_evidence scope validate examples/scope.sample.toml
python -m openops_evidence scope report -i evidence.redacted.json -s examples/scope.sample.toml -f json -o scope-report.json
python -m openops_evidence validate -i scope-report.json -t scope-report
python -m openops_evidence scope report -i evidence.redacted.json -s examples/scope.sample.toml -o scope-report.md
python -m openops_evidence catalog validate examples/service-catalog.sample.toml
python -m openops_evidence catalog report -i evidence.redacted.json -c examples/service-catalog.sample.toml -f json -o service-catalog.json
python -m openops_evidence validate -i service-catalog.json -t service-catalog
python -m openops_evidence catalog report -i evidence.redacted.json -c examples/service-catalog.sample.toml -o service-catalog.md
python -m openops_evidence runbook report -i evidence.redacted.json -c examples/service-catalog.sample.toml --max-age-days 365 -f json -o runbook-report.json
python -m openops_evidence validate -i runbook-report.json -t runbook-report
python -m openops_evidence runbook report -i evidence.redacted.json -c examples/service-catalog.sample.toml --max-age-days 365 -o runbook-report.md
python -m openops_evidence evidence diff --base examples/evidence.previous.json --current evidence.redacted.json -f json -o evidence-drift.json
python -m openops_evidence validate -i evidence-drift.json -t evidence-drift
python -m openops_evidence evidence diff --base examples/evidence.previous.json --current evidence.redacted.json -f markdown -o evidence-drift.md
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
python -m openops_evidence risk register -i report.local.json --waivers examples/waivers.sample.toml -o risk-register.json
python -m openops_evidence validate -i risk-register.json -t risk-register
python -m openops_evidence risk register -i report.local.json --waivers examples/waivers.sample.toml -f markdown -o risk-register.md
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
python -m openops_evidence service-level report -i evidence.redacted.json -c examples/service-catalog.sample.toml -f json -o service-level-report.json
python -m openops_evidence validate -i service-level-report.json -t service-level-report
python -m openops_evidence service-level report -i evidence.redacted.json -c examples/service-catalog.sample.toml -o service-level-report.md
python -m openops_evidence review create -i evidence.redacted.json -p examples/policy.baseline.toml --scope examples/scope.sample.toml --catalog examples/service-catalog.sample.toml --base-evidence examples/evidence.previous.json -o review-pack --archive review-pack.zip --min-score 100 --max-warnings 0
python -m openops_evidence validate -i review-pack/review-summary.json -t review-summary
python -m openops_evidence validate -i review-pack/review-checklist.json -t review-checklist
python -m openops_evidence validate -i review-pack/quality-report.json -t quality-report
python -m openops_evidence validate -i review-pack/completeness-report.json -t completeness-report
python -m openops_evidence validate -i review-pack/restore-report.json -t restore-report
python -m openops_evidence validate -i review-pack/mail-report.json -t mail-report
python -m openops_evidence validate -i review-pack/tls-report.json -t tls-report
python -m openops_evidence validate -i review-pack/access-report.json -t access-report
python -m openops_evidence validate -i review-pack/monitoring-report.json -t monitoring-report
python -m openops_evidence validate -i review-pack/service-level-report.json -t service-level-report
python -m openops_evidence validate -i review-pack/incident-report.json -t incident-report
python -m openops_evidence validate -i review-pack/manifest.json -t bundle
python -m openops_evidence compare --base report.local.json --current report.local.json -o report.comparison.json
python -m openops_evidence compare --base report.local.json --current report.local.json -f markdown -o report.comparison.md
python -m openops_evidence validate -i report.comparison.json -t comparison
python -m openops_evidence plan -i report.local.json -f markdown -o action-plan.md
python -m openops_evidence waiver validate examples/waivers.sample.toml
python -m openops_evidence plan -i report.local.json --waivers examples/waivers.sample.toml -o action-plan.json
python -m openops_evidence ticket export -i action-plan.json -o action-tickets
python -m openops_evidence bundle manifest evidence.scaffold.json evidence.redacted.json evidence-drift.json questionnaire.json inventory.json quality-report.json completeness-report.json freshness-report.json restore-report.json mail-report.json tls-report.json access-report.json monitoring-report.json service-level-report.json incident-report.json scope-report.json service-catalog.json runbook-report.json policy-coverage.json report.local.json gate-result.json readiness-badge.json executive-brief.json risk-register.json scorecard.json readiness-history.json readiness-history.svg report.docs.json report.local.md report.local.sarif.json report.local.prom readiness.bookstack.md -o evidence-bundle.manifest.json
python -m openops_evidence validate -i evidence-bundle.manifest.json -t bundle
python -m openops_evidence bundle verify evidence-bundle.manifest.json --base-dir . -o evidence-bundle.verification.json
python -m openops_evidence validate -i evidence-bundle.verification.json -t bundle-verification
python -m openops_evidence bundle archive evidence-bundle.manifest.json --base-dir . -o evidence-bundle.zip
python -m openops_evidence attest review --manifest evidence-bundle.manifest.json --report report.local.json --gate gate-result.json --scope-report scope-report.json --evidence-drift evidence-drift.json --privacy-scan privacy-scan.json --approver "Example Reviewer" --role "Operations" --statement "Reviewed generated artifacts for demo handoff." -o review-attestation.json
python -m openops_evidence validate -i review-attestation.json -t review-attestation
```

Expected result for the baseline fixture:

```text
Status: PASS
Score: 100
Checks: 10 passed, 0 failed, 0 warnings
```

For real assessments, keep raw evidence private, redact before sharing, and use
your own policy thresholds.
