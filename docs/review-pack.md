# Review Packs

`review create` turns one evidence file and one policy into a complete
readiness handoff folder.

```powershell
python -m openops_evidence review create -i evidence.redacted.json -p policy.baseline.toml --scope scope.toml --catalog service-catalog.toml --base-evidence previous-evidence.json -o review-pack --archive review-pack.zip --min-score 90 --max-warnings 0
```

The command evaluates the policy and writes the common outputs that different
audiences need:

| Artifact | Use |
| --- | --- |
| `index.html` | Browser-friendly review dashboard and artifact index. |
| `README.md` | Entry point and suggested review order. |
| `review-summary.json` / `review-summary.md` | One-page handoff decision summary. |
| `review-checklist.json` / `review-checklist.md` / `review-checklist.csv` | Reviewer task list derived from summary and generated report metrics. |
| `quality-report.json` / `quality-report.md` / `quality-report.csv` | Evidence input hygiene checks for duplicate assets, missing metadata, empty signals, and common gaps. |
| `completeness-report.json` / `completeness-report.md` / `completeness-report.csv` | Check-level missing evidence list for the evaluated policy. |
| `report.json` / `report.md` | Canonical check results and a human-readable report. |
| `executive-brief.json` / `executive-brief.md` | Stakeholder summary with top findings and next steps. |
| `action-plan.json` / `action-plan.md` / `action-plan.csv` | Prioritized remediation queue. |
| `risk-register.json` / `risk-register.md` / `risk-register.csv` | Open, accepted, expired, and closed risk register. |
| `inventory.json` / `inventory.md` / `inventory.csv` | Asset and signal-domain inventory from evidence. |
| `freshness-report.json` / `freshness-report.md` / `freshness-report.csv` | Evidence timestamp freshness report. |
| `restore-report.json` / `restore-report.md` / `restore-report.csv` | Backup recency and restore drill assurance report. |
| `mail-report.json` / `mail-report.md` / `mail-report.csv` | Optional SPF, DKIM, and DMARC report when mail evidence or policy paths exist. |
| `tls-report.json` / `tls-report.md` / `tls-report.csv` | Optional TLS certificate expiry report when TLS evidence or policy paths exist. |
| `access-report.json` / `access-report.md` / `access-report.csv` | Optional public SSH, MFA, and admin entrypoint report when access evidence or policy paths exist. |
| `monitoring-report.json` / `monitoring-report.md` / `monitoring-report.csv` | Optional monitoring target, down target, alert channel, and alert-test report when monitoring evidence or policy paths exist. |
| `runtime-report.json` / `runtime-report.md` / `runtime-report.csv` | Optional Docker and systemd runtime report when runtime evidence or policy paths exist. |
| `incident-report.json` / `incident-report.md` / `incident-report.csv` | Optional incident readiness report when `--catalog` is provided or incident policy paths exist. |
| `evidence-drift.json` / `evidence-drift.md` / `evidence-drift.csv` | Optional drift report when `--base-evidence` is provided. |
| `scope-report.json` / `scope-report.md` / `scope-report.csv` | Optional scope boundary report when `--scope` is provided. |
| `service-catalog.json` / `service-catalog.md` / `service-catalog.csv` | Optional service ownership and evidence coverage report when `--catalog` is provided. |
| `service-level-report.json` / `service-level-report.md` / `service-level-report.csv` | Optional service-level and SLO report when `--catalog` is provided. |
| `runbook-report.json` / `runbook-report.md` / `runbook-report.csv` | Optional runbook coverage report when `--catalog` is provided. |
| `policy-matrix.json` / `policy-matrix.md` / `policy-matrix.csv` | Coverage map for the policy that was evaluated. |
| `policy-coverage.json` / `policy-coverage.md` / `policy-coverage.csv` | Evidence-domain coverage and gap analysis for the evaluated policy. |
| `scorecard.json` / `scorecard.md` / `scorecard.csv` / `scorecard.html` | Readiness summary grouped by operational evidence area. |
| `gate-result.json` / `gate-result.md` | CI decision and threshold details. |
| `readiness-badge.json` | Shields-compatible status badge endpoint JSON. |
| `report.junit.xml` | CI test-result output. |
| `report.sarif.json` | SARIF findings for review tooling. |
| `report.prom` | Prometheus text metrics. |
| `privacy-scan.json` / `privacy-scan.md` | Scan result for generated sharing artifacts. |
| `manifest.json` | Hash manifest for generated artifacts. |

Raw evidence is not copied into the review pack by default. For external
sharing, create the pack from redacted evidence, read `review-summary.md`,
work through `review-checklist.md`, inspect `quality-report.md`, inspect
`completeness-report.md`, inspect `privacy-scan.md`, and verify the manifest:

```powershell
python -m openops_evidence validate -i review-pack/quality-report.json -t quality-report
python -m openops_evidence validate -i review-pack/completeness-report.json -t completeness-report
python -m openops_evidence validate -i review-pack/runtime-report.json -t runtime-report
python -m openops_evidence validate -i review-pack/service-level-report.json -t service-level-report
python -m openops_evidence validate -i review-pack/review-checklist.json -t review-checklist
python -m openops_evidence validate -i review-pack/manifest.json -t bundle
python -m openops_evidence bundle verify review-pack/manifest.json --base-dir review-pack -o review-pack/verification.json
```

Pass `--archive review-pack.zip` when the handoff should also be written as a
ZIP file. The archive includes `manifest.json` and the generated artifacts.

After a pack has been reviewed, create a separate attestation bound to the
manifest hash:

```powershell
python -m openops_evidence attest review --manifest review-pack/manifest.json --report review-pack/report.json --gate review-pack/gate-result.json --privacy-scan review-pack/privacy-scan.json --approver "Example Reviewer" --role "Operations" --statement "Reviewed generated artifacts for handoff." -o review-attestation.json
```

For CI pipelines, add `--fail-on-gate` when the review pack command itself
should return a failing exit code if the generated gate fails:

```powershell
python -m openops_evidence review create -i evidence.redacted.json -p policy.baseline.toml -o review-pack --archive review-pack.zip --min-score 90 --max-warnings 0 --fail-on-gate
```

When `--scope` is provided, add `--fail-on-scope-warn` if unclassified evidence,
out-of-scope evidence, or missing required scope items should fail the review
pack command after the pack has been written.

When `--catalog` is provided, add `--fail-on-catalog-warn` if missing service
assets, evidence domains, runbooks, or unassigned evidence assets should fail
the review pack command after the pack has been written.

Add `--fail-on-runbook-warn` when stale, missing, unreferenced, or malformed
runbook evidence should fail the review pack command after the pack has been
written.

Add `--fail-on-freshness-warn` when stale or invalid evidence timestamps should
fail the review pack command after the pack has been written. Use
`--freshness-max-age-days` to tune the default 30-day freshness window.

Add `--fail-on-restore-warn` when missing, stale, unknown, or failed restore
evidence should fail the review pack command after the pack has been written.
Use `--restore-max-drill-age-days` and `--restore-max-backup-age-days` to tune
the default restore drill and backup recency windows.

Add `--fail-on-mail-warn` when missing SPF, DKIM, missing DMARC, monitoring-only
DMARC, or unknown DMARC policy evidence should fail the review pack command
after the pack has been written.

Add `--fail-on-tls-warn` when missing, invalid, expired, or soon expiring TLS
certificate evidence should fail the review pack command after the pack has
been written.

Add `--fail-on-access-warn` when missing public SSH evidence, missing MFA
evidence, public SSH exposure, missing entrypoints, risky entrypoints, or
unclassified entrypoints should fail the review pack command after the pack has
been written.

Add `--fail-on-monitoring-warn` when missing target evidence, down targets,
missing alert channels, or stale alert tests should fail the review pack command
after the pack has been written.

Add `--fail-on-incident-warn` when missing escalation contacts, missing incident
runbooks, missing alert routing, missing restore proof, or unsafe emergency
access should fail the review pack command after the pack has been written.

Add `--fail-on-open-risk` when open, non-accepted risks in the generated risk
register should fail the review pack command after the pack has been written.

When `--base-evidence` is provided, add `--fail-on-drift` if asset or
signal-domain drift should fail the review pack command after the pack has been
written.

Risk waivers can be applied to the generated action plan:

```powershell
python -m openops_evidence review create -i evidence.redacted.json -p policy.baseline.toml --waivers waivers.toml -o review-pack
```

The same waivers also feed `risk-register.*`, so accepted risks remain visible
with owner, reason, and expiry in the review pack.
