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
| `report.json` / `report.md` | Canonical check results and a human-readable report. |
| `executive-brief.json` / `executive-brief.md` | Stakeholder summary with top findings and next steps. |
| `action-plan.json` / `action-plan.md` / `action-plan.csv` | Prioritized remediation queue. |
| `risk-register.json` / `risk-register.md` / `risk-register.csv` | Open, accepted, expired, and closed risk register. |
| `inventory.json` / `inventory.md` / `inventory.csv` | Asset and signal-domain inventory from evidence. |
| `freshness-report.json` / `freshness-report.md` / `freshness-report.csv` | Evidence timestamp freshness report. |
| `evidence-drift.json` / `evidence-drift.md` / `evidence-drift.csv` | Optional drift report when `--base-evidence` is provided. |
| `scope-report.json` / `scope-report.md` / `scope-report.csv` | Optional scope boundary report when `--scope` is provided. |
| `service-catalog.json` / `service-catalog.md` / `service-catalog.csv` | Optional service ownership and evidence coverage report when `--catalog` is provided. |
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
sharing, create the pack from redacted evidence, inspect `privacy-scan.md`, and
verify the manifest:

```powershell
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
