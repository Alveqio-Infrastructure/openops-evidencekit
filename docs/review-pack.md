# Review Packs

`review create` turns one evidence file and one policy into a complete
readiness handoff folder.

```powershell
python -m openops_evidence review create -i evidence.redacted.json -p policy.baseline.toml -o review-pack --min-score 90 --max-warnings 0
```

The command evaluates the policy and writes the common outputs that different
audiences need:

| Artifact | Use |
| --- | --- |
| `README.md` | Entry point and suggested review order. |
| `report.json` / `report.md` | Canonical check results and a human-readable report. |
| `executive-brief.json` / `executive-brief.md` | Stakeholder summary with top findings and next steps. |
| `action-plan.json` / `action-plan.md` / `action-plan.csv` | Prioritized remediation queue. |
| `inventory.json` / `inventory.md` / `inventory.csv` | Asset and signal-domain inventory from evidence. |
| `policy-matrix.json` / `policy-matrix.md` / `policy-matrix.csv` | Coverage map for the policy that was evaluated. |
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

For CI pipelines, add `--fail-on-gate` when the review pack command itself
should return a failing exit code if the generated gate fails:

```powershell
python -m openops_evidence review create -i evidence.redacted.json -p policy.baseline.toml -o review-pack --min-score 90 --max-warnings 0 --fail-on-gate
```

Risk waivers can be applied to the generated action plan:

```powershell
python -m openops_evidence review create -i evidence.redacted.json -p policy.baseline.toml --waivers waivers.toml -o review-pack
```
