# GitHub Actions Starter

`openops-evidence init --github-actions` creates starter evidence, a baseline
policy, and a GitHub Actions workflow for recurring readiness checks.

```powershell
python -m openops_evidence init ./my-readiness-check --github-actions
```

Generated files:

- `evidence.sample.json`
- `policy.baseline.toml`
- `service-catalog.sample.toml`
- `.github/workflows/openops-evidence.yml`

The workflow validates evidence, renders an inventory, evaluates the baseline
policy, creates an evidence questionnaire, evidence quality and completeness
reports, service catalog report, exposure report, firewall report, patch report, vulnerability report, software inventory report, runtime report, service-level report, policy coverage, runbook
coverage, evidence freshness, restore assurance, mail domain reports, TLS
certificate reports, access exposure reports, monitoring reports, incident readiness reports, JUnit, SARIF, badge, executive brief, risk register,
scorecard, history Markdown/SVG, Prometheus, and review-pack artifacts including
a review summary and reviewer checklist, then
enforces a configurable gate:

```yaml
openops-evidence gate report -i report.openops.json --min-score 90 --max-warnings 0 -o gate-result.json
```

Adjust the generated policy, score threshold, warning threshold, and evidence
collector inputs before using it for production checks. The generated workflow is
a starting point, not a compliance program.
