# GitHub Actions Starter

`openops-evidence init --github-actions` creates starter evidence, a baseline
policy, and a GitHub Actions workflow for recurring readiness checks.

```powershell
python -m openops_evidence init ./my-readiness-check --github-actions
```

Generated files:

- `evidence.sample.json`
- `policy.baseline.toml`
- `.github/workflows/openops-evidence.yml`

The workflow validates evidence, renders an inventory, evaluates the baseline
policy, creates Markdown, JUnit, SARIF, badge, executive brief, scorecard,
history, Prometheus, and review-pack artifacts, then enforces a configurable gate:

```yaml
openops-evidence gate report -i report.openops.json --min-score 90 --max-warnings 0 -o gate-result.json
```

Adjust the generated policy, score threshold, warning threshold, and evidence
collector inputs before using it for production checks. The generated workflow is
a starting point, not a compliance program.
