# CI Gates

Gates turn generated artifacts into explicit pass/fail conditions for CI,
scheduled reviews, and customer-specific readiness thresholds.

## Report Gate

```powershell
python -m openops_evidence gate report -i report.local.json -o gate-result.json
python -m openops_evidence gate report -i report.local.json --min-score 90 --max-warnings 0 -o gate-result.json
python -m openops_evidence gate report -i report.local.json --min-score 90 --max-critical 0 -f markdown -o gate-result.md
python -m openops_evidence validate -i gate-result.json -t gate-result
```

By default, the gate requires the source report status to be `pass`. Use
`--ignore-report-status` only when a pipeline intentionally gates on custom
thresholds instead of the policy's required-failure semantics.

Supported thresholds:

| Option | Meaning |
| --- | --- |
| `--min-score` | Minimum `summary.score` from the report. |
| `--max-failed` | Maximum required failed checks. |
| `--max-warnings` | Maximum warning checks. |
| `--max-critical` | Maximum critical failed or warning findings. |
| `--max-high` | Maximum high failed or warning findings. |

## Exit Code

`gate report` returns `0` when all configured conditions pass and `1` when one
or more conditions fail. Invalid input returns `2`.

The generated JSON can be stored with reports and bundle manifests as evidence
of the acceptance rule used for a specific review.
