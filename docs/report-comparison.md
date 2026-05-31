# Report Comparison

Readiness evidence becomes more useful when teams can compare it over time. The
`compare` command compares two report JSON files and highlights regressions,
improvements, added checks, and removed checks.

## Compare Reports

```powershell
python -m openops_evidence compare --base previous-report.json --current current-report.json -o report.comparison.json
python -m openops_evidence validate -i report.comparison.json -t comparison
```

Render a human-readable diff:

```powershell
python -m openops_evidence compare --base previous-report.json --current current-report.json -f markdown -o report.comparison.md
```

## CI Guardrail

Use `--fail-on-regression` when a pipeline should fail if an existing check
changes from `pass` to `warn` or `fail`, or from `warn` to `fail`.

```powershell
python -m openops_evidence compare --base baseline-report.json --current report.local.json --fail-on-regression
```

Added failing checks are reported under `added`. They are not treated as
regressions because they did not exist in the base report.

## Output

Comparison JSON contains:

- `summary` with score delta and change counts
- `regressions`
- `improvements`
- `neutral_changes`
- `added`
- `removed`

The comparison is operational evidence. Review the source reports before using
the diff in external communication.
