# Policy Authoring

Policies are TOML files with one or more `[[checks]]` tables.

Bundled policy packs can be listed and exported with:

```powershell
python -m openops_evidence policy list
python -m openops_evidence policy show baseline -o policy.baseline.toml
python -m openops_evidence policy validate policy.baseline.toml
```

See [policy-packs.md](policy-packs.md) for pack names and workflow guidance.

## Fields

- `id`: stable machine-readable check ID.
- `title`: human-readable finding title.
- `path`: dotted evidence path.
- `operator`: comparison operator.
- `value`: optional expected value.
- `severity`: `critical`, `high`, `medium`, or `low`.
- `required`: required failures fail the report; optional failures warn.
- `mode`: `any`, `all`, or `none` for multi-value paths.
- `remediation`: practical next step.

## Validation

Run validation before using a custom policy in CI:

```powershell
python -m openops_evidence policy validate policy.baseline.toml
```

Validation catches missing fields, duplicate check IDs, unsupported operators,
unsupported severities, unsupported modes, wrong `required` types, and missing
or malformed operator values.

## Path Queries

Supported paths:

```text
signals.backup.last_success_at
signals.tls.certificates[*].not_after
assets[0].hostname
```

## Operators

List the stable operator catalog from the CLI:

```powershell
python -m openops_evidence policy operators
python -m openops_evidence policy operators -f json
```

Supported operators:

| Operator | Value | Semantics |
| --- | --- | --- |
| `exists` | none | Passes when at least one selected value is not null and not an empty string. |
| `missing` | none | Passes when the path selects no values. |
| `equals` | required | Passes when a selected value is exactly equal to `value`. |
| `not_equals` | required | Passes when a selected value is not exactly equal to `value`. |
| `contains` | required | Passes when `value` is contained in a selected string, list, or object key set. |
| `one_of` | non-empty list | Passes when a selected value is a member of the configured `value` list. |
| `at_least` | numeric | Passes when a selected value is numerically greater than or equal to `value`. |
| `at_most` | numeric | Passes when a selected value is numerically less than or equal to `value`. |
| `matches` | safe regex | Passes when a safe regular expression matches the selected value converted to text. |
| `within_days` | numeric days | Passes when a selected ISO 8601 timestamp is no older than `value` days. |
| `after_now` | none | Passes when a selected ISO 8601 timestamp is strictly in the future. |

For multi-value paths, `mode = "any"` passes when any selected value passes,
`mode = "all"` requires every selected value to pass, and `mode = "none"`
passes when no selected value passes. Empty selections fail for every operator
except `missing`.

## Policy Packs

The package includes bundled policy packs, and the `examples/` directory
contains matching copies for browsing:

- `policy.baseline.toml`: broad operational readiness baseline.
- `policy.security-minimum.toml`: small security-focused baseline.
- `policy.documentation.toml`: documentation readiness baseline.
