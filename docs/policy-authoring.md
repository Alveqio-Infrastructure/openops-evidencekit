# Policy Authoring

Policies are TOML files with one or more `[[checks]]` tables.

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

## Path Queries

Supported paths:

```text
signals.backup.last_success_at
signals.tls.certificates[*].not_after
assets[0].hostname
```

## Operators

- `exists`
- `missing`
- `equals`
- `not_equals`
- `contains`
- `one_of`
- `at_least`
- `at_most`
- `matches`
- `within_days`
- `after_now`
