# Policy Authoring

Policies are TOML files with one or more `[[checks]]` tables.

Bundled policy packs can be listed and exported with:

```powershell
python -m openops_evidence policy list
python -m openops_evidence policy show baseline -o policy.baseline.toml
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

## Policy Packs

The package includes bundled policy packs, and the `examples/` directory
contains matching copies for browsing:

- `policy.baseline.toml`: broad operational readiness baseline.
- `policy.security-minimum.toml`: small security-focused baseline.
- `policy.documentation.toml`: documentation readiness baseline.
