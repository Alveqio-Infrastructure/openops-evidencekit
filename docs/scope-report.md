# Scope Reports

Scope reports compare collected evidence with a declared review scope. They make
the handoff explicit: what is in scope, what is out of scope, what evidence was
collected anyway, and which expected assets or domains are missing.

```powershell
python -m openops_evidence scope validate examples/scope.sample.toml
python -m openops_evidence scope report -i evidence.local.json -s examples/scope.sample.toml -o scope-report.md
python -m openops_evidence scope report -i evidence.local.json -s examples/scope.sample.toml -f json -o scope-report.json
python -m openops_evidence scope report -i evidence.local.json -s examples/scope.sample.toml -f csv -o scope-report.csv
```

Use `--fail-on-warn` when CI should fail if the evidence contains unclassified
items, out-of-scope items, or missing required in-scope items:

```powershell
python -m openops_evidence scope report -i evidence.local.json -s examples/scope.sample.toml --fail-on-warn -o scope-report.md
```

Scope files can be TOML or JSON. A minimal TOML file looks like this:

```toml
[metadata]
name = "Production readiness scope"
owner = "Operations"

[[assets]]
id = "web-01"
status = "in_scope"
owner = "platform"
reason = "Production web service."

[[domains]]
name = "backup"
status = "in_scope"
required = true
owner = "backup"
reason = "Backup and restore proof is required."
```

Supported scope statuses are:

- `in_scope`: expected in the review.
- `out_of_scope`: intentionally excluded, but still visible if evidence was collected.

The generated report uses these statuses:

- `present_in_scope`: evidence exists and the scope declares it as included.
- `present_out_of_scope`: evidence exists even though the scope declares it as excluded.
- `missing_in_scope`: a required in-scope item is missing from evidence.
- `missing_optional`: an optional in-scope domain is missing from evidence.
- `out_of_scope_not_seen`: excluded item was not present in collected evidence.
- `unclassified_evidence`: evidence exists without a matching scope declaration.
