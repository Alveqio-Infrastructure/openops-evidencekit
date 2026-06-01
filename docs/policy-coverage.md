# Policy Coverage

`coverage report` compares evidence signal domains with policy check paths.
It answers two practical questions:

- Which collected evidence domains are not reviewed by the policy?
- Which policy domains expect evidence that is missing from the input?

```powershell
python -m openops_evidence coverage report -i evidence.redacted.json -p policy.baseline.toml -o policy-coverage.md
python -m openops_evidence coverage report -i evidence.redacted.json -p policy.baseline.toml -f json -o policy-coverage.json
python -m openops_evidence coverage report -i evidence.redacted.json -p policy.baseline.toml -f csv -o policy-coverage.csv
```

The command maps `signals.backup.last_success_at` to the `backup` domain,
`signals.monitoring.targets` to `monitoring`, and so on.

Domain statuses:

- `covered`: evidence exists and at least one policy check evaluates the domain.
- `unreviewed_evidence`: evidence exists, but no policy check evaluates it.
- `missing_evidence`: a policy check expects the domain, but the evidence file
  does not include it.

Validate JSON output with:

```powershell
python -m openops_evidence validate -i policy-coverage.json -t policy-coverage
```

Review packs include `policy-coverage.json`, `policy-coverage.md`, and
`policy-coverage.csv` automatically.
