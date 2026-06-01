# Evidence Schema

The schema is intentionally simple in the alpha release. Evidence files are JSON
objects with these top-level keys:

```json
{
  "schema_version": "0.1",
  "generated_at": "2026-05-31T10:00:00+00:00",
  "metadata": {},
  "assets": [],
  "signals": {}
}
```

## Assets

Assets describe systems or endpoints:

```json
{
  "id": "web-01",
  "type": "host",
  "hostname": "web-01.example.invalid",
  "roles": ["web"],
  "tags": ["linux"]
}
```

## Signals

Signals contain observed facts. Common signal groups:

- `backup`
- `monitoring`
- `runtime`
- `access`
- `tls`
- `docs`
- `mail`

Collectors may add new signal groups. Policies should use stable paths whenever
possible.

Documentation collectors use `signals.docs.documents`,
`signals.docs.missing_required`, `signals.docs.stale_documents`,
`signals.docs.inventory_updated_at`, and `signals.docs.runbooks`.

## Validation

Run:

```powershell
python -m openops_evidence validate -i evidence.local.json
```

Validation checks the required envelope and basic asset shape. It does not prove
that a signal is true; it only checks that the file can be interpreted.

The validator accepts `schema_version` `0.1` and patch-compatible versions such
as `0.1.1`. Unknown major/minor versions are rejected so automation can fail
closed when an artifact may require a newer parser.

The repository also includes a draft 2020-12 JSON Schema at
`schemas/evidence.schema.json`.
