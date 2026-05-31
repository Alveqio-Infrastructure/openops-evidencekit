# Evidence Model

Evidence files are JSON objects with a stable envelope:

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

Assets describe systems, repositories, monitors, containers, documents, or
endpoints.

## Signals

Signals hold observed facts. Common groups include:

- `backup`
- `monitoring`
- `runtime`
- `access`
- `tls`
- `docs`
- `mail`

Collector authors can add extension fields, but policies should use stable
paths wherever possible.
