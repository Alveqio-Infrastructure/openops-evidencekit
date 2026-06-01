# Evidence Inventory

`openops-evidence inventory evidence` turns evidence JSON into a compact asset
and signal-domain inventory. It is useful for wiki pages, customer handoff,
readiness reviews, and spreadsheets where raw JSON would be hard to scan.

```powershell
python -m openops_evidence inventory evidence -i evidence.local.json -o inventory.md
python -m openops_evidence inventory evidence -i evidence.local.json -f json -o inventory.json
python -m openops_evidence inventory evidence -i evidence.local.json -f csv -o inventory.csv
python -m openops_evidence validate -i inventory.json -t inventory
```

The inventory records:

- assets with ID, type, hostname, roles, and tags
- signal domains such as backup, monitoring, TLS, mail, access, and docs
- simple summary counts for asset types, roles, tags, hostnames, and signal domains

The command does not infer ownership or criticality. Keep those fields in source
evidence, policy, or your service catalog when they are needed.
