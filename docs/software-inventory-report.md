# Software Inventory Reports

`software report` turns SBOM evidence into a focused component inventory
handoff. The first built-in collector supports CycloneDX JSON.

```powershell
python -m openops_evidence collect cyclonedx-json bom.json -o software.evidence.json
python -m openops_evidence software report -i software.evidence.json -o software-inventory-report.md
python -m openops_evidence software report -i software.evidence.json -f json -o software-inventory-report.json
python -m openops_evidence validate -i software-inventory-report.json -t software-inventory-report
```

The report summarizes component count, SBOM format, CycloneDX spec version, and
metadata gaps for component versions, package URLs, and license identifiers.

## Status Semantics

- `pass`: SBOM evidence exists and components include version, package URL, and
  license metadata.
- `warn`: component metadata is incomplete and needs owner review.
- `fail`: software inventory evidence is missing or no components were recorded.

## Review Packs

Review packs automatically include `software-inventory-report.json`,
`software-inventory-report.md`, and `software-inventory-report.csv` when
evidence contains `signals.software_inventory` or policy paths reference
`signals.software_inventory`.
