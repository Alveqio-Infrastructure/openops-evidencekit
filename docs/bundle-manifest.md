# Bundle Manifest

An evidence bundle is a reviewed set of files that belong together: redacted
evidence, policy, machine report, human report, and optionally a wiki-ready
export. The bundle manifest records those files without embedding their
contents.

The manifest helps with:

- proving which files were reviewed
- detecting accidental changes after review
- attaching evidence to tickets or wiki pages without losing file context
- handing a compact artifact list to downstream automation

## Create A Manifest

```powershell
python -m openops_evidence bundle manifest evidence.redacted.json report.local.json report.local.md readiness.bookstack.md -o evidence-bundle.manifest.json
```

By default, the manifest stores only filenames. This avoids leaking absolute
local paths such as user names, drive letters, or internal directory names.

When all artifacts live below one directory and relative paths are useful, pass
`--base-dir`:

```powershell
python -m openops_evidence bundle manifest out/evidence.redacted.json out/report.local.md --base-dir out -o out/manifest.json
```

## Validate A Manifest

```powershell
python -m openops_evidence validate -i evidence-bundle.manifest.json -t bundle
```

## Manifest Shape

```json
{
  "schema_version": "0.1",
  "generated_at": "2026-05-31T10:00:00+00:00",
  "metadata": {
    "name": "openops-evidence-bundle",
    "created_by": "openops-evidencekit",
    "artifact_count": 2
  },
  "artifacts": [
    {
      "path": "evidence.redacted.json",
      "filename": "evidence.redacted.json",
      "role": "evidence",
      "media_type": "application/json",
      "size_bytes": 4096,
      "sha256": "..."
    }
  ]
}
```

## Roles

EvidenceKit infers a simple role for each artifact:

- `evidence` for valid evidence JSON
- `report` for valid report JSON
- `bundle-manifest` for manifest JSON
- `policy` for TOML files
- `report-markdown` for Markdown files
- `report-html` for HTML files
- `json` or `artifact` as fallback

Role inference is descriptive only. It does not prove that the file is complete
or safe to share.

## Trust Notes

The manifest includes SHA-256 hashes and file sizes. It is useful for integrity
checks, but it is not a signature. A future release may add signing support for
teams that need stronger provenance guarantees.
