# Bundle Manifest

An evidence bundle is a reviewed set of files that belong together: redacted
evidence, policy, machine report, human report, accepted-risk waivers, and
optionally a wiki-ready export. The bundle manifest records those files without embedding their
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

## Verify A Bundle

After moving or sharing artifacts, verify that the files still match the
manifest:

```powershell
python -m openops_evidence bundle verify evidence-bundle.manifest.json --base-dir . -o evidence-bundle.verification.json
python -m openops_evidence validate -i evidence-bundle.verification.json -t bundle-verification
```

Use `--fail-on-mismatch` in CI when missing or changed bundle artifacts should
fail the job.

## Create A Bundle Archive

After a manifest verifies, create a ZIP archive for ticket attachment, customer
handoff, or internal review:

```powershell
python -m openops_evidence bundle archive evidence-bundle.manifest.json --base-dir . -o evidence-bundle.zip
```

The archive command verifies the manifest first and refuses to archive missing,
changed, absolute, or path-traversing artifacts. By default, the manifest file is
included in the ZIP next to the listed artifacts. Use `--no-manifest` only when
your process stores the manifest separately.

## Sign A Manifest

Use a detached signature when a reviewed manifest should carry stronger
provenance than hashes alone. EvidenceKit signs the exact manifest bytes with
HMAC-SHA256 and writes a separate signature document. Keep the signing key in a
secret store, environment variable, or local key file; do not commit it.

```powershell
python -m openops_evidence bundle sign evidence-bundle.manifest.json --key-file .secrets/openops-bundle-signing.key --key-id ops-2026 -o evidence-bundle.signature.json
python -m openops_evidence validate -i evidence-bundle.signature.json -t bundle-signature
```

For CI systems, the default `--key-env OPENOPS_BUNDLE_SIGNING_KEY` can read the
key from an injected secret environment variable instead.

## Verify A Signature

Signature verification checks both the manifest hash recorded in the signature
document and the HMAC over the current manifest bytes:

```powershell
python -m openops_evidence bundle verify-signature evidence-bundle.manifest.json evidence-bundle.signature.json --key-file .secrets/openops-bundle-signing.key --fail-on-invalid -o evidence-bundle.signature-verification.json
```

The verification output uses the same lightweight shape as bundle verification:
`summary.status` is `pass` only when the signature document is valid, the
manifest hash matches, and the HMAC matches.

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
- `inventory` for valid inventory JSON
- `policy-coverage` for valid policy coverage JSON
- `report` for valid report JSON
- `report-history` for valid report history JSON
- `review-attestation` for valid review attestation JSON
- `executive-brief` for valid executive brief JSON
- `scorecard` for valid domain scorecard JSON
- `scope-report` for valid scope report JSON
- `service-catalog` for valid service catalog report JSON
- `runbook-report` for valid runbook coverage report JSON
- `questionnaire` for valid evidence questionnaire JSON
- `report-sarif` for SARIF report JSON
- `gate-result` for valid gate result JSON
- `badge` for Shields-compatible status badge JSON
- `bundle-manifest` for manifest JSON
- `waivers` for valid waiver JSON or TOML files
- `policy` for other TOML files
- `report-markdown` for Markdown files
- `report-html` for HTML files
- `visual` for SVG visual artifacts
- `report-prometheus` for Prometheus/OpenMetrics text output
- `json` or `artifact` as fallback

Role inference is descriptive only. It does not prove that the file is complete
or safe to share.

## Trust Notes

The manifest includes SHA-256 hashes and file sizes. It is useful for integrity
checks by itself, and a detached HMAC signature can prove that someone with the
shared signing key reviewed the exact manifest bytes.

HMAC signatures are symmetric: the same key signs and verifies. They are useful
for small teams and CI workflows, but they are not a public-key trust model. If
you need third-party verification without sharing a secret, use an external
signing system around the generated manifest and keep that policy documented.
