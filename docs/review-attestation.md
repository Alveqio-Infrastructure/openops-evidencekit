# Review Attestations

Review attestations record a human or team sign-off for a generated manifest.
They bind the statement to the manifest filename, byte size, artifact count, and
SHA-256 hash. Optional report, gate, scope, drift, and privacy summaries can be
included as review checks.

```powershell
python -m openops_evidence attest review --manifest review-pack/manifest.json --report review-pack/report.json --gate review-pack/gate-result.json --scope-report review-pack/scope-report.json --evidence-drift review-pack/evidence-drift.json --privacy-scan review-pack/privacy-scan.json --approver "Example Reviewer" --role "Operations" --statement "Reviewed generated artifacts for internal handoff." -o review-attestation.json
python -m openops_evidence validate -i review-attestation.json -t review-attestation
python -m openops_evidence attest review --manifest review-pack/manifest.json --approver "Example Reviewer" --role "Operations" --statement "Reviewed generated artifacts for internal handoff." -f markdown -o review-attestation.md
python -m openops_evidence attest review --manifest review-pack/manifest.json --approver "Example Reviewer" --role "Operations" --statement "Reviewed generated artifacts for internal handoff." -f csv -o review-attestation.csv
```

Use `--fail-on-warn` when CI should fail if any included summary needs
attention:

```powershell
python -m openops_evidence attest review --manifest review-pack/manifest.json --report review-pack/report.json --gate review-pack/gate-result.json --approver "Example Reviewer" --role "Operations" --statement "Reviewed generated artifacts." --fail-on-warn
```

Attestation status is `warn` when an included report fails, a gate fails, scope
or drift reports warn, or the privacy scan has findings. The manifest hash is
recorded regardless of that status.

This artifact is a review assertion, not a compliance certification or legal
advice. Use bundle signatures when you also need cryptographic proof that a
shared key signed the exact manifest bytes.
