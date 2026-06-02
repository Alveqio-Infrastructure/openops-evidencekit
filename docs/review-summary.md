# Review Summaries

Review summaries are generated inside review packs as `review-summary.json` and
`review-summary.md`. They condense the technical report, gate result, risk
register, evidence freshness, privacy scan, scope, drift, service catalog, and
runbook signals into one handoff decision.

Decision statuses are:

- `pass`: ready for handoff
- `warn`: review required before sign-off
- `fail`: blocked by gate, report, open risks, or privacy findings

The Markdown version is meant to be the first file a reviewer reads. It points
to the specific artifact that needs attention, such as `risk-register.md`,
`privacy-scan.md`, `freshness-report.md`, or service/runbook reports.

Review summaries are deliberately deterministic. They summarize generated
artifacts and do not replace human approval or `attest review` sign-off.
