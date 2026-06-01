# OpenOps EvidenceKit

OpenOps EvidenceKit is a vendor-neutral toolkit for infrastructure operations
evidence. It helps small teams collect facts, check readiness rules, redact
sensitive data, and render reports that can be reviewed by humans.

## Useful Links

- Getting started: `Getting-Started.md`
- Evidence model: `Evidence-Model.md`
- Policy authoring: `Policy-Authoring.md`
- Policy packs: repository `docs/policy-packs.md`
- Integrations: `Integrations.md`
- Privacy and sharing: `Privacy-And-Sharing.md`
- Maintainer guide: `Maintainer-Guide.md`

## Core Workflow

1. Collect evidence from supported systems or fixtures.
2. Merge evidence from multiple sources.
3. Redact evidence before it leaves the owning team.
4. Evaluate evidence with a deterministic policy.
5. Apply CI gates for score or finding thresholds.
6. Render a report for review, tickets, or documentation.
7. Compare reports over time.
8. Create a bundle manifest for the shared artifacts.
