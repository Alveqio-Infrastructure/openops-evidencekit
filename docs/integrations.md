# Integration Principles

Integrations should collect facts, not secrets.

## Collector Rules

- Never read private keys.
- Never print bearer tokens or API keys.
- Prefer metadata and timestamps over raw logs.
- Keep customer identifiers out of fixtures.
- Support offline fixture-based tests.
- Document required permissions.

## Supported Offline Collectors

| Area | Integration | Evidence examples |
| --- | --- | --- |
| Backup | restic | last successful snapshot, repository count, protected hosts and paths |
| Backup | Borg | archive recency, repository identifier, protected hosts |
| Monitoring | Prometheus | target count, up/down target count, down target list |
| Monitoring | Uptime Kuma | monitor count, enabled target count, alert channel references |
| Exposure | Nmap XML | hosts, open ports, service names, risky public services |
| Firewall | UFW | status, default incoming policy, allow rules |
| Patching | apt | pending packages, security updates |
| Vulnerability | Trivy JSON | scanner targets, severity counts, finding package and fixed-version fields |
| Runtime | systemd | enabled timers, failed units |
| Runtime | Docker | running containers, restart policies |
| Documentation | local directory | required files, stale files, runbook and inventory timestamps |

## CI Outputs

Run `openops-evidence init --github-actions` to generate a starter workflow that
produces the common CI artifacts below.

| Output | Command | Use |
| --- | --- | --- |
| Evidence scaffold | `openops-evidence scaffold evidence policy.toml -o evidence.scaffold.json` | Create an editable starter Evidence JSON file from expected policy signal paths. |
| Evidence questionnaire | `openops-evidence questionnaire policy policy.toml -o evidence-questionnaire.md` | Send a concrete evidence request list before a readiness review starts. |
| Inventory JSON | `openops-evidence inventory evidence -i evidence.json -f json -o inventory.json` | Publish asset and signal-domain inventory from evidence. |
| Evidence quality | `openops-evidence evidence quality -i evidence.json -o quality-report.md` | Catch duplicate assets, missing metadata, empty signals, and common evidence hygiene gaps. |
| Evidence completeness | `openops-evidence evidence completeness -i evidence.json -p policy.toml -o completeness-report.md` | Show which policy evidence paths are present or still missing. |
| Freshness report | `openops-evidence freshness report -i evidence.json --max-age-days 30 -o freshness-report.md` | Show stale, future, and invalid timestamp-like evidence fields before review. |
| Restore assurance | `openops-evidence restore report -i evidence.json --max-drill-age-days 90 -o restore-report.md` | Show backup recency and restore drill proof before review. |
| Mail domain report | `openops-evidence mail report -i evidence.json -o mail-report.md` | Show SPF, DKIM, and DMARC evidence before review. |
| TLS certificate report | `openops-evidence tls report -i evidence.json -o tls-report.md` | Show certificate expiry and renewal risk before review. |
| Access exposure | `openops-evidence access report -i evidence.json -o access-report.md` | Show public SSH, MFA, and admin entrypoint evidence before review. |
| Monitoring report | `openops-evidence monitoring report -i evidence.json -o monitoring-report.md` | Show target health, down targets, alert channels, and alert-test freshness before review. |
| Exposure report | `openops-evidence exposure report -i evidence.json -o exposure-report.md` | Show open ports and risky public services before review. |
| Firewall report | `openops-evidence firewall report -i evidence.json -o firewall-report.md` | Show firewall status, default policy, and public administrative allow rules before review. |
| Patch report | `openops-evidence patch report -i evidence.json -o patch-report.md` | Show pending package updates, security updates, and reboot state before review. |
| Vulnerability report | `openops-evidence vulnerability report -i evidence.json -o vulnerability-report.md` | Show critical, high, non-critical, and fixable vulnerability findings before review. |
| Runtime report | `openops-evidence runtime report -i evidence.json -o runtime-report.md` | Show stopped containers, missing restart policies, and failed systemd timers. |
| Service-level report | `openops-evidence service-level report -i evidence.json -c service-catalog.toml -o service-level-report.md` | Show per-service SLO targets, observed availability, and missing service-level evidence. |
| Incident readiness | `openops-evidence incident report -i evidence.json -c service-catalog.toml -o incident-report.md` | Show escalation contacts, incident runbooks, alerts, restore proof, and emergency access readiness before review. |
| Scope report | `openops-evidence scope report -i evidence.json -s scope.toml -o scope-report.md` | Show in-scope, out-of-scope, missing, and unclassified evidence boundaries. |
| Service catalog | `openops-evidence catalog report -i evidence.json -c service-catalog.toml -o service-catalog.md` | Check service owners, criticality, assets, evidence domains, and runbooks against collected evidence. |
| Runbook coverage | `openops-evidence runbook report -i evidence.json -c service-catalog.toml --max-age-days 90 -o runbook-report.md` | Check required runbooks for presence, freshness, service references, and unreferenced documents. |
| Evidence drift | `openops-evidence evidence diff --base previous.json --current evidence.json -o evidence-drift.json` | Detect asset and signal-domain drift between recurring evidence runs. |
| Policy coverage | `openops-evidence coverage report -i evidence.json -p policy.toml -o policy-coverage.md` | Find evidence domains that are not covered by policy checks and policy domains that are missing evidence. |
| Gate JSON | `openops-evidence gate report -i report.json --min-score 90 -o gate-result.json` | Enforce readiness thresholds in CI. |
| Review attestation | `openops-evidence attest review --manifest review-pack/manifest.json --approver "Reviewer" --role "Operations" --statement "Reviewed." -o review-attestation.json` | Record a review sign-off bound to a manifest hash. |
| Badge JSON | `openops-evidence badge report -i report.json -o readiness-badge.json` | Publish a compact Shields-compatible readiness status. |
| Executive brief | `openops-evidence brief report -i report.json -o executive-brief.md` | Share a concise stakeholder summary. |
| Risk register | `openops-evidence risk register -i report.json --waivers waivers.toml -o risk-register.json` | Track open, accepted, expired, and closed operational risks. |
| Domain scorecard | `openops-evidence scorecard report -i report.json -o scorecard.md` | Summarize readiness by operational evidence area. |
| History JSON | `openops-evidence history append -i report.json -o readiness-history.json` | Track score and finding changes across recurring reviews. |
| History SVG | `openops-evidence history render -i readiness-history.json -f svg -o readiness-history.svg` | Publish a compact trend graphic for README, wiki, or portal dashboards. |
| Review pack | `openops-evidence review create -i evidence.json -p policy.toml -o review-pack --archive review-pack.zip` | Generate a complete handoff folder and ZIP archive with browser index, review summary, reviewer checklist, quality report, completeness report, restore assurance, mail report, TLS certificate report, access exposure, monitoring report, runtime report, service-level report, incident readiness, report, brief, inventory, gate, badge, action plan, privacy scan, and manifest. |
| JUnit XML | `openops-evidence report -i report.json -f junit -o report.junit.xml` | Publish readiness checks as CI test results. |
| SARIF JSON | `openops-evidence report -i report.json -f sarif -o report.sarif.json` | Import findings into SARIF-aware review tools. |
| Prometheus text | `openops-evidence report -i report.json -f prometheus -o report.prom` | Export score, status, and check counts into monitoring pipelines. |
| Markdown tickets | `openops-evidence ticket export -i action-plan.json -o action-tickets` | Import remediation work into issue trackers or service desks. |

## Candidate Integrations

| Area | Integration | Evidence examples |
| --- | --- | --- |
| Documentation | BookStack | page freshness and required runbook pages from the BookStack API |
| Access | SSH config | public exposure marker, access method evidence |

## AI-Assisted Integrations

AI can help summarize reports or draft remediation text, but AI output must not
change deterministic check results. A future optional assistant layer should
read report JSON and produce commentary that is clearly marked as advisory.
