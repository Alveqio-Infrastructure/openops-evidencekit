# OpenOps DNS Hygiene Report

- Generated: `2026-06-09T06:28:20.330121+00:00`
- Source evidence: `2026-05-31T10:00:00+00:00`
- Status: **PASS**
- Domains: **1**
- Passed: **1**
- Warnings: **0**
- Failed: **0**

## Domains

| Domain | Status | Address records | Nameservers | CAA | DNSSEC | Reason | Recommended action |
| --- | --- | ---: | ---: | --- | --- | --- | --- |
| `example.invalid` | pass | 2 | 2 | yes | yes | Address records, nameservers, CAA, and DNSSEC evidence are present\. | Keep DNS evidence current and review it after provider or certificate authority changes\. |

## Interpretation

- `pass`: address records, nameservers, CAA, and DNSSEC evidence are present.
- `warn`: core DNS resolution evidence exists, but CAA or DNSSEC evidence is missing.
- `fail`: address records or nameserver evidence is missing or the domain entry is invalid.
