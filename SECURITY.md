# Security Policy

OpenOps EvidenceKit handles operational evidence that may contain sensitive
infrastructure details. Treat all raw evidence as confidential unless it has
been reviewed and redacted.

## Reporting Vulnerabilities

Please report suspected vulnerabilities through GitHub Security Advisories when
available. If that is not possible, open an issue with a minimal description and
avoid posting secrets, tokens, real customer data, internal hostnames, private
IP addresses, or exploitable details.

## Data Handling Expectations

- Do not commit real infrastructure evidence to this repository.
- Run `openops-evidence redact` before sharing evidence outside your team.
- Prefer fixtures using `.invalid` domains and synthetic data.
- Collectors should not read private key material or secret stores.
- New integrations must document what they collect and what they never collect.

## Supported Versions

The project is in early alpha. Security fixes target the latest released version.
Maintainer security responsibilities are documented in [GOVERNANCE.md](GOVERNANCE.md).
