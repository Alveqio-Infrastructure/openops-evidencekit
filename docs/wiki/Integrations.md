# Integrations

Supported offline collectors:

- restic snapshots
- Borg archives
- Uptime Kuma exports
- Prometheus target health
- systemd timer exports
- Docker container JSON or JSON lines
- local documentation directories
- TLS endpoint inspection

Collectors should collect facts, not secrets. Prefer exported JSON, timestamps,
counts, and health states over raw logs or full configuration dumps.

Candidate future integrations include BookStack page freshness and SSH access
configuration evidence.
