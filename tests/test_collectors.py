import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from openops_evidence.collectors import (
    collect_borg_archives,
    collect_docker_containers,
    collect_docs_directory,
    collect_nmap_xml,
    collect_prometheus_targets,
    collect_restic_snapshots,
    collect_systemd_timers,
    collect_uptime_kuma_export,
)


class CollectorTests(unittest.TestCase):
    def test_collect_restic_snapshots(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "snapshots.json"
            path.write_text(
                """
[
  {"time": "2026-05-29T22:10:00+00:00", "hostname": "old", "paths": ["/etc"]},
  {"time": "2026-05-30T22:10:00+00:00", "hostname": "new", "paths": ["/srv"]}
]
""".strip(),
                encoding="utf-8",
            )
            evidence = collect_restic_snapshots(str(path))
        self.assertEqual(evidence["signals"]["backup"]["tool"], "restic")
        self.assertEqual(evidence["signals"]["backup"]["snapshot_count"], 2)
        self.assertEqual(evidence["signals"]["backup"]["last_success_at"], "2026-05-30T22:10:00+00:00")
        self.assertEqual(evidence["signals"]["backup"]["protected_hosts"], ["new", "old"])

    def test_collect_uptime_kuma_export(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "kuma.json"
            path.write_text(
                """
{
  "monitorList": [
    {"id": 1, "name": "Web", "type": "http", "url": "https://example.invalid", "active": true, "notificationIDList": [1]},
    {"id": 2, "name": "Old", "type": "http", "url": "https://old.example.invalid", "active": false}
  ]
}
""".strip(),
                encoding="utf-8",
            )
            evidence = collect_uptime_kuma_export(str(path))
        self.assertEqual(evidence["signals"]["monitoring"]["system"], "uptime-kuma")
        self.assertEqual(evidence["signals"]["monitoring"]["targets"], 1)
        self.assertEqual(evidence["signals"]["monitoring"]["monitors_total"], 2)
        self.assertEqual(evidence["signals"]["monitoring"]["alert_channels"], ["1"])

    def test_collect_borg_archives(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "borg.json"
            path.write_text(
                """
{
  "repository": {"id": "repo-1"},
  "archives": [
    {"name": "srv-2026-05-29", "time": "2026-05-29T22:00:00+00:00", "hostname": "srv-01"},
    {"name": "srv-2026-05-30", "time": "2026-05-30T22:00:00+00:00", "hostname": "srv-01"}
  ]
}
""".strip(),
                encoding="utf-8",
            )
            evidence = collect_borg_archives(str(path))
        self.assertEqual(evidence["signals"]["backup"]["tool"], "borg")
        self.assertEqual(evidence["signals"]["backup"]["archive_count"], 2)
        self.assertEqual(evidence["signals"]["backup"]["last_success_at"], "2026-05-30T22:00:00+00:00")
        self.assertEqual(evidence["signals"]["backup"]["protected_hosts"], ["srv-01"])

    def test_collect_prometheus_targets(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "targets.json"
            path.write_text(
                """
{
  "data": {
    "activeTargets": [
      {"labels": {"instance": "web:9100"}, "scrapeUrl": "http://web:9100/metrics", "health": "up"},
      {"labels": {"instance": "db:9100"}, "scrapeUrl": "http://db:9100/metrics", "health": "down"}
    ]
  }
}
""".strip(),
                encoding="utf-8",
            )
            evidence = collect_prometheus_targets(str(path))
        self.assertEqual(evidence["signals"]["monitoring"]["system"], "prometheus")
        self.assertEqual(evidence["signals"]["monitoring"]["targets"], 1)
        self.assertEqual(evidence["signals"]["monitoring"]["targets_down"], 1)
        self.assertEqual(evidence["signals"]["monitoring"]["down_targets"], ["db:9100"])

    def test_collect_nmap_xml(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "nmap.xml"
            path.write_text(
                """
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="203.0.113.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
      <port protocol="tcp" portid="5432"><state state="closed"/><service name="postgresql"/></port>
    </ports>
  </host>
</nmaprun>
""".strip(),
                encoding="utf-8",
            )
            evidence = collect_nmap_xml(str(path))
        exposure = evidence["signals"]["exposure"]
        self.assertEqual(exposure["scanner"], "nmap")
        self.assertEqual(exposure["hosts_total"], 1)
        self.assertEqual(exposure["open_ports_total"], 2)
        self.assertEqual(exposure["risky_ports"], ["203.0.113.10:22/tcp"])

    def test_collect_systemd_timers(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "timers.json"
            path.write_text(
                """
[
  {"unit": "backup.timer", "active": "active", "sub": "waiting"},
  {"unit": "old.timer", "active": "failed", "sub": "failed"}
]
""".strip(),
                encoding="utf-8",
            )
            evidence = collect_systemd_timers(str(path))
        systemd = evidence["signals"]["runtime"]["systemd"]
        self.assertEqual(systemd["timers_total"], 2)
        self.assertEqual(systemd["timers_active"], 1)
        self.assertEqual(systemd["timers_failed"], 1)
        self.assertEqual(systemd["failed_timers"], ["old.timer"])

    def test_collect_docker_containers_from_json_lines(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "containers.jsonl"
            path.write_text(
                """
{"Names":"web","Image":"nginx:stable","State":"running","RestartPolicy":"unless-stopped"}
{"Names":"worker","Image":"busybox:latest","Status":"Exited (0) 1 hour ago","RestartPolicy":"no"}
{"Names":"api","Image":"example/api:1","Status":"Up 2 hours","RestartPolicy":"no"}
""".strip(),
                encoding="utf-8",
            )
            evidence = collect_docker_containers(str(path))
        docker = evidence["signals"]["runtime"]["docker"]
        self.assertEqual(docker["containers_total"], 3)
        self.assertEqual(docker["containers_running"], 2)
        self.assertEqual(docker["containers_exited"], 1)
        self.assertEqual(docker["restart_policy_missing"], ["api"])

    def test_collect_docs_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "runbooks").mkdir()
            inventory = root / "inventory.md"
            runbook = root / "runbooks" / "backup-restore.md"
            stale = root / "runbooks" / "old.md"
            inventory.write_text("# Inventory\n", encoding="utf-8")
            runbook.write_text("# Backup Restore\n", encoding="utf-8")
            stale.write_text("# Old\n", encoding="utf-8")
            old_timestamp = (datetime.now(UTC) - timedelta(days=120)).timestamp()
            os.utime(stale, (old_timestamp, old_timestamp))

            evidence = collect_docs_directory(
                str(root),
                required=["inventory.md", "runbooks/backup-restore.md", "runbooks/missing.md"],
                max_age_days=90,
            )

        docs = evidence["signals"]["docs"]
        self.assertEqual(docs["documents_total"], 3)
        self.assertEqual(docs["required_total"], 3)
        self.assertEqual(docs["required_present"], 2)
        self.assertEqual(docs["missing_required"], ["runbooks/missing.md"])
        self.assertEqual(docs["stale_documents"], ["runbooks/old.md"])
        self.assertEqual(
            [item["path"] for item in docs["runbooks"]],
            ["runbooks/backup-restore.md", "runbooks/old.md"],
        )
        self.assertIsNotNone(docs["inventory_updated_at"])

    def test_collect_docs_rejects_required_paths_outside_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(ValueError):
                collect_docs_directory(temp_dir, required=["../outside.md"])


if __name__ == "__main__":
    unittest.main()
