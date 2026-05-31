import tempfile
import unittest
from pathlib import Path

from openops_evidence.collectors import collect_restic_snapshots, collect_uptime_kuma_export


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


if __name__ == "__main__":
    unittest.main()
