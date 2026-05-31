import tempfile
import unittest
from pathlib import Path

from openops_evidence.collectors import collect_restic_snapshots


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


if __name__ == "__main__":
    unittest.main()
