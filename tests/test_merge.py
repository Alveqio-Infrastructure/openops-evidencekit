import unittest

from openops_evidence.merge import merge_evidence


class MergeTests(unittest.TestCase):
    def test_merges_assets_by_id_and_signals(self):
        merged = merge_evidence(
            [
                {
                    "assets": [{"id": "web-01", "type": "host", "roles": ["web"]}],
                    "signals": {"backup": {"tool": "restic"}},
                },
                {
                    "assets": [{"id": "web-01", "type": "host", "tags": ["linux"]}],
                    "signals": {"monitoring": {"targets": 2}},
                },
            ]
        )
        self.assertEqual(len(merged["assets"]), 1)
        self.assertEqual(merged["assets"][0]["roles"], ["web"])
        self.assertEqual(merged["assets"][0]["tags"], ["linux"])
        self.assertEqual(merged["signals"]["backup"]["tool"], "restic")
        self.assertEqual(merged["signals"]["monitoring"]["targets"], 2)


if __name__ == "__main__":
    unittest.main()
