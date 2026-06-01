import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main


ROOT = Path(__file__).resolve().parents[1]


class ReviewPackTests(unittest.TestCase):
    def test_review_create_outputs_complete_pack(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pack = Path(temp_dir) / "review-pack"

            self.assertEqual(
                main(
                    [
                        "review",
                        "create",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-p",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "--min-score",
                        "100",
                        "--max-warnings",
                        "0",
                        "-o",
                        str(pack),
                    ]
                ),
                0,
            )

            expected = [
                "README.md",
                "action-plan.csv",
                "action-plan.json",
                "action-plan.md",
                "executive-brief.json",
                "executive-brief.md",
                "gate-result.json",
                "gate-result.md",
                "inventory.csv",
                "inventory.json",
                "inventory.md",
                "manifest.json",
                "policy-matrix.csv",
                "policy-matrix.json",
                "policy-matrix.md",
                "privacy-scan.json",
                "privacy-scan.md",
                "readiness-badge.json",
                "report.junit.xml",
                "report.json",
                "report.md",
                "report.prom",
                "report.sarif.json",
            ]
            for filename in expected:
                self.assertTrue((pack / filename).is_file(), filename)

            self.assertEqual(main(["validate", "-i", str(pack / "report.json"), "-t", "report"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "inventory.json"), "-t", "inventory"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "policy-matrix.json"), "-t", "policy-matrix"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "executive-brief.json"), "-t", "executive-brief"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "action-plan.json"), "-t", "action-plan"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "readiness-badge.json"), "-t", "badge"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "gate-result.json"), "-t", "gate-result"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "privacy-scan.json"), "-t", "privacy-scan"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "manifest.json"), "-t", "bundle"]), 0)

            manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
            readme = (pack / "README.md").read_text(encoding="utf-8")
            self.assertEqual(manifest["metadata"]["artifact_count"], len(expected) - 1)
            self.assertIn("does not include raw evidence by default", readme)
            self.assertIn("executive-brief.md", readme)
            self.assertIn("privacy-scan.md", readme)

    def test_review_create_can_fail_on_gate_after_writing_pack(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            policy = temp / "failing-policy.toml"
            pack = temp / "review-pack"
            policy.write_text(
                """
[[checks]]
id = "missing_required_signal"
title = "Required signal exists"
path = "signals.not_present"
operator = "exists"
severity = "high"
required = true
remediation = "Add the missing operational signal to evidence."
""".lstrip(),
                encoding="utf-8",
            )

            self.assertEqual(
                main(
                    [
                        "review",
                        "create",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-p",
                        str(policy),
                        "--fail-on-gate",
                        "-o",
                        str(pack),
                    ]
                ),
                1,
            )

            gate = json.loads((pack / "gate-result.json").read_text(encoding="utf-8"))
            self.assertEqual(gate["summary"]["status"], "fail")
            self.assertTrue((pack / "manifest.json").is_file())


if __name__ == "__main__":
    unittest.main()
