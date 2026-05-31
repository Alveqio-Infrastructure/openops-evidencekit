import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main


ROOT = Path(__file__).resolve().parents[1]


class CliWorkflowTests(unittest.TestCase):
    def test_end_to_end_readiness_workflow(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            evidence = temp / "evidence.json"
            restic = temp / "restic.json"
            merged = temp / "merged.json"
            report = temp / "report.json"
            markdown = temp / "report.md"
            bookstack = temp / "bookstack.md"
            manifest = temp / "manifest.json"

            self.assertEqual(
                main(["collect", "fixture", str(ROOT / "examples" / "evidence.sample.json"), "-o", str(evidence)]),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "collect",
                        "restic-snapshots",
                        str(ROOT / "examples" / "restic.snapshots.sample.json"),
                        "-o",
                        str(restic),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["merge", str(evidence), str(restic), "-o", str(merged)]), 0)
            self.assertEqual(main(["validate", "-i", str(merged)]), 0)
            self.assertEqual(
                main(
                    [
                        "check",
                        "-i",
                        str(evidence),
                        "-p",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "-o",
                        str(report),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["report", "-i", str(report), "-f", "markdown", "-o", str(markdown)]), 0)
            self.assertEqual(main(["report", "-i", str(report), "-f", "bookstack", "-o", str(bookstack)]), 0)
            self.assertEqual(
                main(
                    [
                        "bundle",
                        "manifest",
                        str(merged),
                        str(report),
                        str(markdown),
                        "--base-dir",
                        str(temp),
                        "-o",
                        str(manifest),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(manifest), "-t", "bundle"]), 0)

            report_data = json.loads(report.read_text(encoding="utf-8"))
            manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(report_data["summary"]["status"], "pass")
            self.assertEqual(manifest_data["metadata"]["artifact_count"], 3)
            self.assertIn("# OpenOps Evidence Report", markdown.read_text(encoding="utf-8"))
            self.assertIn("# Infrastructure Readiness Evidence", bookstack.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
