import json
import tempfile
import unittest
import zipfile
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
                "index.html",
                "inventory.csv",
                "inventory.json",
                "inventory.md",
                "manifest.json",
                "policy-matrix.csv",
                "policy-matrix.json",
                "policy-matrix.md",
                "policy-coverage.csv",
                "policy-coverage.json",
                "policy-coverage.md",
                "privacy-scan.json",
                "privacy-scan.md",
                "readiness-badge.json",
                "report.junit.xml",
                "report.json",
                "report.md",
                "report.prom",
                "report.sarif.json",
                "scorecard.csv",
                "scorecard.html",
                "scorecard.json",
                "scorecard.md",
            ]
            for filename in expected:
                self.assertTrue((pack / filename).is_file(), filename)

            self.assertEqual(main(["validate", "-i", str(pack / "report.json"), "-t", "report"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "inventory.json"), "-t", "inventory"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "policy-matrix.json"), "-t", "policy-matrix"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "policy-coverage.json"), "-t", "policy-coverage"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "scorecard.json"), "-t", "scorecard"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "executive-brief.json"), "-t", "executive-brief"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "action-plan.json"), "-t", "action-plan"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "readiness-badge.json"), "-t", "badge"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "gate-result.json"), "-t", "gate-result"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "privacy-scan.json"), "-t", "privacy-scan"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "manifest.json"), "-t", "bundle"]), 0)

            manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
            readme = (pack / "README.md").read_text(encoding="utf-8")
            index = (pack / "index.html").read_text(encoding="utf-8")
            self.assertEqual(manifest["metadata"]["artifact_count"], len(expected) - 1)
            self.assertIn("does not include raw evidence by default", readme)
            self.assertIn("executive-brief.md", readme)
            self.assertIn("privacy-scan.md", readme)
            self.assertIn("<title>OpenOps Review Pack</title>", index)
            self.assertIn("scorecard.html", index)

    def test_review_create_can_include_scope_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            pack = temp / "review-pack"
            fail_pack = temp / "review-pack-fail"

            self.assertEqual(
                main(
                    [
                        "review",
                        "create",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-p",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "--scope",
                        str(ROOT / "examples" / "scope.sample.toml"),
                        "-o",
                        str(pack),
                    ]
                ),
                0,
            )

            self.assertTrue((pack / "scope-report.json").is_file())
            self.assertTrue((pack / "scope-report.md").is_file())
            self.assertTrue((pack / "scope-report.csv").is_file())
            self.assertEqual(main(["validate", "-i", str(pack / "scope-report.json"), "-t", "scope-report"]), 0)

            manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
            readme = (pack / "README.md").read_text(encoding="utf-8")
            index = (pack / "index.html").read_text(encoding="utf-8")
            scope_report = json.loads((pack / "scope-report.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["metadata"]["artifact_count"], 33)
            self.assertEqual(scope_report["summary"]["status"], "warn")
            self.assertIn("scope-report.md", readme)
            self.assertIn("Scope Report", index)

            self.assertEqual(
                main(
                    [
                        "review",
                        "create",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-p",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "--scope",
                        str(ROOT / "examples" / "scope.sample.toml"),
                        "--fail-on-scope-warn",
                        "-o",
                        str(fail_pack),
                    ]
                ),
                1,
            )
            self.assertTrue((fail_pack / "manifest.json").is_file())

    def test_review_create_can_include_service_catalog_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            pack = temp / "review-pack"
            fail_pack = temp / "review-pack-fail"

            self.assertEqual(
                main(
                    [
                        "review",
                        "create",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-p",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "--catalog",
                        str(ROOT / "examples" / "service-catalog.sample.toml"),
                        "-o",
                        str(pack),
                    ]
                ),
                0,
            )

            self.assertTrue((pack / "service-catalog.json").is_file())
            self.assertTrue((pack / "service-catalog.md").is_file())
            self.assertTrue((pack / "service-catalog.csv").is_file())
            self.assertTrue((pack / "runbook-report.json").is_file())
            self.assertTrue((pack / "runbook-report.md").is_file())
            self.assertTrue((pack / "runbook-report.csv").is_file())
            self.assertEqual(main(["validate", "-i", str(pack / "service-catalog.json"), "-t", "service-catalog"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "runbook-report.json"), "-t", "runbook-report"]), 0)

            manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
            readme = (pack / "README.md").read_text(encoding="utf-8")
            index = (pack / "index.html").read_text(encoding="utf-8")
            service_catalog = json.loads((pack / "service-catalog.json").read_text(encoding="utf-8"))
            runbook_report = json.loads((pack / "runbook-report.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["metadata"]["artifact_count"], 36)
            self.assertEqual(service_catalog["summary"]["status"], "warn")
            self.assertEqual(service_catalog["summary"]["missing_catalog_assets_count"], 1)
            self.assertEqual(runbook_report["summary"]["missing_runbooks_count"], 1)
            self.assertIn("service-catalog.md", readme)
            self.assertIn("runbook-report.md", readme)
            self.assertIn("Service Catalog", index)
            self.assertIn("Runbook Report", index)

            self.assertEqual(
                main(
                    [
                        "review",
                        "create",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-p",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "--catalog",
                        str(ROOT / "examples" / "service-catalog.sample.toml"),
                        "--fail-on-catalog-warn",
                        "-o",
                        str(fail_pack),
                    ]
                ),
                1,
            )
            self.assertTrue((fail_pack / "manifest.json").is_file())

            runbook_fail_pack = temp / "review-pack-runbook-fail"
            self.assertEqual(
                main(
                    [
                        "review",
                        "create",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-p",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "--catalog",
                        str(ROOT / "examples" / "service-catalog.sample.toml"),
                        "--fail-on-runbook-warn",
                        "-o",
                        str(runbook_fail_pack),
                    ]
                ),
                1,
            )
            self.assertTrue((runbook_fail_pack / "manifest.json").is_file())

    def test_review_create_can_include_evidence_drift_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            pack = temp / "review-pack"
            fail_pack = temp / "review-pack-fail"

            self.assertEqual(
                main(
                    [
                        "review",
                        "create",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-p",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "--base-evidence",
                        str(ROOT / "examples" / "evidence.previous.json"),
                        "-o",
                        str(pack),
                    ]
                ),
                0,
            )

            self.assertTrue((pack / "evidence-drift.json").is_file())
            self.assertTrue((pack / "evidence-drift.md").is_file())
            self.assertTrue((pack / "evidence-drift.csv").is_file())
            self.assertEqual(main(["validate", "-i", str(pack / "evidence-drift.json"), "-t", "evidence-drift"]), 0)

            manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
            readme = (pack / "README.md").read_text(encoding="utf-8")
            index = (pack / "index.html").read_text(encoding="utf-8")
            drift = json.loads((pack / "evidence-drift.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["metadata"]["artifact_count"], 33)
            self.assertEqual(drift["summary"]["status"], "warn")
            self.assertIn("evidence-drift.md", readme)
            self.assertIn("Evidence Drift", index)

            self.assertEqual(
                main(
                    [
                        "review",
                        "create",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-p",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "--base-evidence",
                        str(ROOT / "examples" / "evidence.previous.json"),
                        "--fail-on-drift",
                        "-o",
                        str(fail_pack),
                    ]
                ),
                1,
            )
            self.assertTrue((fail_pack / "manifest.json").is_file())

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

    def test_review_create_can_write_zip_archive(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            pack = temp / "review-pack"
            archive = temp / "review-pack.zip"

            self.assertEqual(
                main(
                    [
                        "review",
                        "create",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-p",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "-o",
                        str(pack),
                        "--archive",
                        str(archive),
                    ]
                ),
                0,
            )

            self.assertTrue(archive.is_file())
            with zipfile.ZipFile(archive) as zip_file:
                names = set(zip_file.namelist())
            self.assertIn("manifest.json", names)
            self.assertIn("index.html", names)
            self.assertIn("README.md", names)
            self.assertIn("report.json", names)
            self.assertIn("scorecard.html", names)


if __name__ == "__main__":
    unittest.main()
