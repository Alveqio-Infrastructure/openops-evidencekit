import json
import os
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main


ROOT = Path(__file__).resolve().parents[1]


class CliWorkflowTests(unittest.TestCase):
    def test_init_can_create_github_actions_workflow(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)

            self.assertEqual(main(["init", str(temp), "--github-actions"]), 0)

            workflow = temp / ".github" / "workflows" / "openops-evidence.yml"
            self.assertTrue((temp / "evidence.sample.json").is_file())
            self.assertTrue((temp / "policy.baseline.toml").is_file())
            self.assertTrue(workflow.is_file())
            workflow_text = workflow.read_text(encoding="utf-8")
            self.assertIn("openops-evidence inventory evidence", workflow_text)
            self.assertIn("openops-evidence check", workflow_text)
            self.assertIn("-p policy.baseline.toml", workflow_text)
            self.assertIn("openops-evidence badge report", workflow_text)
            self.assertIn("openops-evidence brief report", workflow_text)
            self.assertIn("openops-evidence scorecard report", workflow_text)
            self.assertIn("openops-evidence history append", workflow_text)
            self.assertIn("-f prometheus", workflow_text)
            self.assertIn("openops-evidence review create", workflow_text)

            custom = temp / "custom"
            self.assertEqual(
                main(["init", str(custom), "--policy-pack", "security-minimum", "--github-actions"]),
                0,
            )
            custom_workflow = custom / ".github" / "workflows" / "openops-evidence.yml"
            self.assertIn("-p policy.security-minimum.toml", custom_workflow.read_text(encoding="utf-8"))

    def test_end_to_end_readiness_workflow(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            evidence = temp / "evidence.json"
            restic = temp / "restic.json"
            merged = temp / "merged.json"
            inventory = temp / "inventory.json"
            inventory_markdown = temp / "inventory.md"
            report = temp / "report.json"
            gate = temp / "gate-result.json"
            badge = temp / "readiness-badge.json"
            brief = temp / "executive-brief.json"
            brief_markdown = temp / "executive-brief.md"
            scorecard = temp / "scorecard.json"
            scorecard_markdown = temp / "scorecard.md"
            scorecard_csv = temp / "scorecard.csv"
            scorecard_html = temp / "scorecard.html"
            history = temp / "readiness-history.json"
            history_markdown = temp / "readiness-history.md"
            markdown = temp / "report.md"
            bookstack = temp / "bookstack.md"
            junit = temp / "report.junit.xml"
            sarif = temp / "report.sarif.json"
            prometheus = temp / "report.prom"
            manifest = temp / "manifest.json"
            verification = temp / "verification.json"
            signature = temp / "manifest.signature.json"
            signature_verification = temp / "signature-verification.json"
            archive = temp / "evidence-bundle.zip"

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
            self.assertEqual(main(["inventory", "evidence", "-i", str(merged), "-f", "json", "-o", str(inventory)]), 0)
            self.assertEqual(main(["validate", "-i", str(inventory), "-t", "inventory"]), 0)
            self.assertEqual(
                main(["inventory", "evidence", "-i", str(merged), "-f", "markdown", "-o", str(inventory_markdown)]),
                0,
            )
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
            self.assertEqual(
                main(
                    [
                        "gate",
                        "report",
                        "-i",
                        str(report),
                        "--min-score",
                        "100",
                        "--max-warnings",
                        "0",
                        "-o",
                        str(gate),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(gate), "-t", "gate-result"]), 0)
            self.assertEqual(main(["badge", "report", "-i", str(report), "-o", str(badge)]), 0)
            self.assertEqual(main(["validate", "-i", str(badge), "-t", "badge"]), 0)
            self.assertEqual(main(["brief", "report", "-i", str(report), "-f", "json", "-o", str(brief)]), 0)
            self.assertEqual(main(["validate", "-i", str(brief), "-t", "executive-brief"]), 0)
            self.assertEqual(main(["brief", "report", "-i", str(report), "-o", str(brief_markdown)]), 0)
            self.assertEqual(main(["scorecard", "report", "-i", str(report), "-f", "json", "-o", str(scorecard)]), 0)
            self.assertEqual(main(["validate", "-i", str(scorecard), "-t", "scorecard"]), 0)
            self.assertEqual(main(["scorecard", "report", "-i", str(report), "-o", str(scorecard_markdown)]), 0)
            self.assertEqual(main(["scorecard", "report", "-i", str(report), "-f", "csv", "-o", str(scorecard_csv)]), 0)
            self.assertEqual(main(["scorecard", "report", "-i", str(report), "-f", "html", "-o", str(scorecard_html)]), 0)
            self.assertEqual(
                main(["history", "append", "-i", str(report), "--source", "workflow-test", "-o", str(history)]),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(history), "-t", "history"]), 0)
            self.assertEqual(
                main(["history", "render", "-i", str(history), "-f", "markdown", "-o", str(history_markdown)]),
                0,
            )
            self.assertEqual(main(["report", "-i", str(report), "-f", "bookstack", "-o", str(bookstack)]), 0)
            self.assertEqual(main(["report", "-i", str(report), "-f", "junit", "-o", str(junit)]), 0)
            self.assertEqual(main(["report", "-i", str(report), "-f", "sarif", "-o", str(sarif)]), 0)
            self.assertEqual(main(["report", "-i", str(report), "-f", "prometheus", "-o", str(prometheus)]), 0)
            self.assertEqual(main(["policy", "show", "baseline", "-o", str(temp / "policy.exported.toml")]), 0)
            self.assertEqual(
                main(
                    [
                        "bundle",
                        "manifest",
                        str(merged),
                        str(inventory),
                        str(report),
                        str(gate),
                        str(badge),
                        str(brief),
                        str(scorecard),
                        str(history),
                        str(markdown),
                        str(sarif),
                        str(prometheus),
                        "--base-dir",
                        str(temp),
                        "-o",
                        str(manifest),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(manifest), "-t", "bundle"]), 0)
            self.assertEqual(
                main(["bundle", "verify", str(manifest), "--base-dir", str(temp), "-o", str(verification)]),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(verification), "-t", "bundle-verification"]), 0)
            self.assertEqual(
                main(["bundle", "archive", str(manifest), "--base-dir", str(temp), "-o", str(archive)]),
                0,
            )
            old_key = os.environ.get("OPENOPS_TEST_SIGNING_KEY")
            os.environ["OPENOPS_TEST_SIGNING_KEY"] = "test-signing-key"
            try:
                self.assertEqual(
                    main(
                        [
                            "bundle",
                            "sign",
                            str(manifest),
                            "--key-env",
                            "OPENOPS_TEST_SIGNING_KEY",
                            "--key-id",
                            "test-key",
                            "-o",
                            str(signature),
                        ]
                    ),
                    0,
                )
                self.assertEqual(main(["validate", "-i", str(signature), "-t", "bundle-signature"]), 0)
                self.assertEqual(
                    main(
                        [
                            "bundle",
                            "verify-signature",
                            str(manifest),
                            str(signature),
                            "--key-env",
                            "OPENOPS_TEST_SIGNING_KEY",
                            "--fail-on-invalid",
                            "-o",
                            str(signature_verification),
                        ]
                    ),
                    0,
                )
            finally:
                if old_key is None:
                    os.environ.pop("OPENOPS_TEST_SIGNING_KEY", None)
                else:
                    os.environ["OPENOPS_TEST_SIGNING_KEY"] = old_key

            report_data = json.loads(report.read_text(encoding="utf-8"))
            inventory_data = json.loads(inventory.read_text(encoding="utf-8"))
            gate_data = json.loads(gate.read_text(encoding="utf-8"))
            badge_data = json.loads(badge.read_text(encoding="utf-8"))
            brief_data = json.loads(brief.read_text(encoding="utf-8"))
            scorecard_data = json.loads(scorecard.read_text(encoding="utf-8"))
            history_data = json.loads(history.read_text(encoding="utf-8"))
            manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
            verification_data = json.loads(verification.read_text(encoding="utf-8"))
            signature_data = json.loads(signature.read_text(encoding="utf-8"))
            signature_verification_data = json.loads(signature_verification.read_text(encoding="utf-8"))
            self.assertEqual(report_data["summary"]["status"], "pass")
            self.assertGreaterEqual(inventory_data["summary"]["assets_total"], 2)
            self.assertEqual(gate_data["summary"]["status"], "pass")
            self.assertEqual(badge_data["message"], "pass 100")
            self.assertEqual(brief_data["summary"]["health"], "on_track")
            self.assertEqual(scorecard_data["summary"]["domains_total"], 6)
            self.assertEqual(history_data["summary"]["latest_score"], 100)
            self.assertEqual(manifest_data["metadata"]["artifact_count"], 11)
            self.assertEqual(verification_data["summary"]["status"], "pass")
            self.assertTrue(archive.is_file())
            self.assertEqual(signature_data["metadata"]["key_id"], "test-key")
            self.assertEqual(signature_verification_data["summary"]["status"], "pass")
            self.assertIn("# OpenOps Evidence Report", markdown.read_text(encoding="utf-8"))
            self.assertIn("# Infrastructure Readiness Evidence", bookstack.read_text(encoding="utf-8"))
            self.assertIn("<testsuite", junit.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(sarif.read_text(encoding="utf-8"))["version"], "2.1.0")
            self.assertIn("openops_readiness_score 100", prometheus.read_text(encoding="utf-8"))
            self.assertIn("# OpenOps Executive Brief", brief_markdown.read_text(encoding="utf-8"))
            self.assertIn("# OpenOps Domain Scorecard", scorecard_markdown.read_text(encoding="utf-8"))
            self.assertIn("domain,title,status,score", scorecard_csv.read_text(encoding="utf-8"))
            self.assertIn("<title>OpenOps Domain Scorecard</title>", scorecard_html.read_text(encoding="utf-8"))
            self.assertIn("# OpenOps Readiness History", history_markdown.read_text(encoding="utf-8"))
            self.assertIn("# OpenOps Evidence Inventory", inventory_markdown.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
