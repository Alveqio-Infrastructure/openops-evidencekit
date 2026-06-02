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
            self.assertTrue((temp / "service-catalog.sample.toml").is_file())
            self.assertTrue(workflow.is_file())
            workflow_text = workflow.read_text(encoding="utf-8")
            self.assertIn("openops-evidence inventory evidence", workflow_text)
            self.assertIn("openops-evidence catalog report", workflow_text)
            self.assertIn("openops-evidence freshness report", workflow_text)
            self.assertIn("openops-evidence restore report", workflow_text)
            self.assertIn("openops-evidence mail report", workflow_text)
            self.assertIn("openops-evidence questionnaire policy", workflow_text)
            self.assertIn("openops-evidence coverage report", workflow_text)
            self.assertIn("openops-evidence check", workflow_text)
            self.assertIn("-p policy.baseline.toml", workflow_text)
            self.assertIn("openops-evidence badge report", workflow_text)
            self.assertIn("openops-evidence brief report", workflow_text)
            self.assertIn("openops-evidence risk register", workflow_text)
            self.assertIn("openops-evidence scorecard report", workflow_text)
            self.assertIn("openops-evidence history append", workflow_text)
            self.assertIn("-f prometheus", workflow_text)
            self.assertIn("openops-evidence review create", workflow_text)
            self.assertIn("--archive review-pack.zip", workflow_text)

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
            scope_report = temp / "scope-report.json"
            scope_markdown = temp / "scope-report.md"
            service_catalog = temp / "service-catalog.json"
            service_catalog_markdown = temp / "service-catalog.md"
            runbook_report = temp / "runbook-report.json"
            runbook_markdown = temp / "runbook-report.md"
            freshness_report = temp / "freshness-report.json"
            freshness_markdown = temp / "freshness-report.md"
            restore_report = temp / "restore-report.json"
            restore_markdown = temp / "restore-report.md"
            mail_report = temp / "mail-report.json"
            mail_markdown = temp / "mail-report.md"
            evidence_drift = temp / "evidence-drift.json"
            evidence_drift_markdown = temp / "evidence-drift.md"
            coverage = temp / "policy-coverage.json"
            coverage_markdown = temp / "policy-coverage.md"
            questionnaire = temp / "questionnaire.json"
            questionnaire_markdown = temp / "questionnaire.md"
            report = temp / "report.json"
            gate = temp / "gate-result.json"
            badge = temp / "readiness-badge.json"
            brief = temp / "executive-brief.json"
            brief_markdown = temp / "executive-brief.md"
            risk_register = temp / "risk-register.json"
            risk_register_markdown = temp / "risk-register.md"
            scorecard = temp / "scorecard.json"
            scorecard_markdown = temp / "scorecard.md"
            scorecard_csv = temp / "scorecard.csv"
            scorecard_html = temp / "scorecard.html"
            history = temp / "readiness-history.json"
            history_markdown = temp / "readiness-history.md"
            history_svg = temp / "readiness-history.svg"
            markdown = temp / "report.md"
            bookstack = temp / "bookstack.md"
            junit = temp / "report.junit.xml"
            sarif = temp / "report.sarif.json"
            prometheus = temp / "report.prom"
            manifest = temp / "manifest.json"
            verification = temp / "verification.json"
            attestation = temp / "review-attestation.json"
            attestation_markdown = temp / "review-attestation.md"
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
            self.assertEqual(main(["scope", "validate", str(ROOT / "examples" / "scope.sample.toml")]), 0)
            self.assertEqual(
                main(
                    [
                        "scope",
                        "report",
                        "-i",
                        str(merged),
                        "-s",
                        str(ROOT / "examples" / "scope.sample.toml"),
                        "-f",
                        "json",
                        "-o",
                        str(scope_report),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(scope_report), "-t", "scope-report"]), 0)
            self.assertEqual(
                main(
                    [
                        "scope",
                        "report",
                        "-i",
                        str(merged),
                        "-s",
                        str(ROOT / "examples" / "scope.sample.toml"),
                        "-o",
                        str(scope_markdown),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["catalog", "validate", str(ROOT / "examples" / "service-catalog.sample.toml")]), 0)
            self.assertEqual(
                main(
                    [
                        "catalog",
                        "report",
                        "-i",
                        str(merged),
                        "-c",
                        str(ROOT / "examples" / "service-catalog.sample.toml"),
                        "-f",
                        "json",
                        "-o",
                        str(service_catalog),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(service_catalog), "-t", "service-catalog"]), 0)
            self.assertEqual(
                main(
                    [
                        "catalog",
                        "report",
                        "-i",
                        str(merged),
                        "-c",
                        str(ROOT / "examples" / "service-catalog.sample.toml"),
                        "-o",
                        str(service_catalog_markdown),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "runbook",
                        "report",
                        "-i",
                        str(merged),
                        "-c",
                        str(ROOT / "examples" / "service-catalog.sample.toml"),
                        "--max-age-days",
                        "365",
                        "-f",
                        "json",
                        "-o",
                        str(runbook_report),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(runbook_report), "-t", "runbook-report"]), 0)
            self.assertEqual(
                main(
                    [
                        "runbook",
                        "report",
                        "-i",
                        str(merged),
                        "-c",
                        str(ROOT / "examples" / "service-catalog.sample.toml"),
                        "-o",
                        str(runbook_markdown),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "freshness",
                        "report",
                        "-i",
                        str(merged),
                        "--max-age-days",
                        "365",
                        "-f",
                        "json",
                        "-o",
                        str(freshness_report),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(freshness_report), "-t", "freshness-report"]), 0)
            self.assertEqual(
                main(
                    [
                        "freshness",
                        "report",
                        "-i",
                        str(merged),
                        "--max-age-days",
                        "365",
                        "-o",
                        str(freshness_markdown),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "restore",
                        "report",
                        "-i",
                        str(merged),
                        "--max-drill-age-days",
                        "365",
                        "-f",
                        "json",
                        "-o",
                        str(restore_report),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(restore_report), "-t", "restore-report"]), 0)
            self.assertEqual(
                main(
                    [
                        "restore",
                        "report",
                        "-i",
                        str(merged),
                        "--max-drill-age-days",
                        "365",
                        "-o",
                        str(restore_markdown),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(["mail", "report", "-i", str(merged), "-f", "json", "-o", str(mail_report)]),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(mail_report), "-t", "mail-report"]), 0)
            self.assertEqual(main(["mail", "report", "-i", str(merged), "-o", str(mail_markdown)]), 0)
            self.assertEqual(
                main(
                    [
                        "evidence",
                        "diff",
                        "--base",
                        str(ROOT / "examples" / "evidence.previous.json"),
                        "--current",
                        str(evidence),
                        "-o",
                        str(evidence_drift),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(evidence_drift), "-t", "evidence-drift"]), 0)
            self.assertEqual(
                main(
                    [
                        "evidence",
                        "diff",
                        "--base",
                        str(ROOT / "examples" / "evidence.previous.json"),
                        "--current",
                        str(evidence),
                        "-f",
                        "markdown",
                        "-o",
                        str(evidence_drift_markdown),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "questionnaire",
                        "policy",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "-f",
                        "json",
                        "-o",
                        str(questionnaire),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(questionnaire), "-t", "questionnaire"]), 0)
            self.assertEqual(
                main(
                    [
                        "questionnaire",
                        "policy",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "-o",
                        str(questionnaire_markdown),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "coverage",
                        "report",
                        "-i",
                        str(evidence),
                        "-p",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "-f",
                        "json",
                        "-o",
                        str(coverage),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(coverage), "-t", "policy-coverage"]), 0)
            self.assertEqual(
                main(
                    [
                        "coverage",
                        "report",
                        "-i",
                        str(evidence),
                        "-p",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "-o",
                        str(coverage_markdown),
                    ]
                ),
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
            self.assertEqual(main(["risk", "register", "-i", str(report), "-o", str(risk_register)]), 0)
            self.assertEqual(main(["validate", "-i", str(risk_register), "-t", "risk-register"]), 0)
            self.assertEqual(
                main(["risk", "register", "-i", str(report), "-f", "markdown", "-o", str(risk_register_markdown)]),
                0,
            )
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
            self.assertEqual(
                main(["history", "render", "-i", str(history), "-f", "svg", "-o", str(history_svg)]),
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
                        str(scope_report),
                        str(service_catalog),
                        str(runbook_report),
                        str(freshness_report),
                        str(restore_report),
                        str(mail_report),
                        str(evidence_drift),
                        str(questionnaire),
                        str(coverage),
                        str(report),
                        str(gate),
                        str(badge),
                        str(brief),
                        str(risk_register),
                        str(scorecard),
                        str(history),
                        str(history_svg),
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
            attestation_args = [
                "attest",
                "review",
                "--manifest",
                str(manifest),
                "--report",
                str(report),
                "--gate",
                str(gate),
                "--scope-report",
                str(scope_report),
                "--evidence-drift",
                str(evidence_drift),
                "--approver",
                "Example Reviewer",
                "--role",
                "Operations",
                "--statement",
                "Reviewed generated artifacts for the workflow test.",
            ]
            self.assertEqual(main([*attestation_args, "-o", str(attestation)]), 0)
            self.assertEqual(main(["validate", "-i", str(attestation), "-t", "review-attestation"]), 0)
            self.assertEqual(main([*attestation_args, "-f", "markdown", "-o", str(attestation_markdown)]), 0)
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
            questionnaire_data = json.loads(questionnaire.read_text(encoding="utf-8"))
            coverage_data = json.loads(coverage.read_text(encoding="utf-8"))
            scope_data = json.loads(scope_report.read_text(encoding="utf-8"))
            service_catalog_data = json.loads(service_catalog.read_text(encoding="utf-8"))
            runbook_data = json.loads(runbook_report.read_text(encoding="utf-8"))
            freshness_data = json.loads(freshness_report.read_text(encoding="utf-8"))
            restore_data = json.loads(restore_report.read_text(encoding="utf-8"))
            mail_data = json.loads(mail_report.read_text(encoding="utf-8"))
            evidence_drift_data = json.loads(evidence_drift.read_text(encoding="utf-8"))
            gate_data = json.loads(gate.read_text(encoding="utf-8"))
            badge_data = json.loads(badge.read_text(encoding="utf-8"))
            brief_data = json.loads(brief.read_text(encoding="utf-8"))
            risk_register_data = json.loads(risk_register.read_text(encoding="utf-8"))
            scorecard_data = json.loads(scorecard.read_text(encoding="utf-8"))
            history_data = json.loads(history.read_text(encoding="utf-8"))
            manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
            attestation_data = json.loads(attestation.read_text(encoding="utf-8"))
            verification_data = json.loads(verification.read_text(encoding="utf-8"))
            signature_data = json.loads(signature.read_text(encoding="utf-8"))
            signature_verification_data = json.loads(signature_verification.read_text(encoding="utf-8"))
            self.assertEqual(report_data["summary"]["status"], "pass")
            self.assertGreaterEqual(inventory_data["summary"]["assets_total"], 2)
            self.assertEqual(questionnaire_data["summary"]["questions_total"], 10)
            self.assertEqual(coverage_data["summary"]["coverage_percent"], 100)
            self.assertEqual(scope_data["summary"]["status"], "warn")
            self.assertEqual(scope_data["summary"]["missing_in_scope_assets"], 1)
            self.assertEqual(service_catalog_data["summary"]["status"], "warn")
            self.assertEqual(service_catalog_data["summary"]["missing_catalog_assets_count"], 1)
            self.assertEqual(runbook_data["summary"]["status"], "warn")
            self.assertEqual(runbook_data["summary"]["missing_runbooks_count"], 1)
            self.assertGreater(freshness_data["summary"]["timestamps_total"], 0)
            self.assertEqual(restore_data["summary"]["status"], "pass")
            self.assertEqual(mail_data["summary"]["status"], "pass")
            self.assertEqual(evidence_drift_data["summary"]["status"], "warn")
            self.assertGreater(evidence_drift_data["summary"]["asset_changes_count"], 0)
            self.assertEqual(gate_data["summary"]["status"], "pass")
            self.assertEqual(badge_data["message"], "pass 100")
            self.assertEqual(brief_data["summary"]["health"], "on_track")
            self.assertEqual(risk_register_data["summary"]["status"], "pass")
            self.assertEqual(scorecard_data["summary"]["domains_total"], 6)
            self.assertEqual(history_data["summary"]["latest_score"], 100)
            self.assertEqual(manifest_data["metadata"]["artifact_count"], 22)
            self.assertEqual(attestation_data["summary"]["status"], "warn")
            self.assertEqual(attestation_data["manifest"]["artifact_count"], 22)
            self.assertEqual(verification_data["summary"]["status"], "pass")
            self.assertTrue(archive.is_file())
            self.assertEqual(signature_data["metadata"]["key_id"], "test-key")
            self.assertEqual(signature_verification_data["summary"]["status"], "pass")
            self.assertIn("# OpenOps Evidence Report", markdown.read_text(encoding="utf-8"))
            self.assertIn("# OpenOps Evidence Questionnaire", questionnaire_markdown.read_text(encoding="utf-8"))
            self.assertIn("# OpenOps Policy Coverage", coverage_markdown.read_text(encoding="utf-8"))
            self.assertIn("# Infrastructure Readiness Evidence", bookstack.read_text(encoding="utf-8"))
            self.assertIn("<testsuite", junit.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(sarif.read_text(encoding="utf-8"))["version"], "2.1.0")
            self.assertIn("openops_readiness_score 100", prometheus.read_text(encoding="utf-8"))
            self.assertIn("# OpenOps Executive Brief", brief_markdown.read_text(encoding="utf-8"))
            self.assertIn("# OpenOps Risk Register", risk_register_markdown.read_text(encoding="utf-8"))
            self.assertIn("# OpenOps Domain Scorecard", scorecard_markdown.read_text(encoding="utf-8"))
            self.assertIn("domain,title,status,score", scorecard_csv.read_text(encoding="utf-8"))
            self.assertIn("<title>OpenOps Domain Scorecard</title>", scorecard_html.read_text(encoding="utf-8"))
            self.assertIn("# OpenOps Readiness History", history_markdown.read_text(encoding="utf-8"))
            self.assertIn("<svg", history_svg.read_text(encoding="utf-8"))
            self.assertIn("# OpenOps Evidence Inventory", inventory_markdown.read_text(encoding="utf-8"))
            self.assertIn("# OpenOps Scope Report", scope_markdown.read_text(encoding="utf-8"))
            self.assertIn("# OpenOps Service Catalog Report", service_catalog_markdown.read_text(encoding="utf-8"))
            self.assertIn("# OpenOps Runbook Coverage Report", runbook_markdown.read_text(encoding="utf-8"))
            self.assertIn("# OpenOps Evidence Freshness Report", freshness_markdown.read_text(encoding="utf-8"))
            self.assertIn("# OpenOps Restore Assurance Report", restore_markdown.read_text(encoding="utf-8"))
            self.assertIn("# OpenOps Mail Domain Report", mail_markdown.read_text(encoding="utf-8"))
            self.assertIn("# OpenOps Evidence Drift", evidence_drift_markdown.read_text(encoding="utf-8"))
            self.assertIn("# OpenOps Review Attestation", attestation_markdown.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
