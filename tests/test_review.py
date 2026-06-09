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
                "completeness-report.csv",
                "completeness-report.json",
                "completeness-report.md",
                "executive-brief.json",
                "executive-brief.md",
                "freshness-report.csv",
                "freshness-report.json",
                "freshness-report.md",
                "restore-report.csv",
                "restore-report.json",
                "restore-report.md",
                "gate-result.json",
                "gate-result.md",
                "index.html",
                "inventory.csv",
                "inventory.json",
                "inventory.md",
                "mail-report.csv",
                "mail-report.json",
                "mail-report.md",
                "dns-report.csv",
                "dns-report.json",
                "dns-report.md",
                "tls-report.csv",
                "tls-report.json",
                "tls-report.md",
                "access-report.csv",
                "access-report.json",
                "access-report.md",
                "monitoring-report.csv",
                "monitoring-report.json",
                "monitoring-report.md",
                "manifest.json",
                "policy-matrix.csv",
                "policy-matrix.json",
                "policy-matrix.md",
                "policy-coverage.csv",
                "policy-coverage.json",
                "policy-coverage.md",
                "privacy-scan.json",
                "privacy-scan.md",
                "quality-report.csv",
                "quality-report.json",
                "quality-report.md",
                "readiness-badge.json",
                "report.junit.xml",
                "report.json",
                "report.md",
                "report.prom",
                "report.sarif.json",
                "review-checklist.csv",
                "review-checklist.json",
                "review-checklist.md",
                "review-summary.json",
                "review-summary.md",
                "risk-register.csv",
                "risk-register.json",
                "risk-register.md",
                "scorecard.csv",
                "scorecard.html",
                "scorecard.json",
                "scorecard.md",
            ]
            for filename in expected:
                self.assertTrue((pack / filename).is_file(), filename)

            self.assertEqual(main(["validate", "-i", str(pack / "report.json"), "-t", "report"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "inventory.json"), "-t", "inventory"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "freshness-report.json"), "-t", "freshness-report"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "policy-matrix.json"), "-t", "policy-matrix"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "completeness-report.json"), "-t", "completeness-report"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "policy-coverage.json"), "-t", "policy-coverage"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "quality-report.json"), "-t", "quality-report"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "scorecard.json"), "-t", "scorecard"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "executive-brief.json"), "-t", "executive-brief"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "action-plan.json"), "-t", "action-plan"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "risk-register.json"), "-t", "risk-register"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "readiness-badge.json"), "-t", "badge"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "gate-result.json"), "-t", "gate-result"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "privacy-scan.json"), "-t", "privacy-scan"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "review-summary.json"), "-t", "review-summary"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "review-checklist.json"), "-t", "review-checklist"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "restore-report.json"), "-t", "restore-report"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "mail-report.json"), "-t", "mail-report"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "dns-report.json"), "-t", "dns-report"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "tls-report.json"), "-t", "tls-report"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "access-report.json"), "-t", "access-report"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "monitoring-report.json"), "-t", "monitoring-report"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "manifest.json"), "-t", "bundle"]), 0)

            manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
            review_summary = json.loads((pack / "review-summary.json").read_text(encoding="utf-8"))
            readme = (pack / "README.md").read_text(encoding="utf-8")
            index = (pack / "index.html").read_text(encoding="utf-8")
            self.assertEqual(manifest["metadata"]["artifact_count"], len(expected) - 1)
            self.assertEqual(review_summary["decision"]["status"], "pass")
            self.assertIn("does not include raw evidence by default", readme)
            self.assertIn("review-summary.md", readme)
            self.assertIn("review-checklist.md", readme)
            self.assertIn("completeness-report.md", readme)
            self.assertIn("executive-brief.md", readme)
            self.assertIn("freshness-report.md", readme)
            self.assertIn("restore-report.md", readme)
            self.assertIn("mail-report.md", readme)
            self.assertIn("dns-report.md", readme)
            self.assertIn("tls-report.md", readme)
            self.assertIn("access-report.md", readme)
            self.assertIn("monitoring-report.md", readme)
            self.assertIn("risk-register.md", readme)
            self.assertIn("privacy-scan.md", readme)
            self.assertIn("quality-report.md", readme)
            self.assertIn("<title>OpenOps Review Pack</title>", index)
            self.assertIn("Review Summary", index)
            self.assertIn("Checklist", index)
            self.assertIn("Completeness", index)
            self.assertIn("Quality", index)
            self.assertIn("Freshness", index)
            self.assertIn("Restore", index)
            self.assertIn("Mail", index)
            self.assertIn("DNS", index)
            self.assertIn("TLS", index)
            self.assertIn("Access", index)
            self.assertIn("Monitoring", index)
            self.assertIn("Risk Register", index)
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
            self.assertEqual(manifest["metadata"]["artifact_count"], 68)
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
            self.assertTrue((pack / "service-level-report.json").is_file())
            self.assertTrue((pack / "service-level-report.md").is_file())
            self.assertTrue((pack / "service-level-report.csv").is_file())
            self.assertTrue((pack / "runbook-report.json").is_file())
            self.assertTrue((pack / "runbook-report.md").is_file())
            self.assertTrue((pack / "runbook-report.csv").is_file())
            self.assertEqual(main(["validate", "-i", str(pack / "service-catalog.json"), "-t", "service-catalog"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "service-level-report.json"), "-t", "service-level-report"]), 0)
            self.assertEqual(main(["validate", "-i", str(pack / "runbook-report.json"), "-t", "runbook-report"]), 0)

            manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
            readme = (pack / "README.md").read_text(encoding="utf-8")
            index = (pack / "index.html").read_text(encoding="utf-8")
            service_catalog = json.loads((pack / "service-catalog.json").read_text(encoding="utf-8"))
            service_level = json.loads((pack / "service-level-report.json").read_text(encoding="utf-8"))
            runbook_report = json.loads((pack / "runbook-report.json").read_text(encoding="utf-8"))
            incident_report = json.loads((pack / "incident-report.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["metadata"]["artifact_count"], 77)
            self.assertEqual(service_catalog["summary"]["status"], "warn")
            self.assertEqual(service_level["summary"]["status"], "warn")
            self.assertEqual(service_catalog["summary"]["missing_catalog_assets_count"], 1)
            self.assertEqual(runbook_report["summary"]["missing_runbooks_count"], 1)
            self.assertEqual(incident_report["summary"]["status"], "fail")
            self.assertIn("service-catalog.md", readme)
            self.assertIn("service-level-report.md", readme)
            self.assertIn("runbook-report.md", readme)
            self.assertIn("incident-report.md", readme)
            self.assertIn("Service Catalog", index)
            self.assertIn("Service Levels", index)
            self.assertIn("Runbook Report", index)
            self.assertIn("Incident", index)

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
            self.assertEqual(manifest["metadata"]["artifact_count"], 68)
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
            review_summary = json.loads((pack / "review-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(gate["summary"]["status"], "fail")
            self.assertEqual(review_summary["decision"]["status"], "fail")
            self.assertTrue((pack / "manifest.json").is_file())

    def test_review_create_can_fail_on_freshness_after_writing_pack(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            pack = temp / "review-pack"

            self.assertEqual(
                main(
                    [
                        "review",
                        "create",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-p",
                        str(ROOT / "examples" / "policy.baseline.toml"),
                        "--freshness-max-age-days",
                        "0",
                        "--fail-on-freshness-warn",
                        "-o",
                        str(pack),
                    ]
                ),
                1,
            )

            self.assertTrue((pack / "freshness-report.json").is_file())
            self.assertTrue((pack / "manifest.json").is_file())

    def test_review_create_can_fail_on_restore_after_writing_pack(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            pack = temp / "review-pack"
            policy = temp / "passing-policy.toml"
            stale = temp / "stale-restore.json"
            policy.write_text(
                """
[[checks]]
id = "backup_recent"
title = "Recent backup exists"
path = "signals.backup.last_success_at"
operator = "within_days"
value = 7
severity = "critical"
required = true
remediation = "Record a recent successful backup timestamp."
""".lstrip(),
                encoding="utf-8",
            )
            stale.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T00:00:00+00:00",
                        "metadata": {},
                        "assets": [],
                        "signals": {
                            "backup": {
                                "last_success_at": "2026-05-31T00:00:00+00:00",
                                "repository_count": 1,
                                "restore_test_at": "2026-01-01T00:00:00+00:00",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                main(
                    [
                        "review",
                        "create",
                        "-i",
                        str(stale),
                        "-p",
                        str(policy),
                        "--restore-max-drill-age-days",
                        "7",
                        "--fail-on-restore-warn",
                        "-o",
                        str(pack),
                    ]
                ),
                1,
            )

            restore_report = json.loads((pack / "restore-report.json").read_text(encoding="utf-8"))
            review_summary = json.loads((pack / "review-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(restore_report["summary"]["status"], "warn")
            self.assertEqual(review_summary["decision"]["status"], "warn")
            self.assertTrue((pack / "manifest.json").is_file())

    def test_review_create_can_fail_on_mail_after_writing_pack(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            pack = temp / "review-pack"
            policy = temp / "passing-policy.toml"
            weak_mail = temp / "weak-mail.json"
            policy.write_text(
                """
[[checks]]
id = "mail_domain_recorded"
title = "Mail domain recorded"
path = "signals.mail.domains[*].domain"
operator = "exists"
severity = "medium"
required = true
remediation = "Record at least one mail domain."
""".lstrip(),
                encoding="utf-8",
            )
            weak_mail.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T00:00:00+00:00",
                        "metadata": {},
                        "assets": [],
                        "signals": {
                            "backup": {
                                "last_success_at": "2026-05-31T00:00:00+00:00",
                                "repository_count": 1,
                                "restore_test_at": "2026-05-20T00:00:00+00:00",
                            },
                            "mail": {
                                "domains": [
                                    {
                                        "domain": "example.invalid",
                                        "spf": True,
                                        "dkim": True,
                                        "dmarc": "none",
                                    }
                                ]
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                main(
                    [
                        "review",
                        "create",
                        "-i",
                        str(weak_mail),
                        "-p",
                        str(policy),
                        "--fail-on-mail-warn",
                        "-o",
                        str(pack),
                    ]
                ),
                1,
            )

            mail_report = json.loads((pack / "mail-report.json").read_text(encoding="utf-8"))
            review_summary = json.loads((pack / "review-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(mail_report["summary"]["status"], "warn")
            self.assertEqual(review_summary["decision"]["status"], "warn")
            self.assertTrue((pack / "manifest.json").is_file())

    def test_review_create_can_fail_on_access_after_writing_pack(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            pack = temp / "review-pack"
            policy = temp / "passing-policy.toml"
            weak_access = temp / "weak-access.json"
            policy.write_text(
                """
[[checks]]
id = "mfa_required"
title = "Administrative MFA is required"
path = "signals.access.mfa_required"
operator = "equals"
value = true
severity = "high"
required = true
remediation = "Require MFA for administrative entrypoints."
""".lstrip(),
                encoding="utf-8",
            )
            weak_access.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T00:00:00+00:00",
                        "metadata": {},
                        "assets": [],
                        "signals": {
                            "backup": {
                                "last_success_at": "2026-05-31T00:00:00+00:00",
                                "repository_count": 1,
                                "restore_test_at": "2026-05-20T00:00:00+00:00",
                            },
                            "access": {
                                "ssh_public_exposed": False,
                                "mfa_required": True,
                                "admin_entrypoints": ["public-ssh"],
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                main(
                    [
                        "review",
                        "create",
                        "-i",
                        str(weak_access),
                        "-p",
                        str(policy),
                        "--fail-on-access-warn",
                        "-o",
                        str(pack),
                    ]
                ),
                1,
            )

            access_report = json.loads((pack / "access-report.json").read_text(encoding="utf-8"))
            review_summary = json.loads((pack / "review-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(access_report["summary"]["status"], "fail")
            self.assertEqual(review_summary["decision"]["status"], "fail")
            self.assertTrue((pack / "manifest.json").is_file())

    def test_review_create_can_fail_on_tls_after_writing_pack(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            pack = temp / "review-pack"
            policy = temp / "passing-policy.toml"
            weak_tls = temp / "weak-tls.json"
            policy.write_text(
                """
[[checks]]
id = "tls_cert_recorded"
title = "TLS certificate expiry is recorded"
path = "signals.tls.certificates[*].not_after"
operator = "exists"
severity = "high"
required = true
remediation = "Record TLS certificate expiry evidence."
""".lstrip(),
                encoding="utf-8",
            )
            weak_tls.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T00:00:00+00:00",
                        "metadata": {},
                        "assets": [],
                        "signals": {
                            "backup": {
                                "last_success_at": "2026-05-31T00:00:00+00:00",
                                "repository_count": 1,
                                "restore_test_at": "2026-05-20T00:00:00+00:00",
                            },
                            "tls": {
                                "certificates": [
                                    {
                                        "hostname": "www.example.invalid",
                                        "not_after": "2026-06-10T00:00:00+00:00",
                                    }
                                ]
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                main(
                    [
                        "review",
                        "create",
                        "-i",
                        str(weak_tls),
                        "-p",
                        str(policy),
                        "--fail-on-tls-warn",
                        "-o",
                        str(pack),
                    ]
                ),
                1,
            )

            tls_report = json.loads((pack / "tls-report.json").read_text(encoding="utf-8"))
            review_summary = json.loads((pack / "review-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(tls_report["summary"]["status"], "warn")
            self.assertEqual(review_summary["decision"]["status"], "warn")
            self.assertTrue((pack / "manifest.json").is_file())

    def test_review_create_can_fail_on_monitoring_after_writing_pack(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            pack = temp / "review-pack"
            policy = temp / "passing-policy.toml"
            weak_monitoring = temp / "weak-monitoring.json"
            policy.write_text(
                """
[[checks]]
id = "monitoring_targets_recorded"
title = "Monitoring targets are recorded"
path = "signals.monitoring.targets"
operator = "at_least"
value = 1
severity = "high"
required = true
remediation = "Record monitoring targets."
""".lstrip(),
                encoding="utf-8",
            )
            weak_monitoring.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T00:00:00+00:00",
                        "metadata": {},
                        "assets": [],
                        "signals": {
                            "backup": {
                                "last_success_at": "2026-05-31T00:00:00+00:00",
                                "repository_count": 1,
                                "restore_test_at": "2026-05-20T00:00:00+00:00",
                            },
                            "monitoring": {
                                "system": "prometheus",
                                "targets": 1,
                                "targets_down": 1,
                                "down_targets": ["db:9100"],
                                "alert_channels": ["email"],
                                "last_alert_test_at": "2026-05-31T00:00:00+00:00",
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                main(
                    [
                        "review",
                        "create",
                        "-i",
                        str(weak_monitoring),
                        "-p",
                        str(policy),
                        "--fail-on-monitoring-warn",
                        "-o",
                        str(pack),
                    ]
                ),
                1,
            )

            monitoring_report = json.loads((pack / "monitoring-report.json").read_text(encoding="utf-8"))
            review_summary = json.loads((pack / "review-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(monitoring_report["summary"]["status"], "fail")
            self.assertEqual(review_summary["decision"]["status"], "fail")
            self.assertTrue((pack / "manifest.json").is_file())

    def test_review_create_can_fail_on_incident_after_writing_pack(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            pack = temp / "review-pack"
            policy = temp / "passing-policy.toml"
            weak_incident = temp / "weak-incident.json"
            catalog = temp / "catalog.toml"
            policy.write_text(
                """
[[checks]]
id = "backup_restore_recorded"
title = "Restore drill is recorded"
path = "signals.backup.restore_test_at"
operator = "exists"
severity = "high"
required = true
remediation = "Record restore drill evidence."
""".lstrip(),
                encoding="utf-8",
            )
            catalog.write_text(
                """
[[services]]
id = "database"
name = "Database"
owner = "platform"
criticality = "critical"
assets = ["db-01"]
runbooks = ["database-restore"]
contacts = []
""".lstrip(),
                encoding="utf-8",
            )
            weak_incident.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T00:00:00+00:00",
                        "metadata": {},
                        "assets": [],
                        "signals": {
                            "backup": {"restore_test_at": "2026-05-20T00:00:00+00:00"},
                            "monitoring": {"alert_channels": []},
                            "access": {"ssh_public_exposed": False, "mfa_required": True},
                            "docs": {"runbooks": []},
                        },
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                main(
                    [
                        "review",
                        "create",
                        "-i",
                        str(weak_incident),
                        "-p",
                        str(policy),
                        "--catalog",
                        str(catalog),
                        "--fail-on-incident-warn",
                        "-o",
                        str(pack),
                    ]
                ),
                1,
            )

            incident_report = json.loads((pack / "incident-report.json").read_text(encoding="utf-8"))
            review_summary = json.loads((pack / "review-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(incident_report["summary"]["status"], "fail")
            self.assertEqual(review_summary["decision"]["status"], "fail")
            self.assertTrue((pack / "manifest.json").is_file())

    def test_review_create_can_fail_on_open_risk_after_writing_pack(self):
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
                        "--fail-on-open-risk",
                        "-o",
                        str(pack),
                    ]
                ),
                1,
            )

            risk_register = json.loads((pack / "risk-register.json").read_text(encoding="utf-8"))
            self.assertEqual(risk_register["summary"]["open_count"], 1)
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
            self.assertIn("review-summary.md", names)
            self.assertIn("review-checklist.md", names)
            self.assertIn("completeness-report.md", names)
            self.assertIn("quality-report.md", names)
            self.assertIn("restore-report.md", names)
            self.assertIn("mail-report.md", names)
            self.assertIn("dns-report.md", names)
            self.assertIn("tls-report.md", names)
            self.assertIn("access-report.md", names)
            self.assertIn("monitoring-report.md", names)
            self.assertIn("report.json", names)
            self.assertIn("scorecard.html", names)


if __name__ == "__main__":
    unittest.main()
