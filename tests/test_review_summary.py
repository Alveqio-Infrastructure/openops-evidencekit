import unittest

from openops_evidence.review_summary import create_review_summary, render_review_summary_markdown
from openops_evidence.schema import validate_review_summary


class ReviewSummaryTests(unittest.TestCase):
    def test_review_summary_blocks_on_open_risks_and_privacy_findings(self):
        summary = create_review_summary(
            report={"generated_at": "2026-06-01T10:00:00+00:00", "summary": {"status": "pass", "score": 90}},
            gate={"summary": {"status": "pass"}},
            privacy_scan={"summary": {"findings_count": 1}},
            risk_register={"summary": {"open_count": 2, "accepted_count": 0, "expired_acceptance_count": 0}},
            freshness_report={"summary": {"stale_count": 0, "invalid_count": 0}},
        )

        self.assertEqual(validate_review_summary(summary), [])
        self.assertEqual(summary["decision"]["status"], "fail")
        self.assertEqual(summary["decision"]["recommendation"], "blocked")
        self.assertEqual(summary["metrics"]["open_risks"], 2)
        self.assertIn("privacy findings exist", summary["decision"]["reason"])
        self.assertIn("# OpenOps Review Summary", render_review_summary_markdown(summary))

    def test_review_summary_warns_on_accepted_risks_and_drift(self):
        summary = create_review_summary(
            report={"generated_at": "2026-06-01T10:00:00+00:00", "summary": {"status": "pass", "score": 100}},
            gate={"summary": {"status": "pass"}},
            privacy_scan={"summary": {"findings_count": 0}},
            risk_register={"summary": {"open_count": 0, "accepted_count": 1, "expired_acceptance_count": 0}},
            evidence_drift={"summary": {"asset_changes_count": 1, "domain_changes_count": 0}},
        )

        self.assertEqual(validate_review_summary(summary), [])
        self.assertEqual(summary["decision"]["status"], "warn")
        self.assertEqual(summary["decision"]["recommendation"], "review_required")
        self.assertEqual(summary["metrics"]["accepted_risks"], 1)
        self.assertEqual(summary["metrics"]["drift_changes"], 1)

    def test_review_summary_blocks_on_restore_failures(self):
        summary = create_review_summary(
            report={"generated_at": "2026-06-01T10:00:00+00:00", "summary": {"status": "pass", "score": 100}},
            gate={"summary": {"status": "pass"}},
            privacy_scan={"summary": {"findings_count": 0}},
            restore_report={"summary": {"checks_failed": 1, "checks_warn": 0}},
        )

        self.assertEqual(validate_review_summary(summary), [])
        self.assertEqual(summary["decision"]["status"], "fail")
        self.assertEqual(summary["metrics"]["restore_failures"], 1)
        self.assertIn("restore assurance failed", summary["decision"]["reason"])

    def test_review_summary_blocks_on_mail_failures(self):
        summary = create_review_summary(
            report={"generated_at": "2026-06-01T10:00:00+00:00", "summary": {"status": "pass", "score": 100}},
            gate={"summary": {"status": "pass"}},
            privacy_scan={"summary": {"findings_count": 0}},
            mail_report={"summary": {"domains_failed": 1, "domains_warn": 0}},
        )

        self.assertEqual(validate_review_summary(summary), [])
        self.assertEqual(summary["decision"]["status"], "fail")
        self.assertEqual(summary["metrics"]["mail_failures"], 1)
        self.assertIn("mail domain checks failed", summary["decision"]["reason"])

    def test_review_summary_blocks_on_access_failures(self):
        summary = create_review_summary(
            report={"generated_at": "2026-06-01T10:00:00+00:00", "summary": {"status": "pass", "score": 100}},
            gate={"summary": {"status": "pass"}},
            privacy_scan={"summary": {"findings_count": 0}},
            access_report={"summary": {"checks_failed": 1, "checks_warn": 0}},
        )

        self.assertEqual(validate_review_summary(summary), [])
        self.assertEqual(summary["decision"]["status"], "fail")
        self.assertEqual(summary["metrics"]["access_failures"], 1)
        self.assertIn("access exposure checks failed", summary["decision"]["reason"])

    def test_review_summary_blocks_on_monitoring_failures(self):
        summary = create_review_summary(
            report={"generated_at": "2026-06-01T10:00:00+00:00", "summary": {"status": "pass", "score": 100}},
            gate={"summary": {"status": "pass"}},
            privacy_scan={"summary": {"findings_count": 0}},
            monitoring_report={"summary": {"checks_failed": 1, "checks_warn": 0}},
        )

        self.assertEqual(validate_review_summary(summary), [])
        self.assertEqual(summary["decision"]["status"], "fail")
        self.assertEqual(summary["metrics"]["monitoring_failures"], 1)
        self.assertIn("monitoring checks failed", summary["decision"]["reason"])

    def test_review_summary_blocks_on_exposure_failures(self):
        summary = create_review_summary(
            report={"generated_at": "2026-06-01T10:00:00+00:00", "summary": {"status": "pass", "score": 100}},
            gate={"summary": {"status": "pass"}},
            privacy_scan={"summary": {"findings_count": 0}},
            exposure_report={"summary": {"checks_failed": 1, "checks_warn": 1, "risky_ports_total": 1}},
        )

        self.assertEqual(validate_review_summary(summary), [])
        self.assertEqual(summary["decision"]["status"], "fail")
        self.assertEqual(summary["metrics"]["exposure_failures"], 1)
        self.assertEqual(summary["metrics"]["risky_ports"], 1)
        self.assertIn("network exposure checks failed", summary["decision"]["reason"])

    def test_review_summary_warns_on_exposure_warnings(self):
        summary = create_review_summary(
            report={"generated_at": "2026-06-01T10:00:00+00:00", "summary": {"status": "pass", "score": 100}},
            gate={"summary": {"status": "pass"}},
            privacy_scan={"summary": {"findings_count": 0}},
            exposure_report={"summary": {"checks_failed": 0, "checks_warn": 1, "risky_ports_total": 0}},
        )

        self.assertEqual(validate_review_summary(summary), [])
        self.assertEqual(summary["decision"]["status"], "warn")
        self.assertEqual(summary["metrics"]["exposure_warnings"], 1)
        self.assertIn("network exposure warnings exist", summary["decision"]["reason"])

    def test_review_summary_blocks_on_patch_failures(self):
        summary = create_review_summary(
            report={"generated_at": "2026-06-01T10:00:00+00:00", "summary": {"status": "pass", "score": 100}},
            gate={"summary": {"status": "pass"}},
            privacy_scan={"summary": {"findings_count": 0}},
            patch_report={"summary": {"checks_failed": 1, "checks_warn": 1, "security_updates_total": 2}},
        )

        self.assertEqual(validate_review_summary(summary), [])
        self.assertEqual(summary["decision"]["status"], "fail")
        self.assertEqual(summary["metrics"]["patch_failures"], 1)
        self.assertEqual(summary["metrics"]["security_updates"], 2)
        self.assertIn("patch checks failed", summary["decision"]["reason"])

    def test_review_summary_warns_on_patch_warnings(self):
        summary = create_review_summary(
            report={"generated_at": "2026-06-01T10:00:00+00:00", "summary": {"status": "pass", "score": 100}},
            gate={"summary": {"status": "pass"}},
            privacy_scan={"summary": {"findings_count": 0}},
            patch_report={"summary": {"checks_failed": 0, "checks_warn": 1, "security_updates_total": 0}},
        )

        self.assertEqual(validate_review_summary(summary), [])
        self.assertEqual(summary["decision"]["status"], "warn")
        self.assertEqual(summary["metrics"]["patch_warnings"], 1)
        self.assertIn("patch warnings exist", summary["decision"]["reason"])

    def test_review_summary_blocks_on_runtime_failures(self):
        summary = create_review_summary(
            report={"generated_at": "2026-06-01T10:00:00+00:00", "summary": {"status": "pass", "score": 100}},
            gate={"summary": {"status": "pass"}},
            privacy_scan={"summary": {"findings_count": 0}},
            runtime_report={"summary": {"checks_failed": 1, "checks_warn": 0}},
        )

        self.assertEqual(validate_review_summary(summary), [])
        self.assertEqual(summary["decision"]["status"], "fail")
        self.assertEqual(summary["metrics"]["runtime_failures"], 1)
        self.assertIn("runtime checks failed", summary["decision"]["reason"])

    def test_review_summary_warns_on_runtime_warnings(self):
        summary = create_review_summary(
            report={"generated_at": "2026-06-01T10:00:00+00:00", "summary": {"status": "pass", "score": 100}},
            gate={"summary": {"status": "pass"}},
            privacy_scan={"summary": {"findings_count": 0}},
            runtime_report={"summary": {"checks_failed": 0, "checks_warn": 2}},
        )

        self.assertEqual(validate_review_summary(summary), [])
        self.assertEqual(summary["decision"]["status"], "warn")
        self.assertEqual(summary["metrics"]["runtime_warnings"], 2)
        self.assertIn("runtime warnings exist", summary["decision"]["reason"])

    def test_review_summary_blocks_on_incident_failures(self):
        summary = create_review_summary(
            report={"generated_at": "2026-06-01T10:00:00+00:00", "summary": {"status": "pass", "score": 100}},
            gate={"summary": {"status": "pass"}},
            privacy_scan={"summary": {"findings_count": 0}},
            incident_report={"summary": {"checks_failed": 1, "checks_warn": 0}},
        )

        self.assertEqual(validate_review_summary(summary), [])
        self.assertEqual(summary["decision"]["status"], "fail")
        self.assertEqual(summary["metrics"]["incident_failures"], 1)
        self.assertIn("incident readiness checks failed", summary["decision"]["reason"])

    def test_review_summary_blocks_on_service_level_failures(self):
        summary = create_review_summary(
            report={"generated_at": "2026-06-01T10:00:00+00:00", "summary": {"status": "pass", "score": 100}},
            gate={"summary": {"status": "pass"}},
            privacy_scan={"summary": {"findings_count": 0}},
            service_level_report={"summary": {"services_failed": 1, "services_warn": 0}},
        )

        self.assertEqual(validate_review_summary(summary), [])
        self.assertEqual(summary["decision"]["status"], "fail")
        self.assertEqual(summary["metrics"]["service_level_failures"], 1)
        self.assertIn("service-level targets were missed", summary["decision"]["reason"])

    def test_review_summary_warns_on_service_level_warnings(self):
        summary = create_review_summary(
            report={"generated_at": "2026-06-01T10:00:00+00:00", "summary": {"status": "pass", "score": 100}},
            gate={"summary": {"status": "pass"}},
            privacy_scan={"summary": {"findings_count": 0}},
            service_level_report={"summary": {"services_failed": 0, "services_warn": 2}},
        )

        self.assertEqual(validate_review_summary(summary), [])
        self.assertEqual(summary["decision"]["status"], "warn")
        self.assertEqual(summary["metrics"]["service_level_warnings"], 2)
        self.assertIn("service-level evidence warnings exist", summary["decision"]["reason"])

    def test_review_summary_blocks_on_tls_failures(self):
        summary = create_review_summary(
            report={"generated_at": "2026-06-01T10:00:00+00:00", "summary": {"status": "pass", "score": 100}},
            gate={"summary": {"status": "pass"}},
            privacy_scan={"summary": {"findings_count": 0}},
            tls_report={"summary": {"certificates_failed": 1, "certificates_warn": 0}},
        )

        self.assertEqual(validate_review_summary(summary), [])
        self.assertEqual(summary["decision"]["status"], "fail")
        self.assertEqual(summary["metrics"]["tls_failures"], 1)
        self.assertIn("TLS certificate checks failed", summary["decision"]["reason"])

    def test_review_summary_passes_clean_pack(self):
        summary = create_review_summary(
            report={"generated_at": "2026-06-01T10:00:00+00:00", "summary": {"status": "pass", "score": 100}},
            gate={"summary": {"status": "pass"}},
            privacy_scan={"summary": {"findings_count": 0}},
            risk_register={"summary": {"open_count": 0, "accepted_count": 0, "expired_acceptance_count": 0}},
            freshness_report={"summary": {"stale_count": 0, "invalid_count": 0}},
        )

        self.assertEqual(validate_review_summary(summary), [])
        self.assertEqual(summary["decision"]["status"], "pass")
        self.assertEqual(summary["decision"]["recommendation"], "ready_for_handoff")


if __name__ == "__main__":
    unittest.main()
