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
