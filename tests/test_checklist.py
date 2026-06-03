import unittest

from openops_evidence.checklist import (
    create_review_checklist,
    render_review_checklist_csv,
    render_review_checklist_markdown,
)
from openops_evidence.schema import validate_review_checklist


class ReviewChecklistTests(unittest.TestCase):
    def test_review_checklist_summarizes_required_review_items(self):
        review_summary = {
            "schema_version": "0.1",
            "generated_at": "2026-06-01T10:00:00+00:00",
            "metadata": {},
            "decision": {
                "status": "fail",
                "recommendation": "blocked",
                "reason": "Incident readiness failed.",
            },
            "metrics": {
                "gate_status": "pass",
                "privacy_findings": 0,
                "access_warnings": 1,
                "incident_failures": 1,
            },
            "highlights": [],
            "next_steps": [],
        }
        artifacts = [
            {"filename": "review-summary.md"},
            {"filename": "gate-result.md"},
            {"filename": "privacy-scan.md"},
            {"filename": "access-report.md"},
            {"filename": "incident-report.md"},
            {"filename": "manifest.json"},
        ]

        checklist = create_review_checklist(review_summary, artifacts)

        self.assertEqual(validate_review_checklist(checklist), [])
        self.assertEqual(checklist["summary"]["status"], "fail")
        item_statuses = {item["id"]: item["status"] for item in checklist["items"]}
        self.assertEqual(item_statuses["review_access"], "warn")
        self.assertEqual(item_statuses["review_incident"], "fail")
        self.assertIn("# OpenOps Review Checklist", render_review_checklist_markdown(checklist))
        self.assertIn("id,title,status,required,artifact,reason", render_review_checklist_csv(checklist))


if __name__ == "__main__":
    unittest.main()
