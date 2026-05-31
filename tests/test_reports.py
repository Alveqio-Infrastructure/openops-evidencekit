import unittest

from openops_evidence.reports import render_bookstack_markdown


class ReportTests(unittest.TestCase):
    def test_bookstack_report_groups_failed_actions(self):
        rendered = render_bookstack_markdown(
            {
                "generated_at": "2026-05-31T10:00:00+00:00",
                "summary": {
                    "status": "fail",
                    "score": 40,
                    "checks_passed": 1,
                    "checks_failed": 1,
                    "checks_warn": 0,
                },
                "results": [
                    {
                        "id": "backup_recent",
                        "title": "Recent backup",
                        "status": "fail",
                        "severity": "critical",
                        "path": "signals.backup.last_success_at",
                        "remediation": "Fix backups.",
                    },
                    {
                        "id": "mfa",
                        "title": "MFA enabled",
                        "status": "pass",
                        "severity": "high",
                        "path": "signals.access.mfa_required",
                    },
                ],
            }
        )
        self.assertIn("## Required Action", rendered)
        self.assertIn("Recent backup", rendered)
        self.assertIn("## Passed Checks", rendered)


if __name__ == "__main__":
    unittest.main()
