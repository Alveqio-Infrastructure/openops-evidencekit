import json
import unittest
import xml.etree.ElementTree as ET

from openops_evidence.reports import (
    render_bookstack_markdown,
    render_junit,
    render_markdown,
    render_prometheus,
    render_sarif,
)


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

    def test_markdown_report_escapes_untrusted_fields(self):
        report = {
            "generated_at": "2026-05-31T10:00:00+00:00",
            "summary": {
                "status": "fail",
                "score": 40,
                "checks_passed": 0,
                "checks_failed": 1,
                "checks_warn": 0,
            },
            "results": [
                {
                    "id": "bad`id",
                    "title": "<script>alert(1)</script> [link](javascript:alert(1))",
                    "status": "fail",
                    "severity": "high",
                    "path": "signals.x",
                    "operator": "exists",
                    "remediation": "## Inject\n<script>alert(1)</script>",
                }
            ],
        }

        rendered = render_markdown(report)

        self.assertNotIn("<script>", rendered)
        self.assertNotIn("[link](javascript:alert(1))", rendered)
        self.assertIn("&lt;script&gt;alert\\(1\\)&lt;/script&gt;", rendered)
        self.assertIn("\\[link\\]\\(javascript:alert\\(1\\)\\)", rendered)
        self.assertIn("``bad`id``", rendered)

    def test_bookstack_report_escapes_untrusted_fields(self):
        rendered = render_bookstack_markdown(
            {
                "generated_at": "2026-05-31T10:00:00+00:00",
                "summary": {
                    "status": "fail",
                    "score": 40,
                    "checks_passed": 0,
                    "checks_failed": 1,
                    "checks_warn": 0,
                },
                "results": [
                    {
                        "id": "bad`id",
                        "title": "<script>alert(1)</script>",
                        "status": "fail",
                        "severity": "high",
                        "path": "signals.x",
                        "remediation": "[click](javascript:alert(1))",
                    }
                ],
            }
        )

        self.assertNotIn("<script>", rendered)
        self.assertNotIn("[click](javascript:alert(1))", rendered)
        self.assertIn("&lt;script&gt;alert\\(1\\)&lt;/script&gt;", rendered)
        self.assertIn("\\[click\\]\\(javascript:alert\\(1\\)\\)", rendered)
        self.assertIn("``bad`id``", rendered)

    def test_junit_report_maps_failures_and_warnings(self):
        rendered = render_junit(
            {
                "generated_at": "2026-05-31T10:00:00+00:00",
                "summary": {
                    "status": "fail",
                    "score": 40,
                    "checks_passed": 1,
                    "checks_failed": 1,
                    "checks_warn": 1,
                },
                "results": [
                    {
                        "id": "backup_recent",
                        "title": "Recent backup",
                        "status": "fail",
                        "severity": "critical",
                        "required": True,
                        "path": "signals.backup.last_success_at",
                        "operator": "within_days",
                        "observed_count": 0,
                        "remediation": "Fix backups.",
                    },
                    {
                        "id": "dmarc",
                        "title": "DMARC policy",
                        "status": "warn",
                        "severity": "low",
                        "required": False,
                        "path": "signals.mail.domains[*].dmarc",
                        "operator": "one_of",
                        "observed_count": 1,
                    },
                    {
                        "id": "mfa",
                        "title": "MFA enabled",
                        "status": "pass",
                        "severity": "high",
                        "required": True,
                        "path": "signals.access.mfa_required",
                        "operator": "equals",
                        "observed_count": 1,
                    },
                ],
            }
        )

        root = ET.fromstring(rendered)
        self.assertEqual(root.tag, "testsuite")
        self.assertEqual(root.attrib["tests"], "3")
        self.assertEqual(root.attrib["failures"], "1")
        self.assertEqual(root.attrib["skipped"], "1")
        failure = root.find("./testcase[@name='backup_recent']/failure")
        skipped = root.find("./testcase[@name='dmarc']/skipped")
        self.assertIsNotNone(failure)
        self.assertIsNotNone(skipped)
        self.assertIn("Fix backups.", failure.text or "")

    def test_sarif_report_exports_findings(self):
        sarif = json.loads(
            render_sarif(
                {
                    "generated_at": "2026-05-31T10:00:00+00:00",
                    "summary": {
                        "status": "fail",
                        "score": 40,
                        "checks_passed": 1,
                        "checks_failed": 1,
                        "checks_warn": 1,
                    },
                    "results": [
                        {
                            "id": "backup_recent",
                            "title": "Recent backup",
                            "status": "fail",
                            "severity": "critical",
                            "required": True,
                            "path": "signals.backup.last_success_at",
                            "operator": "within_days",
                            "observed_count": 0,
                            "remediation": "Fix backups.",
                        },
                        {
                            "id": "dmarc",
                            "title": "DMARC policy",
                            "status": "warn",
                            "severity": "low",
                            "required": False,
                            "path": "signals.mail.domains[*].dmarc",
                            "operator": "one_of",
                            "observed_count": 1,
                        },
                        {
                            "id": "mfa",
                            "title": "MFA enabled",
                            "status": "pass",
                            "severity": "high",
                            "required": True,
                            "path": "signals.access.mfa_required",
                            "operator": "equals",
                            "observed_count": 1,
                        },
                    ],
                }
            )
        )

        run = sarif["runs"][0]
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual([result["ruleId"] for result in run["results"]], ["backup_recent", "dmarc"])
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(run["results"][1]["level"], "warning")
        self.assertEqual(
            run["results"][0]["locations"][0]["logicalLocations"][0]["name"],
            "signals.backup.last_success_at",
        )

    def test_prometheus_report_exports_score_and_findings(self):
        rendered = render_prometheus(
            {
                "generated_at": "2026-05-31T10:00:00+00:00",
                "summary": {
                    "status": "fail",
                    "score": 40,
                    "checks_total": 1,
                    "checks_passed": 0,
                    "checks_failed": 1,
                    "checks_warn": 0,
                },
                "results": [
                    {
                        "id": 'backup"recent',
                        "title": "Recent backup",
                        "status": "fail",
                        "severity": "critical",
                        "required": True,
                        "path": "signals.backup.last_success_at",
                        "operator": "within_days",
                    }
                ],
            }
        )

        self.assertIn("openops_readiness_score 40", rendered)
        self.assertIn('openops_report_status{status="pass"} 0', rendered)
        self.assertIn('openops_report_status{status="fail"} 1', rendered)
        self.assertIn('openops_checks_total{result="failed"} 1', rendered)
        self.assertIn('check_id="backup\\"recent"', rendered)
        self.assertIn('required="true"', rendered)


if __name__ == "__main__":
    unittest.main()
