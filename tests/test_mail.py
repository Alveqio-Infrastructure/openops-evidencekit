import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.mail import create_mail_report, render_mail_csv, render_mail_markdown
from openops_evidence.schema import validate_mail_report


ROOT = Path(__file__).resolve().parents[1]


class MailReportTests(unittest.TestCase):
    def test_create_report_passes_enforced_dmarc(self):
        report = create_mail_report(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T10:00:00+00:00",
                "metadata": {"source": "unit-test"},
                "assets": [],
                "signals": {
                    "mail": {
                        "domains": [
                            {
                                "domain": "example.invalid",
                                "spf": True,
                                "dkim": True,
                                "dmarc": "v=DMARC1; p=reject; rua=mailto:dmarc@example.invalid",
                            }
                        ]
                    }
                },
            }
        )

        self.assertEqual(validate_mail_report(report), [])
        self.assertEqual(report["summary"]["status"], "pass")
        self.assertEqual(report["summary"]["dmarc_enforced"], 1)
        self.assertEqual(report["domains"][0]["dmarc_policy"], "reject")
        self.assertIn("# OpenOps Mail Domain Report", render_mail_markdown(report))
        self.assertIn("domain,status,spf", render_mail_csv(report))

    def test_create_report_fails_missing_spf_dkim_or_dmarc(self):
        report = create_mail_report(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T10:00:00+00:00",
                "metadata": {},
                "assets": [],
                "signals": {
                    "mail": {
                        "domains": [
                            {
                                "domain": "example.invalid",
                                "spf": False,
                                "dkim": True,
                                "dmarc": "",
                            }
                        ]
                    }
                },
            }
        )

        self.assertEqual(validate_mail_report(report), [])
        self.assertEqual(report["summary"]["status"], "fail")
        self.assertEqual(report["summary"]["spf_missing"], 1)
        self.assertEqual(report["summary"]["dmarc_missing"], 1)
        self.assertEqual(report["domains"][0]["status"], "fail")

    def test_create_report_warns_on_monitoring_only_dmarc(self):
        report = create_mail_report(
            {
                "schema_version": "0.1",
                "generated_at": "2026-06-01T10:00:00+00:00",
                "metadata": {},
                "assets": [],
                "signals": {
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
        )

        self.assertEqual(validate_mail_report(report), [])
        self.assertEqual(report["summary"]["status"], "warn")
        self.assertEqual(report["summary"]["dmarc_monitoring"], 1)

    def test_cli_outputs_all_formats_and_fail_on_warn(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            json_report = temp / "mail-report.json"
            markdown = temp / "mail-report.md"
            csv = temp / "mail-report.csv"
            weak = temp / "weak-mail.json"
            weak.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-06-01T10:00:00+00:00",
                        "metadata": {},
                        "assets": [],
                        "signals": {
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
                        "mail",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-f",
                        "json",
                        "-o",
                        str(json_report),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(json_report), "-t", "mail-report"]), 0)
            self.assertEqual(
                main(
                    [
                        "mail",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-o",
                        str(markdown),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "mail",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-f",
                        "csv",
                        "-o",
                        str(csv),
                    ]
                ),
                0,
            )
            self.assertIn("# OpenOps Mail Domain Report", markdown.read_text(encoding="utf-8"))
            self.assertIn("domain,status,spf", csv.read_text(encoding="utf-8"))
            self.assertEqual(
                main(["mail", "report", "-i", str(weak), "--fail-on-warn", "-o", str(temp / "weak.md")]),
                1,
            )


if __name__ == "__main__":
    unittest.main()
