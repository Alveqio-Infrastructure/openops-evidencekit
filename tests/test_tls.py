import csv
import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.schema import validate_tls_report
from openops_evidence.tls import create_tls_report, render_tls_csv, render_tls_markdown


def _evidence(certificates: list) -> dict:
    return {
        "schema_version": "0.1",
        "generated_at": "2026-06-01T10:00:00+00:00",
        "metadata": {"source": "unit-test"},
        "assets": [],
        "signals": {"tls": {"certificates": certificates}},
    }


class TlsReportTests(unittest.TestCase):
    def test_tls_report_passes_current_certificate(self):
        report = create_tls_report(
            _evidence(
                [
                    {
                        "hostname": "www.example.invalid",
                        "port": 443,
                        "not_after": "2026-08-20T12:00:00+00:00",
                        "issuer": "Example CA",
                    }
                ]
            ),
            warn_days=30,
        )

        self.assertEqual(validate_tls_report(report), [])
        self.assertEqual(report["summary"]["status"], "pass")
        self.assertEqual(report["summary"]["certificates_passed"], 1)
        self.assertIn("# OpenOps TLS Certificate Report", render_tls_markdown(report))
        rows = list(csv.DictReader(render_tls_csv(report).splitlines()))
        self.assertEqual(rows[0]["hostname"], "www.example.invalid")

    def test_tls_report_warns_before_expiry(self):
        report = create_tls_report(
            _evidence(
                [
                    {
                        "hostname": "www.example.invalid",
                        "not_after": "2026-06-15T12:00:00+00:00",
                    }
                ]
            ),
            warn_days=30,
        )

        self.assertEqual(validate_tls_report(report), [])
        self.assertEqual(report["summary"]["status"], "warn")
        self.assertEqual(report["summary"]["expiring_soon_count"], 1)

    def test_tls_report_fails_expired_or_invalid_certificate(self):
        report = create_tls_report(
            _evidence(
                [
                    {
                        "hostname": "expired.example.invalid",
                        "not_after": "2026-05-01T12:00:00+00:00",
                    },
                    {
                        "hostname": "invalid.example.invalid",
                        "not_after": "not-a-date",
                    },
                ]
            ),
            warn_days=30,
        )

        self.assertEqual(validate_tls_report(report), [])
        self.assertEqual(report["summary"]["status"], "fail")
        self.assertEqual(report["summary"]["certificates_failed"], 2)

    def test_tls_cli_renders_json_markdown_csv_and_warn_exit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            evidence = temp / "evidence.json"
            report_json = temp / "tls-report.json"
            report_md = temp / "tls-report.md"
            report_csv = temp / "tls-report.csv"
            evidence.write_text(
                json.dumps(
                    _evidence(
                        [
                            {
                                "hostname": "www.example.invalid",
                                "not_after": "2026-06-15T12:00:00+00:00",
                            }
                        ]
                    )
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                main(["tls", "report", "-i", str(evidence), "--warn-days", "30", "-f", "json", "-o", str(report_json)]),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(report_json), "-t", "tls-report"]), 0)
            self.assertEqual(main(["tls", "report", "-i", str(evidence), "-o", str(report_md)]), 0)
            self.assertEqual(main(["tls", "report", "-i", str(evidence), "-f", "csv", "-o", str(report_csv)]), 0)
            self.assertEqual(
                main(["tls", "report", "-i", str(evidence), "--fail-on-warn", "-o", str(temp / "warn.md")]),
                1,
            )
            self.assertIn("# OpenOps TLS Certificate Report", report_md.read_text(encoding="utf-8"))
            self.assertIn("hostname,port,status", report_csv.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
