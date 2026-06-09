import csv
import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.dns import create_dns_report, render_dns_csv, render_dns_markdown
from openops_evidence.schema import validate_dns_report


ROOT = Path(__file__).resolve().parents[1]


def _evidence(domains: list) -> dict:
    return {
        "schema_version": "0.1",
        "generated_at": "2026-06-01T10:00:00+00:00",
        "metadata": {"source": "unit-test"},
        "assets": [],
        "signals": {"dns": {"domains": domains}},
    }


class DnsReportTests(unittest.TestCase):
    def test_dns_report_passes_complete_domain_evidence(self):
        report = create_dns_report(
            _evidence(
                [
                    {
                        "domain": "example.invalid",
                        "a": ["192.0.2.10"],
                        "aaaa": ["2001:db8::10"],
                        "nameservers": ["ns1.example.invalid", "ns2.example.invalid"],
                        "caa": ["0 issue \"example-ca.invalid\""],
                        "dnssec": True,
                    }
                ]
            )
        )

        self.assertEqual(validate_dns_report(report), [])
        self.assertEqual(report["summary"]["status"], "pass")
        self.assertEqual(report["summary"]["domains_with_address_records"], 1)
        self.assertEqual(report["summary"]["domains_with_dnssec"], 1)
        self.assertIn("# OpenOps DNS Hygiene Report", render_dns_markdown(report))
        rows = list(csv.DictReader(render_dns_csv(report).splitlines()))
        self.assertEqual(rows[0]["domain"], "example.invalid")

    def test_dns_report_warns_when_caa_or_dnssec_is_missing(self):
        report = create_dns_report(
            _evidence(
                [
                    {
                        "domain": "example.invalid",
                        "a": ["192.0.2.10"],
                        "nameservers": ["ns1.example.invalid"],
                    }
                ]
            )
        )

        self.assertEqual(validate_dns_report(report), [])
        self.assertEqual(report["summary"]["status"], "warn")
        self.assertEqual(report["domains"][0]["caa_present"], None)
        self.assertEqual(report["domains"][0]["dnssec"], None)

    def test_dns_report_fails_without_address_or_nameserver_evidence(self):
        report = create_dns_report(_evidence([{"domain": "example.invalid", "caa": True, "dnssec": True}]))

        self.assertEqual(validate_dns_report(report), [])
        self.assertEqual(report["summary"]["status"], "fail")
        self.assertEqual(report["summary"]["domains_failed"], 1)

    def test_dns_cli_outputs_json_markdown_csv_and_warn_exit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            json_report = temp / "dns-report.json"
            markdown = temp / "dns-report.md"
            csv_report = temp / "dns-report.csv"
            warn = temp / "warn-dns.json"
            warn.write_text(
                json.dumps(
                    _evidence(
                        [
                            {
                                "domain": "example.invalid",
                                "a": ["192.0.2.10"],
                                "nameservers": ["ns1.example.invalid"],
                            }
                        ]
                    )
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                main(
                    [
                        "dns",
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
            self.assertEqual(main(["validate", "-i", str(json_report), "-t", "dns-report"]), 0)
            self.assertEqual(
                main(["dns", "report", "-i", str(ROOT / "examples" / "evidence.sample.json"), "-o", str(markdown)]),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "dns",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "-f",
                        "csv",
                        "-o",
                        str(csv_report),
                    ]
                ),
                0,
            )
            self.assertIn("# OpenOps DNS Hygiene Report", markdown.read_text(encoding="utf-8"))
            self.assertIn("domain,status,address_record_count", csv_report.read_text(encoding="utf-8"))
            self.assertEqual(
                main(["dns", "report", "-i", str(warn), "--fail-on-warn", "-o", str(temp / "warn.md")]),
                1,
            )


if __name__ == "__main__":
    unittest.main()
