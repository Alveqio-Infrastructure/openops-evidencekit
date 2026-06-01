import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.freshness import create_freshness_report, render_freshness_csv, render_freshness_markdown
from openops_evidence.schema import validate_freshness_report


ROOT = Path(__file__).resolve().parents[1]


class FreshnessReportTests(unittest.TestCase):
    def test_create_report_classifies_timestamp_statuses(self):
        evidence = {
            "schema_version": "0.1",
            "generated_at": "2026-06-01T09:00:00+00:00",
            "metadata": {"source": "unit-test", "organization": "Example", "environment": "test"},
            "assets": [],
            "signals": {
                "backup": {"last_success_at": "2026-05-01T00:00:00+00:00"},
                "tls": {"certificates": [{"not_after": "2026-08-01T00:00:00+00:00"}]},
                "docs": {"inventory_updated_at": "not-a-date"},
            },
        }

        report = create_freshness_report(
            evidence,
            max_age_days=7,
            now=datetime(2026, 6, 1, 12, tzinfo=UTC),
        )

        self.assertEqual(validate_freshness_report(report), [])
        self.assertEqual(report["summary"]["status"], "warn")
        self.assertEqual(report["summary"]["stale_count"], 1)
        self.assertEqual(report["summary"]["future_count"], 1)
        self.assertEqual(report["summary"]["invalid_count"], 1)
        self.assertEqual(report["summary"]["current_count"], 1)
        statuses = {item["path"]: item["status"] for item in report["timestamps"]}
        self.assertEqual(statuses["signals.backup.last_success_at"], "stale")
        self.assertEqual(statuses["signals.tls.certificates[0].not_after"], "future")
        self.assertEqual(statuses["signals.docs.inventory_updated_at"], "invalid")
        self.assertIn("# OpenOps Evidence Freshness Report", render_freshness_markdown(report))
        self.assertIn("path,status,value", render_freshness_csv(report))

    def test_cli_outputs_all_formats_and_fail_on_warn(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            json_report = temp / "freshness-report.json"
            markdown = temp / "freshness-report.md"
            csv = temp / "freshness-report.csv"
            stale_evidence = temp / "stale-evidence.json"
            stale_evidence.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "generated_at": "2026-05-01T00:00:00+00:00",
                        "metadata": {},
                        "assets": [],
                        "signals": {"backup": {"last_success_at": "2026-05-01T00:00:00+00:00"}},
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                main(
                    [
                        "freshness",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "--max-age-days",
                        "365",
                        "-f",
                        "json",
                        "-o",
                        str(json_report),
                    ]
                ),
                0,
            )
            self.assertEqual(main(["validate", "-i", str(json_report), "-t", "freshness-report"]), 0)
            self.assertGreater(json.loads(json_report.read_text(encoding="utf-8"))["summary"]["timestamps_total"], 0)
            self.assertEqual(
                main(
                    [
                        "freshness",
                        "report",
                        "-i",
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "--max-age-days",
                        "365",
                        "-o",
                        str(markdown),
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
                        str(ROOT / "examples" / "evidence.sample.json"),
                        "--max-age-days",
                        "365",
                        "-f",
                        "csv",
                        "-o",
                        str(csv),
                    ]
                ),
                0,
            )
            self.assertIn("# OpenOps Evidence Freshness Report", markdown.read_text(encoding="utf-8"))
            self.assertIn("path,status,value", csv.read_text(encoding="utf-8"))
            self.assertEqual(
                main(
                    [
                        "freshness",
                        "report",
                        "-i",
                        str(stale_evidence),
                        "--max-age-days",
                        "0",
                        "--fail-on-warn",
                        "-o",
                        str(temp / "stale.md"),
                    ]
                ),
                1,
            )


if __name__ == "__main__":
    unittest.main()
