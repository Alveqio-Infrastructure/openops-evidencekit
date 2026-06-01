import json
import tempfile
import unittest
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.privacy import render_privacy_scan_markdown, scan_privacy
from openops_evidence.schema import validate_privacy_scan


class PrivacyScanTests(unittest.TestCase):
    def test_scan_privacy_detects_sensitive_patterns_without_echoing_secret(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "evidence.json"
            path.write_text(
                "\n".join(
                    [
                        '{"api_key": "super-secret-value",',
                        '"contact": "admin@example.com",',
                        '"host": "10.10.0.5"}',
                    ]
                ),
                encoding="utf-8",
            )

            scan = scan_privacy([path])

        self.assertEqual(validate_privacy_scan(scan), [])
        self.assertEqual(scan["summary"]["status"], "fail")
        self.assertGreaterEqual(scan["summary"]["findings_count"], 3)
        excerpts = "\n".join(finding["excerpt"] for finding in scan["findings"])
        self.assertIn("<match>", excerpts)
        self.assertNotIn("super-secret-value", excerpts)

    def test_scan_privacy_passes_clean_redacted_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "evidence.redacted.json"
            path.write_text('{"api_key":"<redacted>","contact":"<email>","host":"<ipv4>"}\n', encoding="utf-8")

            scan = scan_privacy([path])

        self.assertEqual(validate_privacy_scan(scan), [])
        self.assertEqual(scan["summary"]["status"], "pass")
        self.assertEqual(scan["summary"]["findings_count"], 0)

    def test_render_privacy_scan_markdown(self):
        scan = {
            "schema_version": "0.1",
            "generated_at": "2026-06-01T10:00:00+00:00",
            "summary": {
                "status": "fail",
                "files_scanned": 1,
                "files_skipped": 0,
                "findings_count": 1,
                "high_count": 1,
                "medium_count": 0,
                "low_count": 0,
            },
            "findings": [
                {
                    "path": "evidence.json",
                    "line": 1,
                    "kind": "token",
                    "severity": "high",
                    "excerpt": "token=<match>",
                }
            ],
        }

        rendered = render_privacy_scan_markdown(scan)

        self.assertIn("# OpenOps Privacy Scan", rendered)
        self.assertIn("token", rendered)

    def test_cli_privacy_scan_and_validation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            artifact = temp / "artifact.txt"
            output = temp / "privacy-scan.json"
            artifact.write_text("password = hunter2-secret\n", encoding="utf-8")

            exit_code = main(["privacy", "scan", str(artifact), "-o", str(output)])
            fail_exit_code = main(["privacy", "scan", str(artifact), "--fail-on-findings", "-o", str(temp / "fail.json")])

            self.assertEqual(exit_code, 0)
            self.assertEqual(fail_exit_code, 1)
            scan = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(scan["summary"]["status"], "fail")
            self.assertEqual(main(["validate", "-i", str(output), "-t", "privacy-scan"]), 0)


if __name__ == "__main__":
    unittest.main()
