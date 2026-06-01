import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.waivers import validate_waiver_document, waiver_index


class WaiverTests(unittest.TestCase):
    def test_validate_waiver_document_accepts_valid_waiver(self):
        errors = validate_waiver_document(
            {
                "metadata": {"name": "accepted risks"},
                "waivers": [
                    {
                        "check_id": "mail_dmarc_policy",
                        "owner": "ops@example.invalid",
                        "reason": "Monitoring rollout.",
                        "expires_at": "2099-12-31T00:00:00+00:00",
                    }
                ],
            }
        )
        self.assertEqual(errors, [])

    def test_validate_waiver_document_reports_errors(self):
        errors = validate_waiver_document(
            {
                "metadata": "bad",
                "waivers": [
                    {
                        "check_id": "duplicate",
                        "owner": "",
                        "reason": "ok",
                        "expires_at": "not-a-date",
                    },
                    {
                        "check_id": "duplicate",
                        "owner": "ops@example.invalid",
                        "reason": "",
                        "expires_at": "2099-12-31T00:00:00+00:00",
                    },
                ],
            }
        )
        self.assertIn("metadata must be a table/object when present.", errors)
        self.assertIn("waivers[0].owner must be a non-empty string.", errors)
        self.assertIn("waivers[0].expires_at must be an ISO 8601 timestamp string.", errors)
        self.assertIn("waivers[1].check_id duplicates another waiver: duplicate", errors)
        self.assertIn("waivers[1].reason must be a non-empty string.", errors)

    def test_waiver_index_marks_active_and_expired(self):
        indexed = waiver_index(
            {
                "waivers": [
                    {
                        "check_id": "active",
                        "owner": "ops@example.invalid",
                        "reason": "Accepted until migration.",
                        "expires_at": "2027-01-01T00:00:00+00:00",
                    },
                    {
                        "check_id": "expired",
                        "owner": "ops@example.invalid",
                        "reason": "Old exception.",
                        "expires_at": "2025-01-01T00:00:00+00:00",
                    },
                ]
            },
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )
        self.assertEqual(indexed["active"]["status"], "active")
        self.assertEqual(indexed["expired"]["status"], "expired")

    def test_cli_waiver_validate(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "waivers.toml"
            path.write_text(
                "\n".join(
                    [
                        "[[waivers]]",
                        'check_id = "mail_dmarc_policy"',
                        'owner = "ops@example.invalid"',
                        'reason = "Synthetic accepted risk."',
                        'expires_at = "2099-12-31T00:00:00+00:00"',
                    ]
                ),
                encoding="utf-8",
            )

            self.assertEqual(main(["waiver", "validate", str(path)]), 0)


if __name__ == "__main__":
    unittest.main()
