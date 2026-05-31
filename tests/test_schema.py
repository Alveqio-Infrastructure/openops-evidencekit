import unittest

from openops_evidence.schema import (
    validate_bundle_manifest,
    validate_evidence,
    validate_report,
    validate_report_comparison,
)


class SchemaTests(unittest.TestCase):
    def test_valid_minimal_evidence(self):
        errors = validate_evidence(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {},
                "assets": [],
                "signals": {},
            }
        )
        self.assertEqual(errors, [])

    def test_missing_evidence_fields_are_reported(self):
        errors = validate_evidence({})
        self.assertIn("schema_version must be a non-empty string.", errors)
        self.assertIn("signals must be an object.", errors)

    def test_valid_report(self):
        errors = validate_report(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "summary": {},
                "results": [],
            }
        )
        self.assertEqual(errors, [])

    def test_valid_bundle_manifest(self):
        errors = validate_bundle_manifest(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {},
                "artifacts": [
                    {
                        "path": "evidence.json",
                        "filename": "evidence.json",
                        "role": "evidence",
                        "media_type": "application/json",
                        "size_bytes": 128,
                        "sha256": "a" * 64,
                    }
                ],
            }
        )
        self.assertEqual(errors, [])

    def test_invalid_bundle_manifest_hash_is_reported(self):
        errors = validate_bundle_manifest(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {},
                "artifacts": [
                    {
                        "path": "evidence.json",
                        "filename": "evidence.json",
                        "role": "evidence",
                        "media_type": "application/json",
                        "size_bytes": 128,
                        "sha256": "not-a-hash",
                    }
                ],
            }
        )
        self.assertIn("artifacts[0].sha256 must be a lowercase SHA-256 hex digest.", errors)

    def test_valid_report_comparison(self):
        errors = validate_report_comparison(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "summary": {},
                "regressions": [],
                "improvements": [],
                "neutral_changes": [],
                "added": [],
                "removed": [],
            }
        )
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
