import unittest

from openops_evidence.schema import (
    validate_bundle_manifest,
    validate_bundle_signature,
    validate_bundle_verification,
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

    def test_valid_bundle_verification(self):
        errors = validate_bundle_verification(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {},
                "summary": {},
                "results": [{"path": "evidence.json", "status": "verified"}],
            }
        )
        self.assertEqual(errors, [])

    def test_valid_bundle_signature(self):
        errors = validate_bundle_signature(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {"key_id": "ops-2026"},
                "manifest": {
                    "path": "manifest.json",
                    "size_bytes": 128,
                    "sha256": "a" * 64,
                },
                "signature": {
                    "algorithm": "hmac-sha256",
                    "value": "b" * 64,
                },
            }
        )
        self.assertEqual(errors, [])

    def test_invalid_bundle_signature_is_reported(self):
        errors = validate_bundle_signature(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {},
                "manifest": {
                    "path": "manifest.json",
                    "size_bytes": -1,
                    "sha256": "not-a-hash",
                },
                "signature": {
                    "algorithm": "none",
                    "value": "not-a-signature",
                },
            }
        )
        self.assertIn("manifest.size_bytes must be a non-negative integer.", errors)
        self.assertIn("manifest.sha256 must be a lowercase SHA-256 hex digest.", errors)
        self.assertIn("signature.algorithm must be hmac-sha256.", errors)
        self.assertIn("signature.value must be a lowercase SHA-256 hex digest.", errors)

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
