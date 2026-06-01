import unittest

from openops_evidence.schema import (
    validate_action_plan,
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

    def test_patch_level_schema_versions_are_compatible(self):
        errors = validate_evidence(
            {
                "schema_version": "0.1.7",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {},
                "assets": [],
                "signals": {},
            }
        )
        self.assertEqual(errors, [])

    def test_unknown_schema_versions_are_rejected(self):
        errors = validate_evidence(
            {
                "schema_version": "0.2",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {},
                "assets": [],
                "signals": {},
            }
        )
        self.assertIn("schema_version '0.2' is not supported; expected 0.1 or 0.1.x.", errors)

    def test_malformed_schema_versions_are_rejected(self):
        errors = validate_report(
            {
                "schema_version": "0.1-beta",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "summary": {},
                "results": [],
            }
        )
        self.assertIn("schema_version must be 0.1 or 0.1.x.", errors)

    def test_valid_report(self):
        errors = validate_report(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "summary": {
                    "score": 100,
                    "status": "pass",
                    "checks_total": 1,
                    "checks_passed": 1,
                    "checks_failed": 0,
                    "checks_warn": 0,
                },
                "results": [
                    {
                        "id": "backup_recent",
                        "title": "Recent backup",
                        "status": "pass",
                        "severity": "critical",
                        "required": True,
                        "path": "signals.backup.last_success_at",
                        "operator": "within_days",
                    }
                ],
            }
        )
        self.assertEqual(errors, [])

    def test_invalid_report_contract_is_reported(self):
        errors = validate_report(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "summary": {
                    "score": 101,
                    "status": "unknown",
                    "checks_total": -1,
                    "checks_passed": 0,
                    "checks_failed": 0,
                    "checks_warn": "none",
                },
                "results": [
                    {
                        "id": "",
                        "title": "Bad",
                        "status": "unknown",
                        "severity": "urgent",
                        "required": "yes",
                        "path": 123,
                        "operator": None,
                    }
                ],
            }
        )
        self.assertIn("summary.score must be at most 100.", errors)
        self.assertIn("summary.status must be one of: fail, pass.", errors)
        self.assertIn("summary.checks_total must be at least 0.", errors)
        self.assertIn("summary.checks_warn must be an integer.", errors)
        self.assertIn("results[0].id must be a non-empty string.", errors)
        self.assertIn("results[0].status must be one of: fail, pass, warn.", errors)
        self.assertIn("results[0].severity must be one of: critical, high, low, medium.", errors)
        self.assertIn("results[0].required must be a boolean.", errors)
        self.assertIn("results[0].path must be a string.", errors)
        self.assertIn("results[0].operator must be a string.", errors)

    def test_valid_action_plan(self):
        errors = validate_action_plan(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {},
                "summary": {
                    "status": "action_required",
                    "items_total": 1,
                    "fail_count": 1,
                    "warn_count": 0,
                    "pass_count": 0,
                    "critical_count": 1,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                },
                "items": [
                    {
                        "priority": "P0",
                        "id": "backup_recent",
                        "title": "Recent backup",
                        "status": "fail",
                        "severity": "critical",
                        "required": True,
                        "path": "signals.backup.last_success_at",
                        "operator": "within_days",
                        "observed_count": 0,
                        "recommended_action": "Configure backups.",
                    }
                ],
            }
        )
        self.assertEqual(errors, [])

    def test_invalid_action_plan_is_reported(self):
        errors = validate_action_plan(
            {
                "schema_version": "0.1",
                "generated_at": "2026-05-31T10:00:00+00:00",
                "metadata": {},
                "summary": {
                    "status": "unknown",
                    "items_total": -1,
                    "fail_count": 0,
                    "warn_count": 0,
                    "pass_count": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                },
                "items": [
                    {
                        "priority": "P9",
                        "id": "",
                        "title": "Bad",
                        "status": "unknown",
                        "severity": "urgent",
                        "required": "yes",
                        "path": 123,
                        "operator": None,
                        "observed_count": -1,
                        "recommended_action": "",
                    }
                ],
            }
        )
        self.assertIn("summary.status must be one of: action_required, pass.", errors)
        self.assertIn("summary.items_total must be at least 0.", errors)
        self.assertIn("items[0].priority must be one of: P0, P1, P2, P3.", errors)
        self.assertIn("items[0].id must be a non-empty string.", errors)
        self.assertIn("items[0].required must be a boolean.", errors)
        self.assertIn("items[0].observed_count must be at least 0.", errors)

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
