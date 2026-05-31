import unittest

from openops_evidence.schema import validate_evidence, validate_report


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


if __name__ == "__main__":
    unittest.main()
