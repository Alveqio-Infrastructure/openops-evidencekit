import unittest

from openops_evidence.policy import Check, evaluate_check, evaluate_policy, validate_policy_document


class PolicyTests(unittest.TestCase):
    def test_evaluate_equals_check_passes(self):
        evidence = {"signals": {"access": {"mfa_required": True}}}
        result = evaluate_check(
            evidence,
            Check(
                id="mfa",
                title="MFA",
                path="signals.access.mfa_required",
                operator="equals",
                value=True,
            ),
        )
        self.assertEqual(result["status"], "pass")

    def test_optional_failure_is_warning(self):
        evidence = {"signals": {"mail": {"domains": [{"dmarc": "none"}]}}}
        result = evaluate_check(
            evidence,
            Check(
                id="dmarc",
                title="DMARC",
                path="signals.mail.domains[*].dmarc",
                operator="one_of",
                value=["quarantine", "reject"],
                required=False,
            ),
        )
        self.assertEqual(result["status"], "warn")

    def test_policy_summary_fails_on_required_failure(self):
        evidence = {"signals": {"access": {"ssh_public_exposed": True}}}
        report = evaluate_policy(
            evidence,
            [
                Check(
                    id="ssh",
                    title="SSH",
                    path="signals.access.ssh_public_exposed",
                    operator="equals",
                    value=False,
                    severity="critical",
                )
            ],
        )
        self.assertEqual(report["summary"]["status"], "fail")
        self.assertEqual(report["summary"]["score"], 0)

    def test_validate_policy_document_accepts_valid_policy(self):
        errors = validate_policy_document(
            {
                "metadata": {"name": "test"},
                "checks": [
                    {
                        "id": "backup_recent",
                        "path": "signals.backup.last_success_at",
                        "operator": "within_days",
                        "value": 2,
                        "severity": "critical",
                        "required": True,
                    }
                ],
            }
        )
        self.assertEqual(errors, [])

    def test_validate_policy_document_reports_authoring_errors(self):
        errors = validate_policy_document(
            {
                "checks": [
                    {"id": "duplicate", "path": "signals.x", "operator": "unknown"},
                    {
                        "id": "duplicate",
                        "title": "",
                        "path": "signals.y",
                        "operator": "one_of",
                        "value": [],
                        "severity": "urgent",
                        "mode": "sometimes",
                        "required": "yes",
                    },
                    {"id": "numeric", "path": "signals.z", "operator": "within_days", "value": "soon"},
                ]
            }
        )
        self.assertIn("checks[0].operator is unsupported: unknown", errors)
        self.assertIn("checks[1].id duplicates another check id: duplicate", errors)
        self.assertIn("checks[1].title must be a non-empty string when present.", errors)
        self.assertIn("checks[1].severity is unsupported: urgent", errors)
        self.assertIn("checks[1].mode is unsupported: sometimes", errors)
        self.assertIn("checks[1].required must be a boolean when present.", errors)
        self.assertIn("checks[1].value must not be empty for operator one_of.", errors)
        self.assertIn("checks[2].value must be numeric for operator within_days.", errors)

    def test_validate_policy_document_rejects_unsafe_matches_regex(self):
        errors = validate_policy_document(
            {
                "checks": [
                    {
                        "id": "unsafe_regex",
                        "path": "signals.name",
                        "operator": "matches",
                        "value": r"(a+)+$",
                    }
                ]
            }
        )
        self.assertIn(
            "checks[0].value contains an unsafe regex pattern: "
            "nested or ambiguous repetition is not allowed",
            errors,
        )

    def test_matches_rejects_unsafe_regex_when_check_is_constructed_directly(self):
        result = evaluate_check(
            {"signals": {"name": "a" * 24 + "!"}},
            Check(
                id="unsafe_regex",
                title="Unsafe regex",
                path="signals.name",
                operator="matches",
                value=r"(a+)+$",
            ),
        )
        self.assertEqual(result["status"], "fail")
        self.assertIn("Unsafe regex pattern", result["error"])

    def test_matches_allows_simple_regex(self):
        result = evaluate_check(
            {"signals": {"name": "web-01"}},
            Check(
                id="simple_regex",
                title="Simple regex",
                path="signals.name",
                operator="matches",
                value=r"^web-[0-9]+$",
            ),
        )
        self.assertEqual(result["status"], "pass")


if __name__ == "__main__":
    unittest.main()
