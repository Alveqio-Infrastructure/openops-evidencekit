import csv
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from openops_evidence.cli import main
from openops_evidence.policy import (
    SUPPORTED_OPERATORS,
    Check,
    create_policy_matrix,
    evaluate_check,
    evaluate_policy,
    list_policy_operators,
    parse_policy,
    render_policy_matrix_csv,
    render_policy_matrix_markdown,
    render_policy_operator_list,
    validate_policy_document,
)


class PolicyTests(unittest.TestCase):
    def test_operator_catalog_matches_supported_operators(self):
        operators = list_policy_operators()
        names = {operator["name"] for operator in operators}
        self.assertEqual(names, SUPPORTED_OPERATORS)
        self.assertEqual(len(names), len(operators))
        self.assertEqual(
            {operator["value"] for operator in operators},
            {"none", "required", "non-empty list", "numeric", "safe regex", "numeric days"},
        )

    def test_render_operator_catalog_as_json(self):
        payload = json.loads(render_policy_operator_list("json"))
        self.assertEqual(payload["operators"][0]["name"], "exists")
        self.assertIn("semantics", payload["operators"][0])

    def test_cli_policy_operators_writes_table(self):
        stdout = StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(main(["policy", "operators"]), 0)
        self.assertIn("within_days", stdout.getvalue())
        self.assertIn("safe regex", stdout.getvalue())

    def test_policy_matrix_renders_markdown_and_csv(self):
        checks = parse_policy(
            {
                "checks": [
                    {
                        "id": "backup_recent",
                        "title": "Recent backup",
                        "path": "signals.backup.last_success_at",
                        "operator": "within_days",
                        "value": 2,
                        "severity": "critical",
                        "required": True,
                        "remediation": "Configure backups.",
                    },
                    {
                        "id": "dmarc",
                        "path": "signals.mail.domains[*].dmarc",
                        "operator": "one_of",
                        "value": ["quarantine", "reject"],
                        "required": False,
                    },
                ]
            }
        )
        matrix = create_policy_matrix(checks)
        markdown = render_policy_matrix_markdown(matrix)
        csv_rows = list(csv.DictReader(StringIO(render_policy_matrix_csv(matrix))))

        self.assertEqual(matrix["summary"]["check_count"], 2)
        self.assertEqual(matrix["summary"]["required_count"], 1)
        self.assertIn("backup_recent", markdown)
        self.assertEqual(csv_rows[1]["value"], '["quarantine", "reject"]')

    def test_cli_policy_matrix_writes_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            policy = temp / "policy.toml"
            output = temp / "matrix.json"
            policy.write_text(
                "\n".join(
                    [
                        "[[checks]]",
                        'id = "backup_recent"',
                        'path = "signals.backup.last_success_at"',
                        'operator = "within_days"',
                        "value = 2",
                        'severity = "critical"',
                    ]
                ),
                encoding="utf-8",
            )

            exit_code = main(["policy", "matrix", str(policy), "-f", "json", "-o", str(output)])

            self.assertEqual(exit_code, 0)
            matrix = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(matrix["summary"]["critical_count"], 1)
            self.assertEqual(main(["validate", "-i", str(output), "-t", "policy-matrix"]), 0)

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
