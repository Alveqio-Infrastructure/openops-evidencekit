import unittest

from openops_evidence.policy import Check, evaluate_check, evaluate_policy


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


if __name__ == "__main__":
    unittest.main()
