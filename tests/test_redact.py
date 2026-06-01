import unittest

from openops_evidence.redact import redact_document


class RedactTests(unittest.TestCase):
    def test_redacts_secret_keys_and_emails(self):
        document = {
            "token": "secret-value",
            "contact": "admin@example.com",
            "nested": {"password": "pw"},
        }
        redacted = redact_document(document)
        self.assertEqual(redacted["token"], "<redacted>")
        self.assertEqual(redacted["nested"]["password"], "<redacted>")
        self.assertEqual(redacted["contact"], "<email>")

    def test_redacts_common_compound_secret_keys(self):
        document = {
            "refresh_token": "refresh",
            "github_token": "ghp_x",
            "secret_key": "secret",
            "privateKey": "private",
            "session_cookie": "cookie",
            "nested": {"apiKey": "api"},
        }
        redacted = redact_document(document)
        self.assertEqual(redacted["refresh_token"], "<redacted>")
        self.assertEqual(redacted["github_token"], "<redacted>")
        self.assertEqual(redacted["secret_key"], "<redacted>")
        self.assertEqual(redacted["privateKey"], "<redacted>")
        self.assertEqual(redacted["session_cookie"], "<redacted>")
        self.assertEqual(redacted["nested"]["apiKey"], "<redacted>")


if __name__ == "__main__":
    unittest.main()
