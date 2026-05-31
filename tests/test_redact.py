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


if __name__ == "__main__":
    unittest.main()
