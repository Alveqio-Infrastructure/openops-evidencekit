import unittest

from openops_evidence.pathquery import query


class PathQueryTests(unittest.TestCase):
    def test_query_nested_value(self):
        document = {"signals": {"backup": {"last_success_at": "now"}}}
        self.assertEqual(query(document, "signals.backup.last_success_at"), ["now"])

    def test_query_wildcard_values(self):
        document = {"assets": [{"hostname": "a"}, {"hostname": "b"}]}
        self.assertEqual(query(document, "assets[*].hostname"), ["a", "b"])

    def test_query_missing_returns_empty_list(self):
        self.assertEqual(query({"a": {"b": 1}}, "a.c"), [])


if __name__ == "__main__":
    unittest.main()
