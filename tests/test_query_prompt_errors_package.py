from __future__ import annotations

import hashlib
import unittest

from n8n.onion_sentinel.analysis.query import prompt_errors


class QueryPromptErrorsPackageTests(unittest.TestCase):
    def test_categories_are_ordered_and_raw_content_is_not_returned(self) -> None:
        cases = {
            "authorization_denied": "forbidden event tuple",
            "execution_timeout": "broker timed out",
            "backend_unavailable": "connection refused",
            "duplicate_request": "query already executed",
            "invalid_broker_response": "malformed response from transport",
            "request_contract_rejection": "unsupported query_dsl field",
            "query_execution_failure": "opaque internal detail secret-value",
        }
        for expected, reason in cases.items():
            with self.subTest(expected=expected):
                category = prompt_errors.category(reason)
                self.assertEqual(category, expected)
                self.assertNotIn(reason, category)

    def test_digest_binds_bounded_raw_error_without_exposing_it(self) -> None:
        seen = []

        def canonical(value):
            seen.append(value)
            return hashlib.sha256(value.encode()).hexdigest()

        raw = "x" * 1200
        digest = prompt_errors.digest(raw, canonical)
        self.assertEqual(len(seen[0]), 1000)
        self.assertEqual(digest, hashlib.sha256(seen[0].encode()).hexdigest())
        self.assertNotIn(raw, digest)


if __name__ == "__main__":
    unittest.main()
