from __future__ import annotations

import ast
import copy
import importlib
import inspect
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
TRANSPORT_PATH = DASHBOARD / "ac_hunter_transport.py"


def load_transport_module():
    if str(DASHBOARD) not in sys.path:
        sys.path.insert(0, str(DASHBOARD))
    return importlib.import_module("ac_hunter_transport")


def function_metrics(qualified_name: str) -> tuple[int, int]:
    tree = ast.parse(TRANSPORT_PATH.read_text(encoding="utf-8"))
    target = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "AcHunterApiClient":
            for child in node.body:
                if isinstance(child, ast.FunctionDef) and child.name == qualified_name:
                    target = child
                    break
    if target is None:
        raise AssertionError("target function is missing")

    complexity = 1
    for node in ast.walk(target):
        if node is target:
            continue
        if isinstance(node, (ast.If, ast.For, ast.While)):
            complexity += 1
        elif isinstance(node, ast.Try):
            complexity += len(node.handlers)
        elif isinstance(node, ast.BoolOp):
            complexity += max(0, len(node.values) - 1)
        elif isinstance(node, ast.IfExp):
            complexity += 1
        elif isinstance(
            node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
        ):
            complexity += sum(1 + len(item.ifs) for item in node.generators)
    return target.end_lineno - target.lineno + 1, complexity


class FakeMorsel:
    def __init__(self, value: str) -> None:
        self.value = value


class FakeCookie:
    fixtures = {}

    def __init__(self) -> None:
        self.fixture = []

    def load(self, raw: str) -> None:
        fixture = self.fixtures[raw]
        if isinstance(fixture, BaseException):
            raise fixture
        self.fixture = fixture

    def items(self):
        return [(name, FakeMorsel(value)) for name, value in self.fixture]


class AcHunterCookieAdmissionArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.transport = load_transport_module()

    def client(self):
        return self.transport.AcHunterApiClient(
            transport=None,
            credentials_loader=lambda: ("unused@example.invalid", "unused"),
        )

    def test_signature_and_current_complexity_debt_are_exact(self) -> None:
        signature = inspect.signature(
            self.transport.AcHunterApiClient._accept_cookies
        )
        self.assertEqual(list(signature.parameters), ["self", "response"])
        self.assertEqual(str(signature.return_annotation), "None")
        for name in (
            "_parsed_cookie_items",
            "_cookie_value_is_admissible",
            "_apply_cookie_item",
            "_accept_cookies",
        ):
            lines, complexity = function_metrics(name)
            self.assertLessEqual(lines, 50)
            self.assertLessEqual(complexity, 10)
        self.assertLessEqual(len(TRANSPORT_PATH.read_text().splitlines()), 600)

    def test_response_and_header_type_admission_return_without_mutation(self) -> None:
        responses = [
            {},
            {"headers": None},
            {"headers": []},
            {"headers": {}},
            {"headers": {"set_cookie": None}},
            {"headers": {"set_cookie": "session=value"}},
            {"headers": {"set_cookie": {}}},
        ]
        for response in responses:
            with self.subTest(response=repr(response)):
                client = self.client()
                client._cookies = {"existing": "value"}
                identity = id(client._cookies)
                before = copy.deepcopy(response)
                result = client._accept_cookies(response)
                self.assertIsNone(result)
                self.assertEqual(client._cookies, {"existing": "value"})
                self.assertEqual(id(client._cookies), identity)
                self.assertEqual(response, before)

    def test_parser_validation_delete_overwrite_and_order_are_exact(self) -> None:
        FakeCookie.fixtures = {
            "raise": RuntimeError("synthetic parse failure"),
            "batch": [
                ("valid_name", "first"),
                ("invalid name", "ignored"),
                ("x" * 129, "ignored"),
                ("maximum", "x" * 4096),
                ("too_large", "x" * 4097),
                ("multibyte_ok", "é" * 2048),
                ("multibyte_large", "é" * 2049),
                ("carriage", "a\rb"),
                ("newline", "a\nb"),
                ("nul", "a\x00b"),
                ("semicolon", "a;b"),
                ("delete_me", ""),
                ("valid_name", "last"),
            ],
        }
        response = {
            "headers": {"set_cookie": [123, "raise", "batch"]},
            "body": {"untouched": True},
        }
        before = copy.deepcopy(response)
        client = self.client()
        client._cookies = {
            "delete_me": "old",
            "existing": "kept",
            "valid_name": "old",
        }
        identity = id(client._cookies)
        with mock.patch.object(self.transport, "SimpleCookie", FakeCookie):
            client._accept_cookies(response)
        self.assertEqual(id(client._cookies), identity)
        self.assertEqual(
            client._cookies,
            {
                "existing": "kept",
                "valid_name": "last",
                "maximum": "x" * 4096,
                "multibyte_ok": "é" * 2048,
            },
        )
        self.assertEqual(response, before)
        self.assertEqual(
            client._cookie_header().split("; "),
            [
                "existing=kept",
                "maximum=" + "x" * 4096,
                "multibyte_ok=" + "é" * 2048,
                "valid_name=last",
            ],
        )

    def test_real_parser_multiple_lines_and_empty_value_behavior_are_exact(self) -> None:
        response = {
            "headers": {
                "set_cookie": [
                    "session=first; Secure; HttpOnly; Path=/",
                    "secondary=bounded; SameSite=Strict; Path=/",
                    "session=final; Path=/",
                    "secondary=; Path=/",
                    "quoted=\"safe-value\"; Path=/",
                    "invalid cookie line",
                ]
            }
        }
        before = copy.deepcopy(response)
        client = self.client()
        client._cookies = {"preexisting": "kept"}
        client._accept_cookies(response)
        self.assertEqual(
            client._cookies,
            {
                "preexisting": "kept",
                "quoted": "safe-value",
                "session": "final",
            },
        )
        self.assertEqual(
            client._cookie_header(),
            "preexisting=kept; quoted=safe-value; session=final",
        )
        self.assertEqual(response, before)

    def test_successful_final_bound_replaces_state_but_errors_leave_partial_state(self) -> None:
        client = self.client()
        client._cookies = {
            "cookie-%02d" % index: "value" for index in range(20)
        }
        old_state = client._cookies
        response = {"headers": {"set_cookie": []}}
        client._accept_cookies(response)
        self.assertIsNot(client._cookies, old_state)
        self.assertEqual(len(client._cookies), 16)
        self.assertEqual(
            list(client._cookies),
            ["cookie-%02d" % index for index in range(16)],
        )

        FakeCookie.fixtures = {
            "good": [("accepted", "value")],
            "unicode-error": [("broken", "\ud800")],
            "later": [("not_reached", "value")],
        }
        client._cookies = {
            "cookie-%02d" % index: "value" for index in range(20)
        }
        partial_state = client._cookies
        failing_response = {
            "headers": {
                "set_cookie": ["good", "unicode-error", "later"]
            }
        }
        before = copy.deepcopy(failing_response)
        with mock.patch.object(self.transport, "SimpleCookie", FakeCookie):
            with self.assertRaises(UnicodeEncodeError) as raised:
                client._accept_cookies(failing_response)
        self.assertIsNone(raised.exception.__cause__)
        self.assertIs(client._cookies, partial_state)
        self.assertEqual(client._cookies["accepted"], "value")
        self.assertNotIn("broken", client._cookies)
        self.assertNotIn("not_reached", client._cookies)
        self.assertEqual(len(client._cookies), 21)
        self.assertEqual(failing_response, before)


if __name__ == "__main__":
    unittest.main()
