"""Characterize bounded alert-intake public-key admission."""

from __future__ import annotations

import ast
import base64
import binascii
import importlib.util
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
INSTALLER_PATH = ROOT / "n8n/bin/install-alert-intake-authorized-key.py"
SPEC = importlib.util.spec_from_file_location(
    "alert_intake_key_admission", INSTALLER_PATH
)
installer = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(installer)


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(INSTALLER_PATH.read_text(encoding="utf-8"))
    target = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )

    class Complexity(ast.NodeVisitor):
        def __init__(self):
            self.value = 1

        def visit_FunctionDef(self, node):
            return

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_If(self, node):
            self.value += 1
            self.generic_visit(node)

        visit_For = visit_If
        visit_While = visit_If

        def visit_Try(self, node):
            self.value += len(node.handlers)
            self.generic_visit(node)

        def visit_BoolOp(self, node):
            self.value += max(0, len(node.values) - 1)
            self.generic_visit(node)

        def visit_ListComp(self, node):
            self.value += sum(
                1 + len(generator.ifs) for generator in node.generators
            )
            self.generic_visit(node)

    visitor = Complexity()
    for child in target.body:
        visitor.visit(child)
    return target.end_lineno - target.lineno + 1, visitor.value


def synthetic_key(label: str = "arr263") -> tuple[str, bytes]:
    payload = base64.b64encode(f"synthetic-{label}".encode("ascii")).decode("ascii")
    return payload, f"ssh-ed25519 {payload} {label}@test\n".encode("ascii")


class AlertIntakeKeyAdmissionTests(unittest.TestCase):
    def test_key_admission_phases_meet_architecture_contract(self) -> None:
        for name in (
            "_decode_key_input",
            "_single_key_line",
            "_key_identity",
            "_validate_key_payload",
            "read_public_key",
        ):
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)

    def _read(self, raw: bytes):
        calls: list[tuple[int, int]] = []

        def read(descriptor: int, maximum: int) -> bytes:
            calls.append((descriptor, maximum))
            return raw

        with mock.patch.object(installer.os, "read", side_effect=read):
            result = installer.read_public_key()
        return result, calls

    def _error(self, raw: bytes) -> tuple[SystemExit, list[tuple[int, int]]]:
        calls: list[tuple[int, int]] = []

        def read(descriptor: int, maximum: int) -> bytes:
            calls.append((descriptor, maximum))
            return raw

        with (
            mock.patch.object(installer.os, "read", side_effect=read),
            self.assertRaises(SystemExit) as raised,
        ):
            installer.read_public_key()
        return raised.exception, calls

    def test_valid_key_preserves_single_bounded_read_and_return_pair(self) -> None:
        payload, key = synthetic_key()
        result, calls = self._read(b" \r\n\t" + key.rstrip() + b" extra-comment  \n\n")
        self.assertEqual(result, ("ssh-ed25519", payload))
        self.assertEqual(calls, [(0, installer.MAX_INPUT_BYTES + 1)])

    def test_oversize_precedes_decode_and_content_validation(self) -> None:
        raw = b"\xff\\n" + b"x" * installer.MAX_INPUT_BYTES
        error, calls = self._error(raw)
        self.assertEqual(str(error), "public key input exceeds the size limit")
        self.assertIsNone(error.__cause__)
        self.assertEqual(calls, [(0, installer.MAX_INPUT_BYTES + 1)])

    def test_non_ascii_projects_exact_error_and_decode_cause(self) -> None:
        error, _ = self._error(b"ssh-ed25519 \xff\n")
        self.assertEqual(str(error), "public key must be ASCII")
        self.assertIsInstance(error.__cause__, UnicodeDecodeError)

    def test_literal_backslash_n_precedes_line_and_field_validation(self) -> None:
        error, _ = self._error(b"bad\\nssh-rsa not-base64\nsecond\n")
        self.assertEqual(
            str(error),
            "public key contains a literal " + ("\\" * 2) + "n sequence",
        )
        self.assertIsNone(error.__cause__)

    def test_exactly_one_nonblank_line_is_required(self) -> None:
        _, first = synthetic_key("first")
        _, second = synthetic_key("second")
        for raw in (b"", b" \r\n\t\n", first + second):
            with self.subTest(raw=raw[:20]):
                error, _ = self._error(raw)
                self.assertEqual(
                    str(error),
                    "provide exactly one public key on stdin",
                )
                self.assertIsNone(error.__cause__)

    def test_key_type_and_minimum_fields_share_exact_failure(self) -> None:
        invalid = (
            b"ssh-ed25519\n",
            b"ssh-rsa c3ludGhldGlj\n",
            b"c3ludGhldGlj comment\n",
        )
        for raw in invalid:
            with self.subTest(raw=raw):
                error, _ = self._error(raw)
                self.assertEqual(
                    str(error),
                    "the alert-intake identity must be one ssh-ed25519 public key",
                )
                self.assertIsNone(error.__cause__)

    def test_strict_base64_errors_preserve_cause(self) -> None:
        error, _ = self._error(b"ssh-ed25519 !!!! synthetic@test\n")
        self.assertEqual(str(error), "public key payload is not valid base64")
        self.assertIsInstance(error.__cause__, binascii.Error)

        with (
            mock.patch.object(installer.os, "read", return_value=b"ssh-ed25519 QQ==\n"),
            mock.patch.object(
                installer.base64,
                "b64decode",
                side_effect=ValueError("synthetic decode failure"),
            ),
            self.assertRaises(SystemExit) as raised,
        ):
            installer.read_public_key()
        self.assertEqual(str(raised.exception), "public key payload is not valid base64")
        self.assertIsInstance(raised.exception.__cause__, ValueError)

    def test_empty_decoded_payload_is_rejected_without_cause(self) -> None:
        with (
            mock.patch.object(installer.os, "read", return_value=b"ssh-ed25519 QQ==\n"),
            mock.patch.object(installer.base64, "b64decode", return_value=b""),
            self.assertRaises(SystemExit) as raised,
        ):
            installer.read_public_key()
        self.assertEqual(str(raised.exception), "public key payload is empty")
        self.assertIsNone(raised.exception.__cause__)

    def test_read_failure_propagates_without_retry(self) -> None:
        with (
            mock.patch.object(
                installer.os,
                "read",
                side_effect=OSError("synthetic stdin failure"),
            ) as read,
            self.assertRaisesRegex(OSError, "synthetic stdin failure"),
        ):
            installer.read_public_key()
        read.assert_called_once_with(0, installer.MAX_INPUT_BYTES + 1)


if __name__ == "__main__":
    unittest.main()
