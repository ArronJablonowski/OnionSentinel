"""Characterization for agent-memory verifier file classification."""
from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n" / "bin" / "verify-agent-memory.py"


def load_module():
    dependency = str(MODULE_PATH.parent)
    if dependency not in sys.path:
        sys.path.insert(0, dependency)
    spec = importlib.util.spec_from_file_location(
        "agent_memory_file_contract_target",
        MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load agent-memory verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakePath:
    def __init__(self, calls, *, exists=True, text="", error=None):
        self.calls = calls
        self.exists = exists
        self.text = text
        self.error = error

    def is_file(self):
        self.calls.append(("is_file",))
        return self.exists

    def read_text(self, *, encoding, errors):
        self.calls.append(("read_text", encoding, errors))
        if self.error is not None:
            raise self.error
        return self.text


class AgentMemoryFileContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def invoke(
        self,
        *,
        exists=True,
        readable=True,
        writable=True,
        text="",
        error=None,
        managed=False,
    ):
        calls = []
        path = FakePath(calls, exists=exists, text=text, error=error)

        def access(candidate, mode):
            self.assertIs(candidate, path)
            calls.append(("access", mode))
            return readable if mode == os.R_OK else writable

        with mock.patch.object(self.module.os, "access", side_effect=access):
            result = self.module._file_contract(
                path,
                managed_memory=managed,
            )
        return result, calls

    def test_missing_file_short_circuits_every_other_probe(self) -> None:
        result, calls = self.invoke(exists=False, managed=True)
        self.assertEqual(result, ["missing"])
        self.assertEqual(calls, [("is_file",)])

    def test_prompt_issues_retain_access_and_content_order(self) -> None:
        cases = (
            ("", ["not-readable", "prompt-missing-memory", "prompt-missing-shared", "prompt-missing-memory_candidates"]),
            ("MEMORY", ["not-readable", "prompt-missing-shared", "prompt-missing-memory_candidates"]),
            ("shared memory", ["not-readable", "prompt-missing-memory_candidates"]),
            ("SHARED MEMORY memory_CANDIDATES", ["not-readable"]),
        )
        for text, expected in cases:
            with self.subTest(text=text):
                result, calls = self.invoke(
                    readable=False,
                    text=text,
                )
                self.assertEqual(result, expected)
                self.assertEqual(
                    calls,
                    [
                        ("is_file",),
                        ("access", os.R_OK),
                        ("read_text", "utf-8", "replace"),
                    ],
                )

    def test_nonmanaged_prompt_never_checks_writability(self) -> None:
        result, calls = self.invoke(
            readable=True,
            writable=False,
            text="memory shared memory_candidates",
        )
        self.assertEqual(result, [])
        self.assertNotIn(("access", os.W_OK), calls)

    def test_managed_marker_cardinality_and_issue_order_are_exact(self) -> None:
        start = self.module.MANAGED_START
        end = self.module.MANAGED_END
        cases = (
            ("", ["not-readable", "not-writable", "invalid-managed-section"]),
            (start, ["not-readable", "not-writable", "invalid-managed-section"]),
            (start + end, ["not-readable", "not-writable"]),
            (start + end + start, ["not-readable", "not-writable", "invalid-managed-section"]),
            (end + start, ["not-readable", "not-writable"]),
        )
        for text, expected in cases:
            with self.subTest(text=text):
                result, calls = self.invoke(
                    readable=False,
                    writable=False,
                    text=text,
                    managed=True,
                )
                self.assertEqual(result, expected)
                self.assertEqual(
                    calls,
                    [
                        ("is_file",),
                        ("access", os.R_OK),
                        ("access", os.W_OK),
                        ("read_text", "utf-8", "replace"),
                    ],
                )

    def test_read_failure_appends_to_access_issues_and_stops_content_checks(self) -> None:
        for managed, expected in (
            (False, ["not-readable", "read-failed"]),
            (True, ["not-readable", "not-writable", "read-failed"]),
        ):
            with self.subTest(managed=managed):
                result, calls = self.invoke(
                    readable=False,
                    writable=False,
                    error=OSError("synthetic read failure"),
                    managed=managed,
                )
                self.assertEqual(result, expected)
                self.assertEqual(calls[-1], ("read_text", "utf-8", "replace"))

    def test_non_oserror_read_exception_still_propagates(self) -> None:
        with self.assertRaisesRegex(ValueError, "synthetic decoding defect"):
            self.invoke(error=ValueError("synthetic decoding defect"))


if __name__ == "__main__":
    unittest.main()
