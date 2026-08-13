"""Characterize forced-command alert batch dispatch and acknowledgements."""

from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n/bin/onion-sentinel-alert-intake.py"


def load_module(name: str = "alert_intake_dispatch_projection"):
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("alert intake cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


intake = load_module()


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    target = next(
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    )
    complexity = 1
    for node in ast.walk(target):
        if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While)):
            complexity += 1
        elif isinstance(node, ast.Try):
            complexity += len(node.handlers)
        elif isinstance(node, ast.BoolOp):
            complexity += max(0, len(node.values) - 1)
        elif isinstance(node, ast.comprehension):
            complexity += 1 + len(node.ifs)
    return target.end_lineno - target.lineno + 1, complexity


class Rejected(Exception):
    pass


class IntakePorts:
    def __init__(self, batch: dict, times: tuple[float, ...], posts=()):
        self.parent = mock.Mock()
        self.read_batch = mock.Mock(return_value=batch)
        self.monotonic = mock.Mock(side_effect=times)
        self.post_message = mock.Mock(side_effect=posts)
        self.reject = mock.Mock(side_effect=Rejected)
        for name in ("read_batch", "monotonic", "post_message", "reject"):
            self.parent.attach_mock(getattr(self, name), name)

    def patches(self):
        return (
            mock.patch.object(intake, "read_batch", self.read_batch),
            mock.patch.object(intake.time, "monotonic", self.monotonic),
            mock.patch.object(intake, "post_message", self.post_message),
            mock.patch.object(intake, "reject", self.reject),
            mock.patch.object(intake, "BATCH_DEADLINE_SECONDS", 30),
        )


class AlertIntakeDispatchProjectionTests(unittest.TestCase):
    def test_decomposed_dispatch_owners_stay_within_quality_bounds(self):
        self.assertLessEqual(len(MODULE_PATH.read_text(encoding="utf-8").splitlines()), 250)
        for name in (
            "_admit_forced_command",
            "_validated_message",
            "_deadline_result",
            "_deliver_batch",
            "_batch_response",
            "main",
        ):
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)

    def invoke(self, ports: IntakePorts, *, command="onion-sentinel-alert-intake batch"):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.dict(
                    os.environ, {"SSH_ORIGINAL_COMMAND": command}, clear=False
                )
            )
            for patch in ports.patches():
                stack.enter_context(patch)
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                stderr
            ):
                result = intake.main()
        return result, stdout.getvalue(), stderr.getvalue()

    def test_success_and_deadline_preserve_order_calls_and_exact_output(self):
        payload_a = {"alert_id": "a"}
        payload_b = {"alert_id": "b"}
        delivered = {
            "delivery_id": "id-a",
            "ok": True,
            "retryable": False,
            "status": "accepted",
            "reason": "",
        }
        ports = IntakePorts(
            {
                "messages": [
                    {"delivery_id": " id-a ", "payload": payload_a},
                    {"delivery_id": "id-b", "payload": payload_b},
                ]
            },
            (100.0, 101.0, 130.0),
            (delivered,),
        )
        result, stdout, stderr = self.invoke(
            ports, command="  onion-sentinel-alert-intake batch\n"
        )
        expected = {
            "ok": False,
            "protocol": "onion-sentinel-alert-batch/v1",
            "processed": 2,
            "results": [
                delivered,
                {
                    "delivery_id": "id-b",
                    "ok": False,
                    "retryable": True,
                    "status": "batch_deadline",
                    "reason": "batch deadline reached before delivery",
                },
            ],
        }
        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(
            stdout,
            json.dumps(expected, separators=(",", ":"), sort_keys=True) + "\n",
        )
        self.assertEqual(
            ports.parent.mock_calls,
            [
                mock.call.read_batch(),
                mock.call.monotonic(),
                mock.call.monotonic(),
                mock.call.post_message("id-a", payload_a),
                mock.call.monotonic(),
            ],
        )

    def test_unsupported_command_rejects_before_batch_or_time_access(self):
        ports = IntakePorts({"messages": []}, ())
        with self.assertRaises(Rejected):
            self.invoke(ports, command="bash")
        self.assertEqual(
            ports.parent.mock_calls,
            [
                mock.call.reject(
                    "interactive sessions and unsupported commands are not permitted"
                )
            ],
        )

    def test_invalid_entries_preserve_exact_rejection_boundaries(self):
        cases = (
            (["not-an-object"], "alert batch entries must be objects"),
            (
                [{"delivery_id": "", "payload": {}}],
                "delivery ids must be unique, non-empty, and bounded",
            ),
            (
                [{"delivery_id": "x" * 513, "payload": {}}],
                "delivery ids must be unique, non-empty, and bounded",
            ),
            (
                [{"delivery_id": "id-a", "payload": "invalid"}],
                "alert message payload must be an object",
            ),
        )
        for messages, reason in cases:
            with self.subTest(reason=reason):
                ports = IntakePorts({"messages": messages}, (100.0,))
                with self.assertRaises(Rejected):
                    self.invoke(ports)
                self.assertEqual(
                    ports.parent.mock_calls,
                    [
                        mock.call.read_batch(),
                        mock.call.monotonic(),
                        mock.call.reject(reason),
                    ],
                )

    def test_duplicate_after_deadline_ack_rejects_without_second_time_or_post(self):
        ports = IntakePorts(
            {
                "messages": [
                    {"delivery_id": "duplicate", "payload": {"ordinal": 1}},
                    {"delivery_id": " duplicate ", "payload": {"ordinal": 2}},
                ]
            },
            (100.0, 130.0),
        )
        with self.assertRaises(Rejected):
            self.invoke(ports)
        self.assertEqual(
            ports.parent.mock_calls,
            [
                mock.call.read_batch(),
                mock.call.monotonic(),
                mock.call.monotonic(),
                mock.call.reject(
                    "delivery ids must be unique, non-empty, and bounded"
                ),
            ],
        )


if __name__ == "__main__":
    unittest.main()
