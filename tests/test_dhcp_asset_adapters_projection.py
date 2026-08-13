from __future__ import annotations

import ast
import copy
import datetime as dt
import importlib
import inspect
import json
import stat
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

ADAPTERS = importlib.import_module("dhcp_asset_adapters")


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse((BIN / "dhcp_asset_adapters.py").read_text(encoding="utf-8"))
    target = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    complexity = 1
    for node in ast.walk(target):
        if node is target:
            continue
        if isinstance(node, (ast.If, ast.For, ast.While, ast.IfExp, ast.Assert)):
            complexity += 1
        elif isinstance(node, ast.Try):
            complexity += len(node.handlers)
        elif isinstance(node, ast.BoolOp):
            complexity += max(0, len(node.values) - 1)
        elif isinstance(node, ast.comprehension):
            complexity += 1 + len(node.ifs)
    return target.end_lineno - target.lineno + 1, complexity


class TracedPath:
    def __init__(self, *, calls, text="", regular=True, symlink=False, mode=0o600, size=1):
        self.calls = calls
        self.text = text
        self.regular = regular
        self.symlink = symlink
        self.metadata = SimpleNamespace(st_uid=9001, st_mode=mode, st_size=size)

    def lstat(self):
        self.calls.append("lstat")
        return self.metadata

    def is_file(self):
        self.calls.append("is_file")
        return self.regular

    def is_symlink(self):
        self.calls.append("is_symlink")
        return self.symlink

    def read_text(self, *, encoding):
        self.calls.append(("read_text", encoding))
        return self.text


class DhcpAssetAdaptersProjectionTests(unittest.TestCase):
    def config(self):
        return {
            "host": "10.88.8.8",
            "ssh_user": "sentinel",
            "ssh_key": "/keys/dhcp",
            "known_hosts": "/keys/known_hosts",
            "connect_timeout_seconds": 17,
            "timeout_seconds": 91,
            "max_response_bytes": 65536,
            "max_stderr_bytes": 4096,
        }

    def test_signatures_and_decomposed_phase_bounds_are_stable(self) -> None:
        self.assertEqual(
            str(inspect.signature(ADAPTERS.asset_store_token)),
            "(path: 'Path') -> 'str'",
        )
        self.assertEqual(
            str(inspect.signature(ADAPTERS.relay_failure_diagnostic)),
            "(stdout: 'object', stderr: 'object') -> 'str'",
        )
        self.assertEqual(
            str(inspect.signature(ADAPTERS.query_dhcp)),
            "(config: 'dict', start: 'dt.datetime', end: 'dt.datetime', "
            "size: 'int', *, now_fn, run_command_fn, validate_response_fn, "
            "diagnostic_fn) -> 'dict'",
        )
        for name in (
            "_validate_asset_store_environment",
            "_environment_values",
            "_asset_store_write_token",
            "asset_store_token",
            "_normalized_diagnostic_text",
            "_relay_payload_diagnostics",
            "relay_failure_diagnostic",
            "_validated_query_window",
            "_validate_query_size",
            "_query_request",
            "_query_command",
            "_run_relay_query",
            "_validated_query_result",
            "query_dhcp",
        ):
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)

    def test_asset_token_preserves_metadata_short_circuit_and_read_order(self) -> None:
        calls = []
        path = TracedPath(calls=calls, regular=False)
        with mock.patch.object(ADAPTERS.os, "geteuid", side_effect=lambda: calls.append("geteuid") or 9001):
            with self.assertRaisesRegex(ValueError, "owner-controlled"):
                ADAPTERS.asset_store_token(path)
        self.assertEqual(calls, ["lstat", "is_file"])

        calls = []
        path = TracedPath(
            calls=calls,
            text=(
                "# ignored\nmissing-delimiter\n"
                " N8N_POST_COMMIT_TOKEN = " + "f" * 32 + " \n"
                "ASSET_STORE_WRITE_TOKEN=" + "a" * 32 + "\n"
                "ASSET_STORE_WRITE_TOKEN=" + "b" * 32 + "\n"
            ),
        )
        with mock.patch.object(ADAPTERS.os, "geteuid", side_effect=lambda: calls.append("geteuid") or 9001):
            result = ADAPTERS.asset_store_token(path)
        self.assertEqual(result, "b" * 32)
        self.assertEqual(
            calls,
            ["lstat", "is_file", "is_symlink", "geteuid", ("read_text", "utf-8")],
        )

    def test_asset_token_preserves_identity_policy_fallback_and_errors(self) -> None:
        invalid = [
            {"symlink": True},
            {"mode": 0o640},
            {"size": 1024 * 1024 + 1},
        ]
        for values in invalid:
            with self.subTest(values=values):
                calls = []
                path = TracedPath(calls=calls, text="N8N_POST_COMMIT_TOKEN=" + "x" * 32, **values)
                with mock.patch.object(ADAPTERS.os, "geteuid", return_value=9001), self.assertRaisesRegex(
                    ValueError, "owner-controlled"
                ):
                    ADAPTERS.asset_store_token(path)

        fallback = TracedPath(
            calls=[],
            text="N8N_POST_COMMIT_TOKEN=" + "z" * 32,
        )
        with mock.patch.object(ADAPTERS.os, "geteuid", return_value=9001):
            self.assertEqual(ADAPTERS.asset_store_token(fallback), "z" * 32)
        short = TracedPath(calls=[], text="ASSET_STORE_WRITE_TOKEN=short")
        with mock.patch.object(ADAPTERS.os, "geteuid", return_value=9001), self.assertRaisesRegex(
            ValueError, "missing or too short"
        ):
            ADAPTERS.asset_store_token(short)

    def test_relay_diagnostic_preserves_allowlist_order_normalization_and_bounds(self) -> None:
        stdout = json.dumps(
            {
                "upstream_detail": " third\n" + "d" * 400,
                "ignored": "must-not-appear",
                "error": " first\u0000  value ",
                "upstream_error": 7,
            }
        )
        stderr = " stderr\t" + "s" * 400
        result = ADAPTERS.relay_failure_diagnostic(stdout, stderr)
        self.assertEqual(
            result,
            "first value; " + ("third " + "d" * 400)[:300] + "; " + ("stderr " + "s" * 400)[:300],
        )
        self.assertNotIn("must-not-appear", result)
        self.assertEqual(len(result), 615)

        bounded = ADAPTERS.relay_failure_diagnostic(
            json.dumps({
                "error": "a" * 400,
                "upstream_error": "b" * 400,
                "upstream_detail": "c" * 400,
            }),
            "d" * 400,
        )
        self.assertEqual(len(bounded), 700)
        self.assertEqual(bounded, ("a" * 300 + "; " + "b" * 300 + "; " + "c" * 300 + "; " + "d" * 300)[:700])

    def test_relay_diagnostic_preserves_invalid_json_and_stderr_coercion(self) -> None:
        self.assertEqual(
            ADAPTERS.relay_failure_diagnostic("not-json", " line\nwith\x00 control "),
            "line with control",
        )
        self.assertEqual(ADAPTERS.relay_failure_diagnostic(None, None), "")

    def test_query_preserves_request_command_calls_and_return_identity(self) -> None:
        start = dt.datetime(2026, 8, 5, 12, tzinfo=dt.timezone(dt.timedelta(hours=2)))
        end = start + dt.timedelta(minutes=30)
        config = self.config()
        before = copy.deepcopy(config)
        calls = []
        response = {"ok": True, "observations": []}
        returned = {"validated": True}

        def run(command, **kwargs):
            calls.append(("run", command, kwargs))
            return SimpleNamespace(returncode=0, stdout=json.dumps(response), stderr="unused")

        def validate(payload, **kwargs):
            calls.append(("validate", payload, kwargs))
            return returned

        now = mock.Mock(
            side_effect=lambda: calls.append(("now",))
            or dt.datetime(2026, 8, 5, 13, tzinfo=dt.timezone.utc)
        )
        diagnostic = mock.Mock(side_effect=AssertionError("diagnostic must not run"))
        result = ADAPTERS.query_dhcp(
            config,
            start,
            end,
            1000,
            now_fn=now,
            run_command_fn=run,
            validate_response_fn=validate,
            diagnostic_fn=diagnostic,
        )

        expected_window = {
            "start": "2026-08-05T10:00:00.000Z",
            "end": "2026-08-05T10:30:00.000Z",
        }
        expected_request = {
            "contract": ADAPTERS.CONTRACT,
            "operation": "dhcp_observations",
            "window": expected_window,
            "size": 1000,
        }
        self.assertIs(result, returned)
        self.assertEqual(config, before)
        self.assertEqual(calls[0], ("now",))
        self.assertEqual(
            calls[1][1],
            [
                "/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o",
                "IdentitiesOnly=yes", "-o", "ConnectTimeout=17", "-o",
                "StrictHostKeyChecking=yes", "-o",
                "UserKnownHostsFile=/keys/known_hosts", "-i", "/keys/dhcp",
                "sentinel@10.88.8.8",
            ],
        )
        self.assertEqual(
            calls[1][2],
            {
                "stdin_text": json.dumps(expected_request, separators=(",", ":"), sort_keys=True),
                "timeout_seconds": 91,
                "max_stdout_bytes": 65536,
                "max_stderr_bytes": 4096,
            },
        )
        self.assertEqual(calls[2], ("validate", response, {"expected_window": expected_window}))

    def test_query_preserves_validation_order_and_nonzero_diagnostic_error(self) -> None:
        config = self.config()
        now = dt.datetime(2026, 8, 5, 13, tzinfo=dt.timezone.utc)
        cases = [
            (
                dt.datetime(2026, 8, 5, 12, tzinfo=dt.timezone.utc),
                dt.datetime(2026, 8, 5, 12, tzinfo=dt.timezone.utc),
                1,
                "window must be positive",
                0,
            ),
            (
                dt.datetime(2026, 8, 4, 0, tzinfo=dt.timezone.utc),
                dt.datetime(2026, 8, 5, 1, tzinfo=dt.timezone.utc),
                1,
                "window must be positive",
                0,
            ),
            (
                dt.datetime(2026, 8, 5, 12, tzinfo=dt.timezone.utc),
                dt.datetime(2026, 8, 5, 13, 6, tzinfo=dt.timezone.utc),
                1,
                "too far in the future",
                1,
            ),
            (
                dt.datetime(2026, 8, 5, 12, tzinfo=dt.timezone.utc),
                dt.datetime(2026, 8, 5, 12, 30, tzinfo=dt.timezone.utc),
                True,
                "size must be",
                1,
            ),
        ]
        for start, end, size, message, now_calls in cases:
            with self.subTest(message=message):
                now_fn = mock.Mock(return_value=now)
                with self.assertRaisesRegex(ValueError, message):
                    ADAPTERS.query_dhcp(
                        config,
                        start,
                        end,
                        size,
                        now_fn=now_fn,
                        run_command_fn=mock.Mock(side_effect=AssertionError("must not run")),
                        validate_response_fn=mock.Mock(),
                        diagnostic_fn=mock.Mock(),
                    )
                self.assertEqual(now_fn.call_count, now_calls)

        proc = SimpleNamespace(returncode=23, stdout="out", stderr="err")
        diagnostic = mock.Mock(return_value="bounded detail")
        validate = mock.Mock(side_effect=AssertionError("must not validate"))
        with self.assertRaisesRegex(RuntimeError, "relay returned 23: bounded detail"):
            ADAPTERS.query_dhcp(
                config,
                dt.datetime(2026, 8, 5, 12, tzinfo=dt.timezone.utc),
                dt.datetime(2026, 8, 5, 12, 30, tzinfo=dt.timezone.utc),
                1,
                now_fn=lambda: now,
                run_command_fn=lambda *_args, **_kwargs: proc,
                validate_response_fn=validate,
                diagnostic_fn=diagnostic,
            )
        diagnostic.assert_called_once_with("out", "err")
        validate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
