"""Characterization for Onion Sentinel web recovery supervision."""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import hashlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n" / "bin" / "ensure-onion-sentinel-web.py"


def load_module():
    spec = importlib.util.spec_from_file_location("web_recovery_workflow", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guard = load_module()


class WebRecoveryWorkflowCharacterization(unittest.TestCase):
    def test_public_surface_and_target_signatures_are_exact(self) -> None:
        names = sorted(name for name in dir(guard) if not name.startswith("__"))
        encoded = json.dumps(names, separators=(",", ":"), sort_keys=True).encode()
        self.assertEqual(
            (len(names), hashlib.sha256(encoded).hexdigest()),
            (37, "9d650591668d1267f01192b08757e7571b66a433b804df18b78bda04a4e72e54"),
        )
        self.assertEqual(
            str(inspect.signature(guard.authorize_restart)),
            "(state_path: 'Path', *, now: 'float | None' = None, window_seconds: 'int' = 900, max_restarts: 'int' = 3) -> 'tuple[bool, dict[str, object]]'",
        )
        self.assertEqual(
            str(inspect.signature(guard.recover)),
            "(port: 'int', label: 'str', health_url: 'str', plist_path: 'Path', restart_state_path: 'Path | None' = None, restart_window_seconds: 'int' = 900, max_restarts: 'int' = 3) -> 'dict[str, object]'",
        )
        self.assertEqual(str(inspect.signature(guard.main)), "() -> 'int'")

    def test_restart_budget_filters_exact_window_and_publishes_owner_only_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state" / "restart.json"
            state_path.parent.mkdir()
            state_path.write_text(
                json.dumps({"attempts": [39, 40, 90, 100, 101, "99", None]}),
                encoding="utf-8",
            )
            state_path.chmod(0o600)
            allowed, state = guard.authorize_restart(
                state_path,
                now=100,
                window_seconds=60,
                max_restarts=4,
            )
            self.assertTrue(allowed)
            self.assertEqual(
                state,
                {
                    "schema": "onion-sentinel-web-restart-budget-v1",
                    "attempts": [40.0, 90.0, 100.0, 100],
                    "window_seconds": 60,
                    "max_restarts": 4,
                    "quarantined": False,
                    "updated_at": 100,
                },
            )
            self.assertEqual(json.loads(state_path.read_text()), state)
            self.assertEqual(stat.S_IMODE(state_path.stat().st_mode), 0o600)
            self.assertEqual([path.name for path in state_path.parent.iterdir()], ["restart.json"])

    def test_restart_budget_rejects_invalid_policy_and_unsafe_or_invalid_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(RuntimeError, "^restart budget is invalid$"):
                guard.authorize_restart(root / "missing", now=1, window_seconds=0)
            state = root / "state.json"
            state.write_text("{}", encoding="utf-8")
            state.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "^restart state file permissions are too open$"):
                guard.authorize_restart(state, now=1)
            state.chmod(0o600)
            state.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "^restart state file is invalid$"):
                guard.authorize_restart(state, now=1)
            state.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "^restart state file is invalid$"):
                guard.authorize_restart(state, now=1)

    def recover(self, **patches):
        defaults = {
            "probe_health": mock.Mock(return_value=(False, "offline")),
            "listener_pids": mock.Mock(return_value=[]),
            "process_details": mock.Mock(),
            "authorize_restart": mock.Mock(return_value=(True, {"attempts": [1], "window_seconds": 90})),
            "terminate_known_simple_server": mock.Mock(),
            "ensure_started": mock.Mock(return_value=False),
        }
        defaults.update(patches)
        stack = [mock.patch.object(guard, name, value) for name, value in defaults.items()]
        stack.append(mock.patch.object(guard.os, "getuid", return_value=501))
        for patcher in stack:
            patcher.start()
            self.addCleanup(patcher.stop)
        return guard.recover(
            8766,
            "web.label",
            "http://health",
            Path("/expected/web.plist"),
            Path("/restart.json"),
            90,
            2,
        ), defaults

    def test_recovery_healthy_short_circuits_every_mutating_boundary(self) -> None:
        result, ports = self.recover(probe_health=mock.Mock(return_value=(True, "onion-sentinel")))
        self.assertEqual(result, {"ok": True, "state": "healthy", "recovered": False, "detail": "onion-sentinel"})
        ports["listener_pids"].assert_not_called()
        ports["authorize_restart"].assert_not_called()
        ports["ensure_started"].assert_not_called()

    def test_recovery_refuses_wrong_owner_unknown_and_multiple_listeners_before_budget(self) -> None:
        for details, expected in (
            ([(502, "python server.py")], {"detail": "unknown listener requires operator review", "listener_pid": 7}),
            ([(501, "python unknown.py")], {"detail": "unknown listener requires operator review", "listener_pid": 7}),
            (
                [(501, "python onion_sentinel_server.py --port 8766"), (501, "python -m http.server 8766")],
                {"detail": "multiple listeners require operator review"},
            ),
        ):
            with self.subTest(details=details):
                result, ports = self.recover(
                    listener_pids=mock.Mock(return_value=[7] if len(details) == 1 else [7, 8]),
                    process_details=mock.Mock(side_effect=details),
                )
                self.assertEqual(result["state"], "refused")
                self.assertEqual(result["detail"], expected["detail"])
                if "listener_pid" in expected:
                    self.assertEqual(result["listener_pid"], expected["listener_pid"])
                ports["authorize_restart"].assert_not_called()
                ports["ensure_started"].assert_not_called()

    def test_recovery_quarantine_preserves_budget_projection(self) -> None:
        budget = {"attempts": [1.0, 2.0], "window_seconds": 90}
        result, ports = self.recover(authorize_restart=mock.Mock(return_value=(False, budget)))
        self.assertEqual(
            result,
            {
                "ok": False,
                "state": "quarantined",
                "recovered": False,
                "detail": "automatic restart budget exhausted",
                "restart_attempts": 2,
                "restart_window_seconds": 90,
            },
        )
        ports["ensure_started"].assert_not_called()

    def test_recovery_terminates_only_exact_simple_server_then_starts_and_reprobes(self) -> None:
        probe = mock.Mock(side_effect=[(False, "offline"), (False, "warming"), (True, "onion-sentinel")])
        with mock.patch.object(guard.time, "sleep") as sleep:
            result, ports = self.recover(
                probe_health=probe,
                listener_pids=mock.Mock(return_value=[7]),
                process_details=mock.Mock(return_value=(501, "python3 -m http.server 8766")),
                ensure_started=mock.Mock(return_value=True),
            )
        self.assertEqual(
            result,
            {
                "ok": True,
                "state": "recovered",
                "recovered": True,
                "bootstrapped": True,
                "detail": "onion-sentinel",
            },
        )
        ports["authorize_restart"].assert_called_once_with(
            Path("/restart.json"), window_seconds=90, max_restarts=2
        )
        ports["terminate_known_simple_server"].assert_called_once_with(7)
        ports["ensure_started"].assert_called_once_with("web.label", Path("/expected/web.plist"))
        self.assertEqual(probe.call_args_list[1:], [
            mock.call("http://health", timeout=1.0),
            mock.call("http://health", timeout=1.0),
        ])
        sleep.assert_called_once_with(0.5)

    def test_recovery_failure_preserves_24_bounded_retries_sleeps_and_last_detail(self) -> None:
        probe = mock.Mock(side_effect=[(False, "initial")] + [(False, f"attempt-{index}") for index in range(24)])
        with mock.patch.object(guard.time, "sleep") as sleep:
            result, _ports = self.recover(probe_health=probe)
        self.assertEqual(result, {"ok": False, "state": "failed", "recovered": False, "detail": "attempt-23"})
        self.assertEqual(probe.call_count, 25)
        self.assertEqual(sleep.call_args_list, [mock.call(0.5)] * 24)

    def args(self, **changes) -> argparse.Namespace:
        values = {
            "port": 8766,
            "label": "web.label",
            "health_url": "http://health",
            "plist": None,
            "maintenance_hold": None,
            "restart_state": None,
            "restart_window_seconds": 90,
            "max_restarts": 2,
            "check_only": False,
        }
        values.update(changes)
        return argparse.Namespace(**values)

    def main_case(self, args: argparse.Namespace, *, hold=False, health=(False, "offline"), recovery=None):
        stdout = io.StringIO()
        with mock.patch.object(argparse.ArgumentParser, "parse_args", return_value=args), mock.patch.object(
            guard.Path, "home", return_value=Path("/synthetic/home")
        ), mock.patch.object(guard, "maintenance_hold_active", return_value=hold) as maintenance, mock.patch.object(
            guard, "probe_health", return_value=health
        ) as probe, mock.patch.object(
            guard, "recover", side_effect=recovery if isinstance(recovery, Exception) else None,
            return_value=recovery if isinstance(recovery, dict) else {"ok": True},
        ) as recover, redirect_stdout(stdout):
            code = guard.main()
        return code, stdout.getvalue(), maintenance, probe, recover

    def test_main_maintenance_precedes_check_and_recovery_with_default_hold_path(self) -> None:
        code, stdout, maintenance, probe, recover = self.main_case(self.args(check_only=True), hold=True)
        self.assertEqual(code, 0)
        self.assertEqual(
            stdout,
            '{"detail": "planned maintenance hold", "ok": true, "recovered": false, "state": "maintenance"}\n',
        )
        maintenance.assert_called_once_with(Path("/synthetic/home/n8n-local/logs/onion-sentinel-web-maintenance.hold"))
        probe.assert_not_called()
        recover.assert_not_called()

    def test_main_check_only_and_recovery_error_preserve_output_and_exit_contracts(self) -> None:
        code, stdout, _maintenance, probe, recover = self.main_case(
            self.args(check_only=True, maintenance_hold="/hold"), health=(False, "identity-mismatch")
        )
        self.assertEqual((code, stdout), (1, '{"detail": "identity-mismatch", "ok": false, "state": "failed"}\n'))
        probe.assert_called_once_with("http://health")
        recover.assert_not_called()

        code, stdout, _maintenance, _probe, recover = self.main_case(
            self.args(plist="/plist", restart_state="/state"),
            recovery=subprocess.SubprocessError("synthetic launchd failure"),
        )
        self.assertEqual(code, 1)
        self.assertEqual(
            stdout,
            '{"detail": "synthetic launchd failure", "ok": false, "recovered": false, "state": "failed"}\n',
        )
        recover.assert_called_once_with(8766, "web.label", "http://health", Path("/plist"), Path("/state"), 90, 2)


if __name__ == "__main__":
    unittest.main()
