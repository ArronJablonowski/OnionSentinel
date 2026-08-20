import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = ROOT / "n8n/bin/sqlite_backup_recovery_gate.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "sqlite_backup_recovery_gate",
        GATE_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SqliteBackupRecoveryGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gate = load_module()

    def test_fresh_backup_returns_without_sleeping(self):
        with tempfile.TemporaryDirectory() as temporary:
            backup_dir = Path(temporary)
            (backup_dir / "alerts.sqlite3.fixture.backup.json").write_text(
                "{}",
                encoding="utf-8",
            )
            with mock.patch.object(self.gate.time, "sleep") as sleep:
                recovered = self.gate.wait_for_fresh_backup(
                    backup_dir,
                    max_age_seconds=7200,
                    grace_seconds=90,
                    poll_seconds=1,
                    wall_time=lambda: 1,
                    monotonic_time=lambda: 1,
                )
        self.assertTrue(recovered)
        sleep.assert_not_called()

    def test_stale_backup_can_recover_during_bounded_grace(self):
        ages = iter([7201, 12])
        monotonic = iter([0, 0, 1])
        with mock.patch.object(
            self.gate,
            "newest_backup_age_seconds",
            side_effect=lambda *_args, **_kwargs: next(ages),
        ), mock.patch.object(self.gate.time, "sleep") as sleep:
            recovered = self.gate.wait_for_fresh_backup(
                Path("/unused"),
                max_age_seconds=7200,
                grace_seconds=90,
                poll_seconds=1,
                monotonic_time=lambda: next(monotonic),
            )
        self.assertTrue(recovered)
        sleep.assert_called_once_with(1)

    def test_stale_backup_remains_failed_after_grace(self):
        monotonic = iter([0, 0, 90])
        with mock.patch.object(
            self.gate,
            "newest_backup_age_seconds",
            return_value=7201,
        ), mock.patch.object(self.gate.time, "sleep") as sleep:
            recovered = self.gate.wait_for_fresh_backup(
                Path("/unused"),
                max_age_seconds=7200,
                grace_seconds=90,
                poll_seconds=90,
                monotonic_time=lambda: next(monotonic),
            )
        self.assertFalse(recovered)
        sleep.assert_called_once_with(90)

    def test_symlinked_commit_metadata_is_not_admitted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            external = root / "external.backup.json"
            external.write_text("{}", encoding="utf-8")
            backups = root / "backups"
            backups.mkdir()
            (backups / "linked.backup.json").symlink_to(external)
            self.assertIsNone(
                self.gate.newest_backup_age_seconds(backups, now=1)
            )

    def test_evaluator_waits_before_taking_its_evaluation_timestamp(self):
        source = (ROOT / "n8n/bin/evaluate-operational-slos.py").read_text(
            encoding="utf-8"
        )
        gate_call = source.index(
            "    sqlite_backup_recovery_gate.wait_for_fresh_backup("
        )
        timestamp = source.index("    now = dt.datetime.now", gate_call)
        evaluation = source.index("    failures, snapshot = evaluate(", timestamp)
        self.assertLess(gate_call, timestamp)
        self.assertLess(timestamp, evaluation)

    def test_installer_deploys_gate_before_monitor(self):
        source = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text(
            encoding="utf-8"
        )
        gate_copy = source.index(
            'cp "$REPO_DIR/n8n/bin/sqlite_backup_recovery_gate.py" '
            '"$STACK_DIR/bin/sqlite_backup_recovery_gate.py"'
        )
        monitor_copy = source.index(
            'cp "$REPO_DIR/n8n/bin/monitor-n8n-stack.zsh" '
            '"$STACK_DIR/bin/monitor-n8n-stack.zsh"'
        )
        self.assertLess(gate_copy, monitor_copy)


if __name__ == "__main__":
    unittest.main()
