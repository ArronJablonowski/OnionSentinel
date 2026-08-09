from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_controlled_recovery import (  # noqa: E402
    ControlledRecoveryPolicy,
    ControlledRecoverySources,
    controlled_recovery_spool_pending,
    recover_controlled_evaluation_spool,
)


class SchedulerControlledRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.runtime = Path(self.temporary.name).resolve()
        self.runtime.chmod(0o700)
        self.args = SimpleNamespace(alert_store_url="http://127.0.0.1:18787")
        self.policy = ControlledRecoveryPolicy(
            max_spool_bytes=1024,
            indeterminate_submission_marker="submission_indeterminate",
        )
        self.sources = ControlledRecoverySources(
            effective_uid=lambda: self.runtime.stat().st_uid,
            owner_private_directory=mock.Mock(return_value=True),
            load_owner_private_json=mock.Mock(return_value={"payload": True}),
            validate_payload=mock.Mock(
                return_value={"analysis_id": "analysis-1"}
            ),
            post_result=mock.Mock(
                return_value={"stored_response_sha256": "A" * 64}
            ),
            terminal_success=mock.Mock(return_value=True),
            settle_frozen_memory=mock.Mock(),
        )

    def queue(self, name: str = "analysis-1.json") -> Path:
        queue_dir = self.runtime / "analysis-index-pending"
        queue_dir.mkdir(mode=0o700, exist_ok=True)
        path = queue_dir / name
        path.write_text("{}\n", encoding="utf-8")
        path.chmod(0o600)
        return path

    def recover(self) -> bool:
        return recover_controlled_evaluation_spool(
            self.sources,
            self.policy,
            self.args,
            self.runtime,
        )

    def test_missing_spool_directory_has_no_recovery_work(self) -> None:
        self.assertFalse(self.recover())
        self.sources.load_owner_private_json.assert_not_called()

    def test_exact_spool_replays_proves_and_durably_retires(self) -> None:
        spool = self.queue()

        self.assertTrue(self.recover())

        self.assertFalse(spool.exists())
        recovery = self.sources.terminal_success.call_args.args[1]
        self.assertEqual(recovery["stored_response_digest"], "a" * 64)
        self.sources.settle_frozen_memory.assert_called_once_with(
            self.runtime,
            recovery,
        )

    def test_indeterminate_replay_requires_exact_terminal_proof(self) -> None:
        spool = self.queue()
        self.sources.post_result.side_effect = RuntimeError(
            "submission_indeterminate"
        )

        self.assertTrue(self.recover())

        self.assertFalse(spool.exists())
        self.sources.terminal_success.assert_called_once()

    def test_indeterminate_replay_without_proof_keeps_spool(self) -> None:
        spool = self.queue()
        self.sources.post_result.side_effect = RuntimeError(
            "submission_indeterminate"
        )
        self.sources.terminal_success.return_value = False

        with self.assertRaisesRegex(RuntimeError, "submission_indeterminate"):
            self.recover()

        self.assertTrue(spool.exists())
        self.sources.settle_frozen_memory.assert_not_called()

    def test_filename_must_match_validated_analysis_identity(self) -> None:
        spool = self.queue("different.json")

        with self.assertRaisesRegex(RuntimeError, "filename is not exact"):
            self.recover()

        self.assertTrue(spool.exists())
        self.sources.post_result.assert_not_called()

    def test_unexpected_or_multiple_artifacts_fail_closed(self) -> None:
        queue_dir = self.runtime / "analysis-index-pending"
        queue_dir.mkdir(mode=0o700)
        unexpected = queue_dir / "note.txt"
        unexpected.write_text("unexpected\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "unexpected artifact"):
            self.recover()

        unexpected.unlink()
        self.queue("analysis-1.json")
        second = queue_dir / "analysis-2.json"
        second.write_text("{}\n", encoding="utf-8")
        second.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, "exactly one spool"):
            self.recover()

    def test_presence_check_fails_closed_for_unsafe_directory(self) -> None:
        queue_dir = self.runtime / "analysis-index-pending"
        queue_dir.mkdir(mode=0o755)

        self.assertTrue(
            controlled_recovery_spool_pending(
                self.runtime,
                effective_uid=lambda: queue_dir.stat().st_uid,
            )
        )

    def test_presence_check_is_false_when_directory_is_absent(self) -> None:
        self.assertFalse(
            controlled_recovery_spool_pending(
                self.runtime,
                effective_uid=lambda: self.runtime.stat().st_uid,
            )
        )


if __name__ == "__main__":
    unittest.main()
