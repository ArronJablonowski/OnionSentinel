from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_controlled_artifacts import (  # noqa: E402
    FrozenMemoryPolicy,
    load_owner_private_json,
    owner_private_directory,
    settle_controlled_frozen_memory_artifacts,
)


class SchedulerControlledArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="onion-sentinel-controlled-artifacts-"
        )
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.uid = os.getuid()
        self.policy = FrozenMemoryPolicy()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def private_directory(self, name: str) -> Path:
        directory = self.root / name
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
        return directory

    def write_json(
        self, path: Path, value: object, *, mode: int = 0o600
    ) -> None:
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(mode)

    def load(self, path: Path, *, max_bytes: int = 4096) -> dict[str, object]:
        return load_owner_private_json(
            path,
            self.root,
            max_bytes=max_bytes,
            effective_uid=self.uid,
        )

    def test_owner_private_directory_requires_canonical_private_descendant(
        self,
    ) -> None:
        private = self.private_directory("private")
        self.assertTrue(
            owner_private_directory(
                private, self.root, effective_uid=self.uid
            )
        )
        private.chmod(0o755)
        self.assertFalse(
            owner_private_directory(
                private, self.root, effective_uid=self.uid
            )
        )
        private.chmod(0o700)
        alias = self.root / "alias"
        alias.symlink_to(private, target_is_directory=True)
        self.assertFalse(
            owner_private_directory(
                alias, self.root, effective_uid=self.uid
            )
        )
        self.assertFalse(
            owner_private_directory(
                self.root.parent, self.root, effective_uid=self.uid
            )
        )

    def test_load_owner_private_json_accepts_exact_bounded_object(self) -> None:
        directory = self.private_directory("queue")
        artifact = directory / "result.json"
        self.write_json(artifact, {"ok": True})
        self.assertEqual(self.load(artifact), {"ok": True})

    def test_load_rejects_symlink_public_oversize_and_outside_files(self) -> None:
        directory = self.private_directory("queue")
        target = directory / "target.json"
        self.write_json(target, {"ok": True})
        alias = directory / "alias.json"
        alias.symlink_to(target)
        public = directory / "public.json"
        self.write_json(public, {"ok": True}, mode=0o644)
        oversized = directory / "oversized.json"
        self.write_json(oversized, {"value": "x" * 100})
        outside = self.root.parent / f"{self.root.name}-outside.json"
        self.write_json(outside, {"ok": True})
        try:
            cases = (
                (alias, 4096, "canonical"),
                (public, 4096, "owner-only"),
                (oversized, 8, "bounded"),
                (outside, 4096, "unsafe"),
            )
            for path, limit, message in cases:
                with self.subTest(path=path.name):
                    with self.assertRaisesRegex(RuntimeError, message):
                        self.load(path, max_bytes=limit)
        finally:
            outside.unlink(missing_ok=True)

    def test_load_rejects_invalid_json_and_non_object(self) -> None:
        directory = self.private_directory("queue")
        invalid = directory / "invalid.json"
        invalid.write_text("{", encoding="utf-8")
        invalid.chmod(0o600)
        non_object = directory / "list.json"
        self.write_json(non_object, [1, 2, 3])
        with self.assertRaisesRegex(RuntimeError, "invalid JSON"):
            self.load(invalid)
        with self.assertRaisesRegex(RuntimeError, "contain an object"):
            self.load(non_object)

    def frozen_task(self) -> dict[str, object]:
        return {
            "schema": self.policy.task_schema,
            "analysis_id": "analysis-1",
            "submitted_response_sha256": "a" * 64,
            "primary": {"allowed": False, "candidates": []},
            "reviewer": {"allowed": False, "candidates": []},
        }

    def settle(self) -> None:
        settle_controlled_frozen_memory_artifacts(
            self.root,
            {
                "analysis_id": "analysis-1",
                "response_digest": "a" * 64,
            },
            policy=self.policy,
            effective_uid=self.uid,
        )

    def test_settlement_removes_exact_pending_and_committed_tasks(self) -> None:
        tasks: list[Path] = []
        for directory_name in self.policy.directory_names:
            directory = self.private_directory(directory_name)
            task = directory / "analysis-1.json"
            self.write_json(task, self.frozen_task())
            tasks.append(task)
        self.settle()
        self.assertTrue(all(not task.exists() for task in tasks))

    def test_settlement_rejects_mismatched_task_and_preserves_it(self) -> None:
        mutations = (
            ("schema", "different"),
            ("analysis_id", "different"),
            ("submitted_response_sha256", "b" * 64),
            ("primary", {"allowed": True, "candidates": []}),
            ("reviewer", {"allowed": False, "candidates": ["memory"]}),
        )
        for index, (field, value) in enumerate(mutations):
            with self.subTest(field=field):
                directory = self.private_directory(f"pending-{index}")
                policy = FrozenMemoryPolicy(directory_names=(directory.name,))
                task_path = directory / "analysis-1.json"
                task = self.frozen_task()
                task[field] = value
                self.write_json(task_path, task)
                with self.assertRaisesRegex(RuntimeError, "not exact"):
                    settle_controlled_frozen_memory_artifacts(
                        self.root,
                        {
                            "analysis_id": "analysis-1",
                            "response_digest": "a" * 64,
                        },
                        policy=policy,
                        effective_uid=self.uid,
                    )
                self.assertTrue(task_path.exists())

    def test_settlement_rejects_unsafe_memory_directory(self) -> None:
        directory = self.private_directory("memory-writeback-pending")
        directory.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError, "directory is unsafe"):
            self.settle()


if __name__ == "__main__":
    unittest.main()
