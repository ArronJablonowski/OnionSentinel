#!/usr/bin/env python3
"""Characterization tests for concrete AI startup runtime binding."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
if str(N8N_ROOT) not in sys.path:
    sys.path.insert(0, str(N8N_ROOT))

from onion_sentinel import startup_runtime_adapter


class StartupRuntimeAdapterTests(unittest.TestCase):
    def test_latest_prompt_is_ordered_and_missing_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            first = root / "20260101-ai-prompt.json"
            latest = root / "20260102-ai-prompt.json"
            first.write_text("{}", encoding="utf-8")
            latest.write_text("{}", encoding="utf-8")
            self.assertEqual(startup_runtime_adapter.latest_prompt(root), latest)
            first.unlink()
            latest.unlink()
            with self.assertRaisesRegex(SystemExit, "no prompt packages found"):
                startup_runtime_adapter.latest_prompt(root)

    def test_generate_prompt_preserves_bounded_builder_contract(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            builder = root / "build-ai-investigation-prompt.py"
            output = root / "generated-ai-prompt.json"
            builder.write_text("# synthetic builder fixture\n", encoding="utf-8")
            output.write_text("{}", encoding="utf-8")
            observed: dict[str, object] = {}

            def run(command, **kwargs):
                observed["command"] = command
                observed["kwargs"] = kwargs
                return SimpleNamespace(
                    returncode=0, stdout=f"note\n{output}\n", stderr=""
                )

            args = SimpleNamespace(
                levels="critical,high",
                hours=24,
                related_limit=8,
                correlation_limit=12,
                correlation_min_score=55,
                max_prompt_bytes=524288,
                prompt_dir=root / "prompts",
                timeout=999,
            )
            result = startup_runtime_adapter.generate_prompt(
                {
                    "BIN_DIR": root,
                    "run_bounded_command": run,
                    "BoundedProcessError": RuntimeError,
                },
                args,
            )

            self.assertEqual(result, output)
            command = observed["command"]
            self.assertEqual(command[1], str(builder))
            self.assertEqual(command[2:], [
                "--levels", "critical,high", "--hours", "24",
                "--related-limit", "8", "--correlation-limit", "12",
                "--correlation-min-score", "55", "--max-package-bytes",
                "524288", "--out-dir", str(args.prompt_dir),
            ])
            self.assertEqual(observed["kwargs"], {
                "timeout_seconds": 300,
                "max_stdout_bytes": 16 * 1024,
                "max_stderr_bytes": 256 * 1024,
            })

    def test_generate_prompt_rejects_nonexistent_reported_path(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "build-ai-investigation-prompt.py").write_text(
                "# synthetic builder fixture\n", encoding="utf-8"
            )
            args = SimpleNamespace(
                levels="high", hours=1, related_limit=1,
                correlation_limit=1, correlation_min_score=1,
                max_prompt_bytes=262144, prompt_dir=root, timeout=30,
            )
            with self.assertRaisesRegex(SystemExit, "valid path"):
                startup_runtime_adapter.generate_prompt(
                    {
                        "BIN_DIR": root,
                        "run_bounded_command": lambda *_args, **_kwargs: (
                            SimpleNamespace(
                                returncode=0,
                                stdout=str(root / "missing.json"),
                                stderr="",
                            )
                        ),
                        "BoundedProcessError": RuntimeError,
                    },
                    args,
                )


if __name__ == "__main__":
    unittest.main()
