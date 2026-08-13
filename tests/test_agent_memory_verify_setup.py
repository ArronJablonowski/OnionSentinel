"""Characterization for agent-memory setup verification orchestration."""
from __future__ import annotations

import importlib.util
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
        "agent_memory_verify_setup_target",
        MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load agent-memory verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AgentMemoryVerifySetupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()
        cls.config = Path("/synthetic/config")
        cls.memory = Path("/synthetic/memory")

    @staticmethod
    def paths(config, memory, role):
        return (
            config / f"{role}.prompt",
            config / f"{role}.reviewer",
            memory / f"{role}.memory",
            memory / "shared-agent-memory.md",
        )

    def invoke(
        self,
        *,
        file_issues=None,
        memory_mismatch=(),
        execution_mismatch=(),
        builder_error=None,
    ):
        calls = []
        file_issues = file_issues or {}
        roles = {"z-role", "a-role"}

        def primary(config, role):
            calls.append(("primary_path", config, role))
            return config / f"{role}.prompt"

        def reviewer(config, role):
            calls.append(("reviewer_path", config, role))
            return config / f"{role}.reviewer"

        def memory(memory_dir, role):
            calls.append(("memory_path", memory_dir, role))
            return memory_dir / f"{role}.memory"

        def contract(path, *, managed_memory=False):
            calls.append(("file_contract", path, managed_memory))
            return list(file_issues.get(str(path), ()))

        def memory_context(**kwargs):
            role = kwargs["agent_role"]
            calls.append(("memory_context", kwargs))
            if builder_error is not None and role == "a-role":
                raise builder_error
            prompt, reviewer_path, role_memory, shared = self.paths(
                self.config,
                self.memory,
                role,
            )
            del prompt, reviewer_path
            mismatch = role in memory_mismatch
            return {
                "role_memory": {
                    "exists": not mismatch,
                    "path": str(role_memory),
                },
                "shared_memory": {
                    "exists": True,
                    "path": str(shared),
                },
            }

        def execution_context(**kwargs):
            role = kwargs["agent_role"]
            calls.append(("execution_context", kwargs))
            prompt, reviewer_path, role_memory, shared = self.paths(
                self.config,
                self.memory,
                role,
            )
            mismatch = role in execution_mismatch
            return {
                "system_prompt_file": str(prompt),
                "second_opinion_system_prompt_file": str(reviewer_path),
                "agent_memory_file": str(role_memory),
                "shared_memory_file": str(shared),
                "memory_writeback_contract": {
                    "response_field": "wrong" if mismatch else "memory_candidates"
                },
            }

        with (
            mock.patch.object(self.module, "MEMORY_ROLES", roles),
            mock.patch.object(self.module, "role_prompt_file", side_effect=primary),
            mock.patch.object(
                self.module,
                "role_second_opinion_prompt_file",
                side_effect=reviewer,
            ),
            mock.patch.object(self.module, "role_memory_file", side_effect=memory),
            mock.patch.object(self.module, "_file_contract", side_effect=contract),
            mock.patch.object(
                self.module,
                "build_agent_memory_context",
                side_effect=memory_context,
            ),
            mock.patch.object(
                self.module,
                "build_agent_execution_context",
                side_effect=execution_context,
            ),
        ):
            result = self.module.verify_setup(self.config, self.memory)
        return result, calls

    def test_success_preserves_sorted_roles_paths_builder_order_and_envelopes(self) -> None:
        result, calls = self.invoke()
        self.assertTrue(result["ok"])
        self.assertEqual(result["agent_count"], 2)
        self.assertEqual(list(result["agents"]), ["a-role", "z-role"])
        self.assertEqual(
            [call[0] for call in calls],
            [
                "file_contract",
                "primary_path",
                "reviewer_path",
                "memory_path",
                "file_contract",
                "file_contract",
                "file_contract",
                "memory_context",
                "execution_context",
                "primary_path",
                "reviewer_path",
                "memory_path",
                "file_contract",
                "file_contract",
                "file_contract",
                "memory_context",
                "execution_context",
            ],
        )
        first_memory = calls[7][1]
        self.assertEqual(first_memory["agent_role"], "a-role")
        self.assertEqual(
            first_memory["evidence"],
            {
                "verification": "agent memory contract",
                "agent_role": "a-role",
            },
        )
        self.assertEqual(first_memory["limit_bytes"], 1024)
        first_execution = calls[8][1]
        self.assertEqual(first_execution["config_dir"], self.config)
        self.assertEqual(first_execution["memory_dir"], self.memory)
        self.assertEqual(
            first_execution["evidence"],
            {
                "verification": "agent execution contract",
                "agent_role": "a-role",
            },
        )
        for role, item in result["agents"].items():
            prompt, reviewer, memory, shared = self.paths(
                self.config,
                self.memory,
                role,
            )
            self.assertEqual(item["prompt_file"], str(prompt))
            self.assertEqual(item["second_opinion_prompt_file"], str(reviewer))
            self.assertEqual(item["memory_file"], str(memory))
            self.assertEqual(item["shared_memory_file"], str(shared))
            self.assertTrue(item["read_context_ready"])
            self.assertTrue(item["execution_context_ready"])
            self.assertTrue(item["writeback_ready"])
            self.assertEqual(item["issues"], [])

    def test_file_issues_keep_prefix_order_and_skip_both_builders(self) -> None:
        a_prompt, a_reviewer, a_memory, shared = self.paths(
            self.config,
            self.memory,
            "a-role",
        )
        issues = {
            str(a_prompt): ["p1", "p2"],
            str(a_reviewer): ["r1"],
            str(a_memory): ["m1"],
            str(shared): ["s1", "s2"],
        }
        result, calls = self.invoke(file_issues=issues)
        self.assertFalse(result["ok"])
        self.assertEqual(
            result["agents"]["a-role"]["issues"],
            [
                "prompt:p1",
                "prompt:p2",
                "second-opinion-prompt:r1",
                "memory:m1",
                "shared:s1",
                "shared:s2",
            ],
        )
        builder_roles = [
            call[1]["agent_role"]
            for call in calls
            if call[0] in {"memory_context", "execution_context"}
        ]
        self.assertEqual(builder_roles, [])
        self.assertEqual(
            result["agents"]["z-role"]["issues"],
            ["shared:s1", "shared:s2"],
        )
        self.assertFalse(result["agents"]["a-role"]["read_context_ready"])
        self.assertFalse(result["agents"]["a-role"]["writeback_ready"])

    def test_classified_builder_errors_have_exact_query_issue(self) -> None:
        for error in (OSError("x"), ValueError("x"), KeyError("x")):
            with self.subTest(error=type(error).__name__):
                result, calls = self.invoke(builder_error=error)
                item = result["agents"]["a-role"]
                self.assertEqual(item["issues"], [f"query:{type(error).__name__}"])
                self.assertFalse(item["read_context_ready"])
                self.assertFalse(item["execution_context_ready"])
                self.assertFalse(item["writeback_ready"])
                self.assertFalse(
                    any(
                        call[0] == "execution_context"
                        and call[1]["agent_role"] == "a-role"
                        for call in calls
                    )
                )

    def test_memory_mismatch_wins_even_after_execution_context_succeeds(self) -> None:
        result, calls = self.invoke(memory_mismatch={"a-role"})
        item = result["agents"]["a-role"]
        self.assertEqual(item["issues"], ["query:contract-mismatch"])
        self.assertFalse(item["read_context_ready"])
        self.assertTrue(item["execution_context_ready"])
        self.assertTrue(
            any(
                call[0] == "execution_context"
                and call[1]["agent_role"] == "a-role"
                for call in calls
            )
        )

    def test_execution_mismatch_is_reported_when_memory_context_matches(self) -> None:
        result, _ = self.invoke(execution_mismatch={"z-role"})
        item = result["agents"]["z-role"]
        self.assertEqual(item["issues"], ["execution:contract-mismatch"])
        self.assertTrue(item["read_context_ready"])
        self.assertFalse(item["execution_context_ready"])
        self.assertFalse(item["writeback_ready"])

    def test_unclassified_builder_error_propagates(self) -> None:
        with self.assertRaisesRegex(TypeError, "programming defect"):
            self.invoke(builder_error=TypeError("programming defect"))


if __name__ == "__main__":
    unittest.main()
