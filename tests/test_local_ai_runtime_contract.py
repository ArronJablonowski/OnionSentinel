#!/usr/bin/env python3
"""Compatibility checks for the package-free local AI runtime contract."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

import local_ai_runtime_contract as contract  # noqa: E402
import local_ai_analysis_contract as analysis_contract  # noqa: E402
import local_ai_runtime_compat as runtime_compat  # noqa: E402


def load_runner():
    spec = importlib.util.spec_from_file_location(
        "local_ai_contract_runner", BIN / "run-local-ai-analysis.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class LocalAiRuntimeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_runner()

    def test_runner_reexports_exact_contract_values_and_error_types(self) -> None:
        for name in (
            "CONTROLLED_RESULT_ENVIRONMENT",
            "DEFAULT_RESPONSE_VALUES",
            "INVESTIGATION_QUERY_AGGREGATIONS",
            "RuntimeArtifactError",
            "AnalysisIndexSubmissionError",
        ):
            with self.subTest(name=name):
                self.assertIs(getattr(self.runner, name), getattr(contract, name))

    def test_private_mutable_runtime_slots_are_reexported(self) -> None:
        self.assertTrue(
            {"_CONTROLLED_EVALUATION_TOKEN", "_CONTROLLED_EVALUATION_TMPDIR"}
            <= set(contract.__all__)
        )
        self.assertEqual(self.runner._CONTROLLED_EVALUATION_TOKEN, "")
        self.assertIsNone(self.runner._CONTROLLED_EVALUATION_TMPDIR)

    def test_runner_reexports_exact_analysis_policy_tables(self) -> None:
        for name in (
            "HOSTED_FORBIDDEN_KEYS",
            "INVESTIGATION_PARAMETER_KEYS",
            "MODEL_INTERNAL_KEYS",
            "REVIEW_KNOWN_FIELD_PATHS",
            "STRUCTURED_ENUMS",
            "TRUSTED_QUERY_AUDIT_FIELDS",
            "_MODEL_LIST_PATH_SENTINEL",
        ):
            with self.subTest(name=name):
                self.assertIs(
                    getattr(self.runner, name),
                    getattr(analysis_contract, name),
                )

    def test_extracted_runtime_delegates_preserve_runner_patch_seams(self) -> None:
        self.assertIs(self.runner.atomic_write_json.__globals__, vars(self.runner))
        self.assertIs(self.runner._provider_routing.__globals__, vars(self.runner))
        self.assertIs(
            self.runner._evidence_contract_dependencies.__globals__,
            vars(self.runner),
        )
        self.assertIs(
            self.runner._query_security_onion_dependencies.__globals__,
            vars(self.runner),
        )
        self.assertIs(
            self.runner._review_workflow_dependencies.__globals__,
            vars(self.runner),
        )
        self.assertIs(
            self.runner.controlled_evaluation_result_identity.__globals__,
            vars(self.runner),
        )
        self.assertIsNot(self.runner.atomic_write_json, runtime_compat.atomic_write_json)
        runtime_io = mock.Mock()
        with mock.patch.object(self.runner, "_runtime_io", return_value=runtime_io):
            self.runner.atomic_write_json(Path("unused.json"), {"ok": True})
        runtime_io.atomic_write_json.assert_called_once_with(
            Path("unused.json"), {"ok": True}
        )


if __name__ == "__main__":
    unittest.main()
