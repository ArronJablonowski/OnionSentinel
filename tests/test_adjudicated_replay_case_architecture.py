from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import inspect
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
EXPORTER_PATH = ROOT / "n8n/bin/export-adjudicated-analysis-replays.py"


def load_exporter():
    spec = importlib.util.spec_from_file_location(
        "adjudicated_replay_case_architecture", EXPORTER_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(EXPORTER_PATH.read_text(encoding="utf-8"))
    target = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )

    class Complexity(ast.NodeVisitor):
        def __init__(self):
            self.value = 1

        def visit_FunctionDef(self, node):
            return

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_If(self, node):
            self.value += 1
            self.generic_visit(node)

        visit_For = visit_If
        visit_While = visit_If

        def visit_Try(self, node):
            self.value += len(node.handlers)
            self.generic_visit(node)

        def visit_BoolOp(self, node):
            self.value += max(0, len(node.values) - 1)
            self.generic_visit(node)

        def visit_IfExp(self, node):
            self.value += 1
            self.generic_visit(node)

        def visit_ListComp(self, node):
            self.value += sum(
                1 + len(generator.ifs) for generator in node.generators
            )
            self.generic_visit(node)

        visit_SetComp = visit_ListComp
        visit_GeneratorExp = visit_ListComp
        visit_DictComp = visit_ListComp

    visitor = Complexity()
    for child in target.body:
        visitor.visit(child)
    return target.end_lineno - target.lineno + 1, visitor.value


class TrackingRow(dict):
    def __init__(self, values):
        super().__init__(values)
        self.trace = []

    def __getitem__(self, key):
        self.trace.append(key)
        return super().__getitem__(key)


class TrackingRunner:
    trace = []
    outcome = ""

    @classmethod
    def normalized_detection_outcome(cls, value):
        cls.trace.append(["normalized_detection_outcome", value])
        cls.outcome = str(value)
        return cls.outcome

    @classmethod
    def legacy_verdict_factors(cls, outcome, escalation_needed=False):
        cls.trace.append(["legacy_verdict_factors", outcome])
        return {
            "event_status": "unknown",
            "detection_validity": "unknown",
            "activity_disposition": "unknown",
            "handling": "investigate",
            "duplicate_of": None,
        }

    @classmethod
    def derive_legacy_detection_outcome(cls, factors):
        cls.trace.append(["derive_legacy_detection_outcome", copy.deepcopy(factors)])
        return cls.outcome


def base_row(**overrides):
    values = {
        "artifact_path": "artifact.json",
        "response_json": json.dumps(
            {
                "detection_outcome": "inconclusive",
                "_second_opinion": {
                    "status": "completed",
                    "response": {"detection_outcome": "inconclusive"},
                },
            }
        ),
        "outcome_override": "inconclusive",
        "event_status": "unknown",
        "detection_validity": "unknown",
        "activity_disposition": "unknown",
        "handling": "investigate",
        "duplicate_of": None,
        "adjudication_id": "a" * 170,
        "analysis_id": "b" * 170,
        "created_at": "c" * 90,
        "adjudication_confidence": "d" * 20,
        "agent_role": "e" * 70,
        "rationale": "f" * 4010,
        "evidence_gap": "g" * 2010,
        "next_action": "h" * 2010,
    }
    values.update(overrides)
    return TrackingRow(values)


class AdjudicatedReplayCaseArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.exporter = load_exporter()

    def setUp(self) -> None:
        TrackingRunner.trace = []
        TrackingRunner.outcome = ""

    def test_signature_current_debt_and_call_site_are_exact(self) -> None:
        signature = inspect.signature(self.exporter.replay_case)
        self.assertEqual(
            list(signature.parameters),
            ["runner", "item", "analysis_root", "prompt_root"],
        )
        self.assertEqual(signature.parameters["analysis_root"].kind.name, "KEYWORD_ONLY")
        self.assertEqual(signature.parameters["prompt_root"].kind.name, "KEYWORD_ONLY")
        self.assertEqual(str(signature.return_annotation), "dict[str, Any]")
        for name in (
            "_load_replay_material",
            "_explicit_adjudication_factors",
            "_add_adjudication_duplicate",
            "_expected_adjudication",
            "_bounded_row_text",
            "_adjudication_provenance",
            "_completed_reviewer_response",
            "replay_case",
        ):
            lines, complexity = function_metrics(name)
            self.assertLessEqual(lines, 50)
            self.assertLessEqual(complexity, 10)
        source = EXPORTER_PATH.read_text(encoding="utf-8")
        self.assertEqual(source.count("replay_case("), 2)
        self.assertLessEqual(len(source.splitlines()), 800)

    def test_projection_truncation_row_access_and_callbacks_are_exact(self) -> None:
        row = base_row()
        package = {
            "package_type": "soc-ai-investigation-prompt",
            "alert": {"alert_id": "fixture"},
        }
        callback_trace = []

        def confined(value, root):
            callback_trace.append(["confined_path", str(value), str(root)])
            return Path(root) / str(value)

        def bounded(path, limit):
            callback_trace.append(["bounded_json", path.name, limit])
            return (
                {"prompt_package": "prompt.json"}
                if path.name == "artifact.json"
                else copy.deepcopy(package)
            )

        def catalog(value):
            callback_trace.append(["evidence_reference_catalog", copy.deepcopy(value)])
            return ["alert", "alert:fixture"]

        with (
            mock.patch.object(self.exporter, "confined_path", side_effect=confined),
            mock.patch.object(self.exporter, "bounded_json", side_effect=bounded),
            mock.patch.object(
                self.exporter, "evidence_reference_catalog", side_effect=catalog
            ),
        ):
            result = self.exporter.replay_case(
                TrackingRunner,
                row,
                analysis_root=Path("/analysis"),
                prompt_root=Path("/prompts"),
            )

        self.assertEqual(
            row.trace,
            [
                "artifact_path", "response_json", "outcome_override",
                "event_status", "detection_validity", "activity_disposition",
                "handling", "duplicate_of", "adjudication_id",
                "adjudication_id", "analysis_id", "created_at",
                "adjudication_confidence", "agent_role", "rationale",
                "evidence_gap", "next_action",
            ],
        )
        self.assertEqual(
            callback_trace,
            [
                ["confined_path", "artifact.json", "/analysis"],
                ["bounded_json", "artifact.json", self.exporter.MAX_ARTIFACT_BYTES],
                ["confined_path", "prompt.json", "/prompts"],
                ["bounded_json", "prompt.json", self.exporter.MAX_PROMPT_BYTES],
                ["evidence_reference_catalog", package],
            ],
        )
        self.assertEqual(
            [item[0] for item in TrackingRunner.trace],
            [
                "normalized_detection_outcome",
                "legacy_verdict_factors",
                "derive_legacy_detection_outcome",
            ],
        )
        self.assertEqual(result["case_id"], "adjudication-" + "a" * 160)
        self.assertEqual(result["label_provenance"]["adjudication_id"], "a" * 160)
        self.assertEqual(result["label_provenance"]["analysis_id"], "b" * 160)
        self.assertEqual(result["label_provenance"]["created_at"], "c" * 80)
        self.assertEqual(result["label_provenance"]["confidence"], "d" * 16)
        self.assertEqual(result["label_provenance"]["agent_role"], "e" * 64)
        self.assertEqual(len(result["label_provenance"]["rationale"]), 4000)
        self.assertEqual(len(result["label_provenance"]["evidence_gap"]), 2000)
        self.assertEqual(len(result["label_provenance"]["next_action"]), 2000)
        self.assertEqual(
            result["label_provenance"]["factored_labels"],
            [
                "event_status", "detection_validity", "activity_disposition",
                "handling", "duplicate_of",
            ],
        )
        self.assertEqual(result["allowed_evidence_refs"], ["alert", "alert:fixture"])
        self.assertEqual(
            result["reviewer_response"], {"detection_outcome": "inconclusive"}
        )

    def test_real_files_and_row_are_not_mutated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            analysis = root / "analysis"
            prompts = root / "prompts"
            analysis.mkdir()
            prompts.mkdir()
            prompt = prompts / "prompt.json"
            prompt.write_text(
                json.dumps({"package_type": "soc-ai-investigation-prompt"}),
                encoding="utf-8",
            )
            artifact = analysis / "artifact.json"
            artifact.write_text(
                json.dumps({"prompt_package": str(prompt)}), encoding="utf-8"
            )
            row = base_row(artifact_path=str(artifact))
            before_row = dict(row)
            before_files = {
                path: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (artifact, prompt)
            }
            self.exporter.replay_case(
                TrackingRunner,
                row,
                analysis_root=analysis,
                prompt_root=prompts,
            )
            self.assertEqual(dict(row), before_row)
            self.assertEqual(
                {
                    path: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (artifact, prompt)
                },
                before_files,
            )

    def test_response_and_reviewer_admission_failures_are_exact(self) -> None:
        package = {"package_type": "soc-ai-investigation-prompt"}

        def run(row):
            with (
                mock.patch.object(
                    self.exporter,
                    "confined_path",
                    side_effect=lambda value, root: Path(root) / str(value),
                ),
                mock.patch.object(
                    self.exporter,
                    "bounded_json",
                    side_effect=[{"prompt_package": "prompt.json"}, package],
                ),
            ):
                return self.exporter.replay_case(
                    TrackingRunner,
                    row,
                    analysis_root=Path("/analysis"),
                    prompt_root=Path("/prompts"),
                )

        with self.assertRaisesRegex(ValueError, "response_json root must be an object"):
            run(base_row(response_json="[]"))
        with self.assertRaisesRegex(ValueError, "invalid handling"):
            run(base_row(handling="invalid"))
        with self.assertRaisesRegex(ValueError, "empty duplicate_of"):
            run(base_row(duplicate_of="  "))
        for second_opinion in (
            None,
            [],
            {"status": "pending", "response": {}},
            {"status": "completed", "response": []},
        ):
            response = {"_second_opinion": second_opinion}
            result = run(base_row(response_json=json.dumps(response)))
            self.assertNotIn("reviewer_response", result)


if __name__ == "__main__":
    unittest.main()
