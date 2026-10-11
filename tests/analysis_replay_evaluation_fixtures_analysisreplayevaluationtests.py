from __future__ import annotations

from analysis_replay_evaluation_fixtures import (
    DetectionModuleRecorder,
    EVALUATOR_PATH,
    EvaluationRunnerRecorder,
    FIXTURE_PATH,
    FakeRunner,
    Path,
    ROOT,
    SPEC,
    copy,
    evaluator,
    importlib,
    json,
    mock,
    os,
    tempfile,
    unittest,
)

class AnalysisReplayEvaluationTestsFixtures(unittest.TestCase):
    def valid_case(self, case_id="case-1"):
        return {
            "case_id": case_id,
            "expected": {"handling": "investigate"},
            "primary_response": {"override": "case"},
            "prompt_package": {"prompt_override": "case"},
        }


    def load_payload(self, payload):
        path = mock.Mock()
        path.read_bytes.return_value = b"serialized"
        with mock.patch.object(evaluator.json, "loads", return_value=payload) as loads:
            result = evaluator.load_suite(path)
        loads.assert_called_once_with("serialized")
        return result


