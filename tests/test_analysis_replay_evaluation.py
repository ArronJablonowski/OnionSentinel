import copy
import importlib.util
import json
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVALUATOR_PATH = ROOT / "operations" / "evaluate-analysis-replays.py"
FIXTURE_PATH = ROOT / "operations" / "fixtures" / "analysis-replays.json"
SPEC = importlib.util.spec_from_file_location("analysis_replay_evaluator", EVALUATOR_PATH)
evaluator = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(evaluator)


class FakeRunner:
    @staticmethod
    def validate_response(response):
        return dict(response)

    @staticmethod
    def apply_deterministic_evidence_guard(response, prompt_package):
        result = dict(response)
        validation = prompt_package.get("detection_validation") or {}
        if validation.get("rule_intent_match") == "mismatch":
            result.update(
                {
                    "event_status": validation.get("event_status", "unknown"),
                    "detection_validity": "logic_error",
                    "activity_disposition": "unknown",
                    "handling": "investigate",
                    "duplicate_of": None,
                    "detection_outcome": "false_positive_logic_rule",
                    "_deterministic_evidence_guard": {
                        "override_applied": True,
                        "confidence_cap": 0.79,
                    },
                }
            )
        return result

    @staticmethod
    def compare_analysis_results(primary, reviewer):
        return {"material_disagreement": primary != reviewer}


class AnalysisReplayEvaluationTests(unittest.TestCase):
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

    def test_load_suite_preserves_identity_precedence_and_copy_isolation(self):
        first = self.valid_case(" first ")
        first["reviewer_response"] = {"reviewer_override": "case"}
        second = self.valid_case("second")
        payload = {
            "schema": evaluator.REPLAY_SCHEMA,
            "response_defaults": {
                "override": "default",
                "reviewer_override": "default",
                "nested": {"values": [1]},
            },
            "prompt_defaults": {
                "prompt_override": "default",
                "nested_prompt": {"values": [2]},
            },
            "cases": [first, second],
        }

        result = self.load_payload(payload)

        self.assertIs(result, payload)
        self.assertEqual(first["case_id"], " first ")
        self.assertEqual(first["primary_response"]["override"], "case")
        self.assertEqual(first["reviewer_response"]["reviewer_override"], "case")
        self.assertEqual(first["prompt_package"]["prompt_override"], "case")
        self.assertEqual(second["primary_response"]["override"], "case")
        self.assertEqual(second["prompt_package"]["prompt_override"], "case")
        self.assertEqual(first["primary_response"]["nested"], {"values": [1]})
        self.assertEqual(first["prompt_package"]["nested_prompt"], {"values": [2]})
        self.assertIsNot(
            first["primary_response"]["nested"],
            second["primary_response"]["nested"],
        )
        self.assertIsNot(
            first["primary_response"]["nested"],
            first["reviewer_response"]["nested"],
        )
        self.assertIsNot(
            first["primary_response"]["nested"],
            payload["response_defaults"]["nested"],
        )
        self.assertIsNot(
            first["prompt_package"]["nested_prompt"],
            second["prompt_package"]["nested_prompt"],
        )
        first["primary_response"]["nested"]["values"].append(9)
        self.assertEqual(second["primary_response"]["nested"]["values"], [1])
        self.assertEqual(payload["response_defaults"]["nested"]["values"], [1])

    def test_load_suite_preserves_suite_and_case_admission_errors(self):
        valid = {
            "schema": evaluator.REPLAY_SCHEMA,
            "cases": [self.valid_case()],
        }
        cases = [
            ([], "unsupported analysis replay suite schema"),
            ({"schema": "wrong", "cases": []}, "unsupported analysis replay suite schema"),
            ({"schema": evaluator.REPLAY_SCHEMA}, "analysis replay suite must contain at least one case"),
            ({"schema": evaluator.REPLAY_SCHEMA, "cases": {}}, "analysis replay suite must contain at least one case"),
            ({"schema": evaluator.REPLAY_SCHEMA, "cases": []}, "analysis replay suite must contain at least one case"),
            (dict(valid, response_defaults=[]), "response_defaults must be an object"),
            (dict(valid, prompt_defaults=[]), "prompt_defaults must be an object"),
            (dict(valid, cases=[[]]), "cases[0] must be an object"),
            (dict(valid, cases=[dict(self.valid_case(), case_id="  ")]), "cases[0].case_id is missing or duplicated"),
            (dict(valid, cases=[self.valid_case(1), self.valid_case("1")]), "cases[1].case_id is missing or duplicated"),
            (dict(valid, cases=[dict(self.valid_case(), expected=[])]), "case-1.expected must be an object"),
            (dict(valid, cases=[dict(self.valid_case(), primary_response=[])]), "case-1.primary_response must be an object"),
            (dict(valid, cases=[dict(self.valid_case(), prompt_package=[])]), "case-1.prompt_package must be an object"),
        ]
        for payload, message in cases:
            with self.subTest(message=message, payload=payload):
                with self.assertRaisesRegex(ValueError, message.replace("[", "\\[").replace("]", "\\]")):
                    self.load_payload(copy.deepcopy(payload))

        oversized = dict(valid, cases=[self.valid_case("one"), self.valid_case("two")])
        with mock.patch.object(evaluator, "MAX_CASES", 1):
            with self.assertRaisesRegex(ValueError, "exceeds 1 cases"):
                self.load_payload(oversized)

        path = mock.Mock()
        path.read_bytes.return_value = b"abc"
        with mock.patch.object(evaluator, "MAX_REPLAY_BYTES", 2), \
             mock.patch.object(evaluator.json, "loads") as loads:
            with self.assertRaisesRegex(ValueError, "byte limit"):
                evaluator.load_suite(path)
        loads.assert_not_called()

        path.read_bytes.return_value = b"\xff"
        with self.assertRaises(UnicodeDecodeError):
            evaluator.load_suite(path)

        path.read_bytes.return_value = b"{"
        with self.assertRaises(json.JSONDecodeError):
            evaluator.load_suite(path)

    def test_load_suite_preserves_detection_fixture_admission(self):
        valid_fixture = {
            "rule": "alert tcp any any -> any any (sid:1;)",
            "sid": "1",
            "packets": [{"payload": "00"}],
        }
        accepted = self.valid_case()
        accepted["detection_validation_fixture"] = valid_fixture
        payload = {"schema": evaluator.REPLAY_SCHEMA, "cases": [accepted]}
        self.assertIs(self.load_payload(payload), payload)

        fixtures = [
            ([], "case-1.detection_validation_fixture must be an object"),
            (dict(valid_fixture, rule=""), "case-1.detection_validation_fixture is missing rule identity"),
            (dict(valid_fixture, sid=""), "case-1.detection_validation_fixture is missing rule identity"),
            (dict(valid_fixture, packets={}), "case-1.detection_validation_fixture packets are invalid"),
            (dict(valid_fixture, packets=[]), "case-1.detection_validation_fixture packets are invalid"),
            (dict(valid_fixture, packets=[{}] * 101), "case-1.detection_validation_fixture packets are invalid"),
        ]
        for fixture, message in fixtures:
            case = self.valid_case()
            case["detection_validation_fixture"] = fixture
            payload = {"schema": evaluator.REPLAY_SCHEMA, "cases": [case]}
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message.replace("[", "\\[").replace("]", "\\]")):
                    self.load_payload(payload)

    def test_checked_in_replays_are_exact_with_deterministic_guard(self):
        suite = evaluator.load_suite(FIXTURE_PATH)
        results = [
            evaluator.evaluate_case(FakeRunner, case)
            for case in suite["cases"]
        ]
        report = evaluator.summarize(suite, results)
        self.assertEqual(report["case_count"], 5)
        self.assertEqual(report["exact_factored_accuracy"], 1.0)
        self.assertEqual(report["dangerous_dismissals"], [])
        self.assertEqual(report["over_escalations"], [])
        self.assertEqual(
            report["deterministic_guard_cases"],
            [],
        )
        self.assertTrue(results[0]["detection_validation_rebuilt"])
        self.assertEqual(
            results[0]["rebuilt_detection_validation"]["rule_intent_match"],
            "unknown",
        )
        self.assertIsNotNone(report["calibration"]["brier_score"])

    def test_detects_dangerous_dismissal_and_over_escalation(self):
        suite = {
            "suite_name": "unit",
            "version": 1,
        }
        cases = [
            {
                "case_id": "dismissal",
                "label_source": "unit",
                "label_provenance": "unit",
                "prompt_package": {},
                "expected": {
                    "event_status": "observed",
                    "detection_validity": "matched_intent",
                    "activity_disposition": "malicious",
                    "handling": "contain",
                    "duplicate_of": None,
                    "detection_outcome": "true_positive_malicious",
                },
                "primary_response": {
                    "event_status": "observed",
                    "detection_validity": "matched_intent",
                    "activity_disposition": "malicious",
                    "handling": "no_action",
                    "duplicate_of": None,
                    "detection_outcome": "true_positive_malicious",
                    "confidence_score": 0.9,
                },
            },
            {
                "case_id": "escalation",
                "label_source": "unit",
                "label_provenance": "unit",
                "prompt_package": {},
                "expected": {
                    "event_status": "observed",
                    "detection_validity": "matched_intent",
                    "activity_disposition": "benign",
                    "handling": "no_action",
                    "duplicate_of": None,
                    "detection_outcome": "informational_no_action",
                },
                "primary_response": {
                    "event_status": "observed",
                    "detection_validity": "matched_intent",
                    "activity_disposition": "benign",
                    "handling": "contain",
                    "duplicate_of": None,
                    "detection_outcome": "informational_no_action",
                    "confidence_score": 0.8,
                },
            },
        ]
        results = [evaluator.evaluate_case(FakeRunner, case) for case in cases]
        report = evaluator.summarize(suite, results)
        self.assertEqual(report["dangerous_dismissals"], ["dismissal"])
        self.assertEqual(report["over_escalations"], ["escalation"])

    def test_flags_evidence_references_outside_exported_catalog(self):
        case = {
            "case_id": "unsupported-evidence-reference",
            "label_source": "analyst_adjudication",
            "label_provenance": {"adjudication_id": "adj-unit"},
            "prompt_package": {"alert": {"alert_id": "fixture"}},
            "allowed_evidence_refs": ["alert", "alert:fixture"],
            "expected": {"detection_outcome": "inconclusive"},
            "primary_response": {
                "detection_outcome": "inconclusive",
                "evidence_used": ["alert", "fabricated-query-result"],
                "confidence_score": 0.4,
            },
        }
        result = evaluator.evaluate_case(FakeRunner, case)
        self.assertEqual(
            result["unsupported_evidence_refs"],
            ["fabricated-query-result"],
        )

    def test_rejects_empty_or_wrong_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text('{"schema":"wrong","cases":[]}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "schema"):
                evaluator.load_suite(path)

    def test_full_report_output_is_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reports" / "result.json"
            evaluator.atomic_private_text(path, "{}\n")
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
