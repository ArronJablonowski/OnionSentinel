import importlib.util
import os
import tempfile
import unittest
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
