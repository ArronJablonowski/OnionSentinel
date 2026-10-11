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

class AnalysisReplayEvaluationTestsSummarizePreservesSchemaCallsIdentityAndReviewerMetricsCases:
    def test_summarize_preserves_schema_calls_identity_and_reviewer_metrics(self):
        unsupported = ["fabricated"]
        results = [
            {
                "case_id": "one",
                "fields": {
                    "event_status": {"expected": "observed", "actual": "observed"},
                    "detection_outcome": {"expected": "true_positive", "actual": "true_positive"},
                    "ignored": {"expected": "x", "actual": "x"},
                },
                "reviewer": {"event_status": "observed"},
                "exact_factored_verdict": True,
                "dangerous_dismissal": False,
                "over_escalation": True,
                "schema_repaired": False,
                "unsupported_evidence_refs": [],
                "deterministic_guard": "not-an-object",
            },
            {
                "case_id": "two",
                "fields": {
                    "event_status": {"expected": "missed", "actual": "observed"},
                },
                "reviewer": [],
                "exact_factored_verdict": False,
                "dangerous_dismissal": True,
                "over_escalation": False,
                "schema_repaired": True,
                "unsupported_evidence_refs": unsupported,
                "deterministic_guard": {
                    "override_applied": False,
                    "confidence_cap": 0.7,
                },
            },
            {
                "case_id": "three",
                "fields": {
                    "event_status": {"expected": "observed", "actual": "observed"},
                },
                "reviewer": {"event_status": "missed"},
                "exact_factored_verdict": True,
                "dangerous_dismissal": False,
                "over_escalation": False,
                "schema_repaired": False,
                "unsupported_evidence_refs": [],
                "deterministic_guard": {
                    "override_applied": False,
                    "confidence_cap": None,
                },
            },
        ]
        suite = {"suite_name": "summary-unit", "version": 7}
        original_suite = copy.deepcopy(suite)
        original_results = copy.deepcopy(results)
        calls = []
        event_metrics = {"metric": "event"}
        detection_metrics = {"metric": "detection"}
        calibration = {"calibration": "result"}

        def classify(items, field):
            calls.append(("classification", items, field))
            return {
                "event_status": event_metrics,
                "detection_outcome": detection_metrics,
            }[field]

        def calibrate(items):
            calls.append(("calibration", items))
            return calibration

        with mock.patch.object(evaluator, "_classification_metrics", side_effect=classify), \
             mock.patch.object(evaluator, "_calibration_metrics", side_effect=calibrate):
            report = evaluator.summarize(suite, results)

        self.assertEqual(suite, original_suite)
        self.assertEqual(results, original_results)
        self.assertEqual(
            [(call[0], call[-1] if call[0] == "classification" else None) for call in calls],
            [
                ("classification", "event_status"),
                ("classification", "detection_outcome"),
                ("calibration", None),
            ],
        )
        self.assertTrue(all(call[1] is results for call in calls))
        self.assertEqual(
            list(report),
            [
                "schema",
                "suite_name",
                "suite_version",
                "case_count",
                "exact_factored_verdicts",
                "exact_factored_accuracy",
                "dangerous_dismissals",
                "over_escalations",
                "schema_repair_cases",
                "unsupported_evidence_reference_cases",
                "deterministic_guard_cases",
                "field_metrics",
                "calibration",
                "reviewer",
                "cases",
            ],
        )
        self.assertEqual(report["schema"], "onion-sentinel-analysis-replay-report-v1")
        self.assertEqual(report["suite_name"], "summary-unit")
        self.assertEqual(report["suite_version"], 7)
        self.assertEqual(report["case_count"], 3)
        self.assertEqual(report["exact_factored_verdicts"], 2)
        self.assertEqual(report["exact_factored_accuracy"], 0.666667)
        self.assertEqual(report["dangerous_dismissals"], ["two"])
        self.assertEqual(report["over_escalations"], ["one"])
        self.assertEqual(report["schema_repair_cases"], ["two"])
        self.assertEqual(report["unsupported_evidence_reference_cases"], {"two": unsupported})
        self.assertIs(report["unsupported_evidence_reference_cases"]["two"], unsupported)
        self.assertEqual(report["deterministic_guard_cases"], ["two"])
        self.assertEqual(list(report["field_metrics"]), ["event_status", "detection_outcome"])
        self.assertIs(report["field_metrics"]["event_status"], event_metrics)
        self.assertIs(report["field_metrics"]["detection_outcome"], detection_metrics)
        self.assertIs(report["calibration"], calibration)
        self.assertEqual(
            report["reviewer"],
            {"case_count": 2, "primary_exact": 2, "reviewer_exact": 1, "net_exact_gain": -1},
        )
        self.assertEqual(
            list(report["reviewer"]),
            ["case_count", "primary_exact", "reviewer_exact", "net_exact_gain"],
        )
        self.assertIs(report["cases"], results)


    def test_summarize_preserves_empty_and_helper_failure_boundaries(self):
        class SuiteRecorder(dict):
            def __init__(self):
                super().__init__({"suite_name": "empty", "version": 1})
                self.gets = []

            def get(self, key, default=None):
                self.gets.append(key)
                return super().get(key, default)

        suite = SuiteRecorder()
        with mock.patch.object(evaluator, "_classification_metrics") as classify, \
             mock.patch.object(evaluator, "_calibration_metrics") as calibrate:
            with self.assertRaises(ZeroDivisionError):
                evaluator.summarize(suite, [])
        classify.assert_not_called()
        calibrate.assert_not_called()
        self.assertEqual(suite.gets, ["suite_name", "version"])

        results = [
            {
                "case_id": "failure",
                "fields": {"event_status": {"expected": "x", "actual": "x"}},
                "reviewer": None,
                "exact_factored_verdict": True,
                "dangerous_dismissal": False,
                "over_escalation": False,
                "schema_repaired": False,
                "unsupported_evidence_refs": [],
                "deterministic_guard": None,
            }
        ]
        with mock.patch.object(
            evaluator,
            "_classification_metrics",
            side_effect=LookupError("classification-stop"),
        ), mock.patch.object(evaluator, "_calibration_metrics") as calibrate:
            with self.assertRaisesRegex(LookupError, "classification-stop"):
                evaluator.summarize({}, results)
        calibrate.assert_not_called()

        with mock.patch.object(evaluator, "_classification_metrics", return_value={}), \
             mock.patch.object(
                 evaluator,
                 "_calibration_metrics",
                 side_effect=RuntimeError("calibration-stop"),
             ):
            with self.assertRaisesRegex(RuntimeError, "calibration-stop"):
                evaluator.summarize({}, results)


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


