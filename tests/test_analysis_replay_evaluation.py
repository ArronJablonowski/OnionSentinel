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


class DetectionModuleRecorder:
    def __init__(self):
        self.calls = []
        self.context = object()
        self.registry = object()
        self.playbook = object()
        self.markers = object()
        self.features = object()
        self.result = object()

    def extract_rule_context(self, alert, raw, sid):
        self.calls.append(("extract_rule_context", alert, raw, sid))
        return self.context

    def load_detection_playbooks(self, path):
        self.calls.append(("load_detection_playbooks", path))
        return self.registry

    def resolve_detection_playbook(self, registry, context):
        self.calls.append(("resolve_detection_playbook", registry, context))
        return self.playbook

    def marker_specs(self, context, playbook):
        self.calls.append(("marker_specs", context, playbook))
        return self.markers

    def extract_group_packet_features(self, rows, markers):
        self.calls.append(("extract_group_packet_features", rows, markers))
        return self.features

    def build_detection_validation(self, context, features, playbook):
        self.calls.append(
            ("build_detection_validation", context, features, playbook)
        )
        return self.result


class EvaluationRunnerRecorder:
    calls = []
    primary = None
    reviewer = None
    comparison = None

    @classmethod
    def reset(cls):
        cls.calls = []
        cls.primary = {
            "event_status": "observed",
            "detection_validity": "matched_intent",
            "activity_disposition": "malicious",
            "handling": "contain",
            "duplicate_of": None,
            "detection_outcome": "true_positive_malicious",
            "confidence_score": 1.2,
            "evidence_used": ["alert", 7, "fabricated", 7],
            "_schema_repair": {"applied": True},
            "_verdict_validation": {
                "deterministic_evidence_guard": {"source": "validation"},
            },
            "_deterministic_evidence_guard": {"source": "fallback"},
            "final_disposition_status": "confirmed",
        }
        cls.reviewer = {"review": "normalized"}
        cls.comparison = {"material_disagreement": False}

    @classmethod
    def validate_response(cls, response, prompt_package):
        cls.calls.append(("validate_response", response, prompt_package))
        return cls.reviewer if response.get("kind") == "reviewer" else cls.primary

    @classmethod
    def compare_analysis_results(cls, primary, reviewer):
        cls.calls.append(("compare_analysis_results", primary, reviewer))
        return cls.comparison


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

    def test_rebuild_detection_validation_preserves_rows_calls_and_identity(self):
        module = DetectionModuleRecorder()
        case = {
            "case_id": "rebuild-case",
            "detection_validation_fixture": {
                "sid": 7,
                "revision": 3,
                "ruleset": None,
                "rule": 5,
                "name": "",
                "packets": [
                    {"packet_base64": "first", "linktype": "101"},
                    {"packet_base64": 123, "linktype": 0},
                ],
            },
        }
        original = copy.deepcopy(case)

        result = evaluator.rebuild_detection_validation(case, module)

        self.assertIs(result, module.result)
        self.assertEqual(case, original)
        self.assertEqual(
            [item[0] for item in module.calls],
            [
                "extract_rule_context",
                "load_detection_playbooks",
                "resolve_detection_playbook",
                "marker_specs",
                "extract_group_packet_features",
                "build_detection_validation",
            ],
        )
        _, alert, raw_base, sid = module.calls[0]
        self.assertEqual(alert, {"rule_id": "7", "rule_ruleset": ""})
        self.assertEqual(sid, "7")
        self.assertEqual(
            raw_base,
            {
                "rule": {"rule": "5", "rev": 3, "ruleset": ""},
                "message": {
                    "alert": {
                        "signature_id": "7",
                        "rev": 3,
                        "signature": "replay fixture",
                        "rule": "5",
                    }
                },
            },
        )
        self.assertEqual(
            module.calls[1],
            ("load_detection_playbooks", evaluator.DEFAULT_DETECTION_PLAYBOOKS),
        )
        self.assertEqual(
            module.calls[2],
            ("resolve_detection_playbook", module.registry, module.context),
        )
        self.assertEqual(
            module.calls[3],
            ("marker_specs", module.context, module.playbook),
        )
        _, rows, markers = module.calls[4]
        self.assertIs(markers, module.markers)
        self.assertEqual(
            rows,
            [
                {
                    "rule_id": "7",
                    "raw_event_json": {
                        "rule": {"rule": "5", "rev": 3, "ruleset": ""},
                        "message": {
                            "alert": {
                                "signature_id": "7",
                                "rev": 3,
                                "signature": "replay fixture",
                                "rule": "5",
                            },
                            "packet": "first",
                            "packet_info": {"linktype": 101},
                        },
                    },
                    "alert_json": {"rule_id": "7", "rule_ruleset": ""},
                },
                {
                    "rule_id": "7",
                    "raw_event_json": {
                        "rule": {"rule": "5", "rev": 3, "ruleset": ""},
                        "message": {
                            "alert": {
                                "signature_id": "7",
                                "rev": 3,
                                "signature": "replay fixture",
                                "rule": "5",
                            },
                            "packet": "123",
                            "packet_info": {"linktype": 1},
                        },
                    },
                    "alert_json": {"rule_id": "7", "rule_ruleset": ""},
                },
            ],
        )
        self.assertIs(
            rows[0]["raw_event_json"]["rule"],
            rows[1]["raw_event_json"]["rule"],
        )
        self.assertIs(
            rows[0]["raw_event_json"]["message"]["alert"],
            rows[1]["raw_event_json"]["message"]["alert"],
        )
        self.assertIsNot(
            rows[0]["raw_event_json"]["message"],
            rows[1]["raw_event_json"]["message"],
        )
        self.assertEqual(
            module.calls[5],
            (
                "build_detection_validation",
                module.context,
                module.features,
                module.playbook,
            ),
        )

    def test_rebuild_detection_validation_preserves_module_resolution(self):
        for fixture in (None, [], "not-an-object"):
            case = {"detection_validation_fixture": fixture}
            with self.subTest(fixture=fixture), \
                 mock.patch.object(evaluator, "load_module") as load:
                self.assertIsNone(evaluator.rebuild_detection_validation(case))
                load.assert_not_called()

        class FalseModule:
            def __bool__(self):
                return False

        loaded = DetectionModuleRecorder()
        case = {
            "case_id": "loaded-module",
            "detection_validation_fixture": {
                "rule": "rule",
                "sid": "1",
                "packets": [{"packet_base64": "packet"}],
            },
        }
        with mock.patch.object(evaluator, "load_module", return_value=loaded) as load:
            result = evaluator.rebuild_detection_validation(case, FalseModule())
        load.assert_called_once_with(evaluator.DEFAULT_DETECTION_VALIDATOR)
        self.assertIs(result, loaded.result)

    def test_rebuild_detection_validation_preserves_packet_failures(self):
        class BadLinktype:
            def __int__(self):
                raise OverflowError("linktype-stop")

        invalid = [
            ([], "rebuild-case detection packet must be an object", ValueError),
            ({}, "rebuild-case detection packet is missing packet_base64", ValueError),
            (
                {"packet_base64": 0},
                "rebuild-case detection packet is missing packet_base64",
                ValueError,
            ),
            (
                {"packet_base64": "packet", "linktype": BadLinktype()},
                "linktype-stop",
                OverflowError,
            ),
        ]
        for packet, message, error in invalid:
            module = DetectionModuleRecorder()
            packets = [packet]
            fixture = {
                "rule": "rule",
                "sid": "1",
                "packets": packets,
            }
            case = {
                "case_id": "rebuild-case",
                "detection_validation_fixture": fixture,
            }
            with self.subTest(message=message):
                with self.assertRaisesRegex(error, message):
                    evaluator.rebuild_detection_validation(case, module)
            self.assertIs(case["detection_validation_fixture"], fixture)
            self.assertIs(fixture["packets"], packets)
            self.assertIs(packets[0], packet)
            self.assertEqual(
                [item[0] for item in module.calls],
                [
                    "extract_rule_context",
                    "load_detection_playbooks",
                    "resolve_detection_playbook",
                ],
            )

    def test_evaluate_case_preserves_projection_calls_identity_and_copy_isolation(self):
        EvaluationRunnerRecorder.reset()
        rebuilt = {"rule_intent_match": "match"}
        case = {
            "case_id": "full-case",
            "label_source": "analyst_adjudication",
            "label_provenance": {"adjudication_id": "adj-1"},
            "prompt_package": {"nested": {"values": [1]}},
            "expected": {
                "event_status": "observed",
                "detection_validity": "matched_intent",
                "activity_disposition": "malicious",
                "handling": "contain",
                "duplicate_of": None,
                "detection_outcome": "true_positive_malicious",
            },
            "primary_response": {"kind": "primary"},
            "reviewer_response": {"kind": "reviewer"},
            "allowed_evidence_refs": ["alert"],
        }
        original = copy.deepcopy(case)

        with mock.patch.object(
            evaluator,
            "rebuild_detection_validation",
            return_value=rebuilt,
        ) as rebuild:
            result = evaluator.evaluate_case(EvaluationRunnerRecorder, case)

        self.assertEqual(case, original)
        rebuild.assert_called_once_with(case, None)
        self.assertEqual(
            [call[0] for call in EvaluationRunnerRecorder.calls],
            ["validate_response", "validate_response", "compare_analysis_results"],
        )
        primary_call, reviewer_call, comparison_call = EvaluationRunnerRecorder.calls
        self.assertEqual(primary_call[1], {"kind": "primary"})
        self.assertEqual(reviewer_call[1], {"kind": "reviewer"})
        self.assertIsNot(primary_call[1], case["primary_response"])
        self.assertIsNot(reviewer_call[1], case["reviewer_response"])
        for call in (primary_call, reviewer_call):
            self.assertEqual(
                call[2],
                {
                    "nested": {"values": [1]},
                    "detection_validation": rebuilt,
                },
            )
            self.assertIsNot(call[2], case["prompt_package"])
            self.assertIsNot(call[2]["nested"], case["prompt_package"]["nested"])
        self.assertIsNot(primary_call[2], reviewer_call[2])
        self.assertIs(comparison_call[1], EvaluationRunnerRecorder.primary)
        self.assertIs(comparison_call[2], EvaluationRunnerRecorder.reviewer)
        self.assertEqual(
            list(result),
            [
                "case_id",
                "label_source",
                "label_provenance",
                "fields",
                "exact_factored_verdict",
                "dangerous_dismissal",
                "over_escalation",
                "confidence_score",
                "confidence_brier",
                "schema_repaired",
                "unsupported_evidence_refs",
                "deterministic_guard",
                "final_disposition_status",
                "detection_validation_rebuilt",
                "rebuilt_detection_validation",
                "primary",
                "reviewer",
                "review_comparison",
            ],
        )
        self.assertEqual(
            list(result["fields"]),
            [*evaluator.FACTORED_FIELDS, "detection_outcome"],
        )
        self.assertTrue(result["exact_factored_verdict"])
        self.assertFalse(result["dangerous_dismissal"])
        self.assertFalse(result["over_escalation"])
        self.assertEqual(result["confidence_score"], 1.0)
        self.assertEqual(result["confidence_brier"], 0.0)
        self.assertTrue(result["schema_repaired"])
        self.assertEqual(
            result["unsupported_evidence_refs"],
            ["7", "fabricated", "7"],
        )
        self.assertIs(
            result["deterministic_guard"],
            EvaluationRunnerRecorder.primary["_verdict_validation"][
                "deterministic_evidence_guard"
            ],
        )
        self.assertEqual(result["final_disposition_status"], "confirmed")
        self.assertTrue(result["detection_validation_rebuilt"])
        self.assertIs(result["rebuilt_detection_validation"], rebuilt)
        self.assertIs(result["primary"], EvaluationRunnerRecorder.primary)
        self.assertIs(result["reviewer"], EvaluationRunnerRecorder.reviewer)
        self.assertIs(result["review_comparison"], EvaluationRunnerRecorder.comparison)

    def test_evaluate_case_preserves_fallbacks_risk_and_confidence_bounds(self):
        class Runner:
            compare_analysis_results = None

            @staticmethod
            def validate_response(response, _prompt_package):
                return dict(response)

        base = {
            "case_id": "fallback-case",
            "prompt_package": {},
            "primary_response": {
                "handling": "no_action",
                "activity_disposition": "benign",
                "confidence_score": "not-a-number",
                "evidence_used": "not-a-list",
                "_deterministic_evidence_guard": {"source": "fallback"},
            },
            "reviewer_response": [],
            "allowed_evidence_refs": "not-a-list",
            "expected": {
                "handling": "contain",
                "activity_disposition": "benign",
            },
        }
        result = evaluator.evaluate_case(Runner, copy.deepcopy(base))
        self.assertEqual(list(result["fields"]), ["activity_disposition", "handling"])
        self.assertFalse(result["exact_factored_verdict"])
        self.assertTrue(result["dangerous_dismissal"])
        self.assertFalse(result["over_escalation"])
        self.assertEqual(result["confidence_score"], 0.0)
        self.assertEqual(result["confidence_brier"], 0.0)
        self.assertEqual(result["unsupported_evidence_refs"], [])
        self.assertIsNone(result["reviewer"])
        self.assertIsNone(result["review_comparison"])
        self.assertEqual(result["deterministic_guard"], {"source": "fallback"})

        cases = (
            ({}, {}, False, 0.0),
            ({"detection_outcome": "same"}, {"detection_outcome": "same"}, True, 0.0),
            ({"detection_outcome": "same"}, {"detection_outcome": "other"}, False, 0.0),
            ({"handling": "no_action"}, {"handling": "contain", "activity_disposition": "benign", "confidence_score": float("inf")}, False, 1.0),
            ({"handling": "contain"}, {"handling": "contain", "confidence_score": -1}, True, 0.0),
        )
        for expected, primary, exact, confidence in cases:
            case = {
                "case_id": "bounds",
                "prompt_package": {},
                "primary_response": primary,
                "expected": expected,
            }
            with self.subTest(expected=expected, primary=primary):
                result = evaluator.evaluate_case(Runner, case)
                self.assertIs(result["exact_factored_verdict"], exact)
                self.assertEqual(result["confidence_score"], confidence)

        escalation = copy.deepcopy(base)
        escalation["expected"]["handling"] = "no_action"
        escalation["primary_response"]["handling"] = "escalate"
        result = evaluator.evaluate_case(Runner, escalation)
        self.assertFalse(result["dangerous_dismissal"])
        self.assertTrue(result["over_escalation"])

    def test_evaluate_case_preserves_failure_boundaries(self):
        case = {
            "case_id": "failure-case",
            "prompt_package": {},
            "primary_response": {},
            "expected": {},
        }
        with mock.patch.object(evaluator.copy, "deepcopy", side_effect=OSError("copy-stop")), \
             mock.patch.object(evaluator, "rebuild_detection_validation") as rebuild:
            with self.assertRaisesRegex(OSError, "copy-stop"):
                evaluator.evaluate_case(FakeRunner, case)
        rebuild.assert_not_called()

        with mock.patch.object(
            evaluator,
            "rebuild_detection_validation",
            side_effect=RuntimeError("rebuild-stop"),
        ), mock.patch.object(evaluator, "normalize_with_runtime") as normalize:
            with self.assertRaisesRegex(RuntimeError, "rebuild-stop"):
                evaluator.evaluate_case(FakeRunner, case)
        normalize.assert_not_called()

        reviewer_case = {
            **case,
            "reviewer_response": {},
        }
        with mock.patch.object(evaluator, "rebuild_detection_validation", return_value=None), \
             mock.patch.object(
                 evaluator,
                 "normalize_with_runtime",
                 side_effect=[{}, LookupError("reviewer-stop")],
             ) as normalize:
            with self.assertRaisesRegex(LookupError, "reviewer-stop"):
                evaluator.evaluate_case(FakeRunner, reviewer_case)
        self.assertEqual(normalize.call_count, 2)

    def test_classification_metrics_preserves_schema_values_and_scan_count(self):
        class IterationRecorder(list):
            def __init__(self, values):
                super().__init__(values)
                self.iterations = 0

            def __iter__(self):
                self.iterations += 1
                return super().__iter__()

        results = IterationRecorder(
            [
                {"fields": {"kind": {"expected": "A", "actual": "A"}}},
                {"fields": {"kind": {"expected": "A", "actual": "B"}}},
                {"fields": {"kind": {"expected": "B", "actual": "B"}}},
                {"fields": {"kind": {"expected": None, "actual": "B"}}},
                {"fields": {"other": {"expected": "ignored", "actual": "ignored"}}},
            ]
        )
        original = copy.deepcopy(list(results))
        initial_iterations = results.iterations

        metrics = evaluator._classification_metrics(results, "kind")
        metric_iterations = results.iterations - initial_iterations

        self.assertEqual(list(results), original)
        self.assertEqual(metric_iterations, 12)
        self.assertEqual(
            list(metrics),
            ["total", "correct", "accuracy", "confusion", "per_label"],
        )
        self.assertEqual(metrics["total"], 4)
        self.assertEqual(metrics["correct"], 2)
        self.assertEqual(metrics["accuracy"], 0.5)
        self.assertEqual(
            metrics["confusion"],
            {
                "A": {"A": 1, "B": 1},
                "B": {"B": 1},
                "None": {"B": 1},
            },
        )
        self.assertEqual(
            metrics["per_label"],
            {
                "A": {
                    "support": 2,
                    "precision": 1.0,
                    "recall": 0.5,
                    "f1": 0.666667,
                },
                "B": {
                    "support": 1,
                    "precision": 0.333333,
                    "recall": 1.0,
                    "f1": 0.5,
                },
                "None": {
                    "support": 1,
                    "precision": None,
                    "recall": 0.0,
                    "f1": None,
                },
            },
        )
        self.assertEqual(list(metrics["confusion"]), ["A", "B", "None"])
        self.assertEqual(list(metrics["per_label"]), ["A", "B", "None"])
        for label in metrics["per_label"]:
            self.assertEqual(
                list(metrics["per_label"][label]),
                ["support", "precision", "recall", "f1"],
            )

    def test_classification_metrics_preserves_empty_freshness_and_failures(self):
        empty = evaluator._classification_metrics([], "kind")
        missing = evaluator._classification_metrics([{"fields": {}}], "kind")
        self.assertEqual(
            empty,
            {
                "total": 0,
                "correct": 0,
                "accuracy": None,
                "confusion": {},
                "per_label": {},
            },
        )
        self.assertEqual(missing, empty)
        self.assertIsNot(missing, empty)
        self.assertIsNot(missing["confusion"], empty["confusion"])
        self.assertIsNot(missing["per_label"], empty["per_label"])

        class BadString:
            def __str__(self):
                raise LookupError("string-stop")

        results = [
            {"fields": {"kind": {"expected": BadString(), "actual": "A"}}},
        ]
        with self.assertRaisesRegex(LookupError, "string-stop"):
            evaluator._classification_metrics(results, "kind")
        self.assertIsInstance(results[0]["fields"]["kind"]["expected"], BadString)

    def test_calibration_metrics_preserves_bounds_values_order_and_scan_count(self):
        class IterationRecorder(list):
            def __init__(self, values):
                super().__init__(values)
                self.iterations = 0

            def __iter__(self):
                self.iterations += 1
                return super().__iter__()

        scores = [
            (0.0, False),
            (0.099, True),
            (0.1, True),
            (0.199, False),
            (0.5, True),
            (0.999, True),
            (1.0, False),
            (-0.1, True),
            (1.1, False),
        ]
        results = IterationRecorder(
            [
                {
                    "confidence_score": score,
                    "exact_factored_verdict": correct,
                    "confidence_brier": (index + 1) / 10,
                }
                for index, (score, correct) in enumerate(scores)
            ]
        )
        original = copy.deepcopy(list(results))
        initial_iterations = results.iterations

        metrics = evaluator._calibration_metrics(results)
        metric_iterations = results.iterations - initial_iterations

        self.assertEqual(list(results), original)
        self.assertEqual(metric_iterations, 11)
        self.assertEqual(
            list(metrics),
            ["brier_score", "expected_calibration_error", "bins"],
        )
        self.assertEqual(metrics["brier_score"], 0.5)
        self.assertEqual(metrics["expected_calibration_error"], 0.344556)
        self.assertEqual(
            metrics["bins"],
            [
                {
                    "lower": 0.0,
                    "upper": 0.1,
                    "count": 2,
                    "mean_confidence": 0.0495,
                    "accuracy": 0.5,
                    "gap": 0.4505,
                },
                {
                    "lower": 0.1,
                    "upper": 0.2,
                    "count": 2,
                    "mean_confidence": 0.1495,
                    "accuracy": 0.5,
                    "gap": 0.3505,
                },
                {
                    "lower": 0.5,
                    "upper": 0.6,
                    "count": 1,
                    "mean_confidence": 0.5,
                    "accuracy": 1.0,
                    "gap": 0.5,
                },
                {
                    "lower": 0.9,
                    "upper": 1.0,
                    "count": 2,
                    "mean_confidence": 0.9995,
                    "accuracy": 0.5,
                    "gap": 0.4995,
                },
            ],
        )
        for item in metrics["bins"]:
            self.assertEqual(
                list(item),
                ["lower", "upper", "count", "mean_confidence", "accuracy", "gap"],
            )

    def test_calibration_metrics_preserves_empty_freshness_and_failure_order(self):
        first = evaluator._calibration_metrics([])
        second = evaluator._calibration_metrics([])
        self.assertEqual(
            first,
            {
                "brier_score": None,
                "expected_calibration_error": None,
                "bins": [],
            },
        )
        self.assertIsNot(first, second)
        self.assertIsNot(first["bins"], second["bins"])

        with self.assertRaises(KeyError) as error:
            evaluator._calibration_metrics([{"confidence_brier": 0.0}])
        self.assertEqual(error.exception.args, ("confidence_score",))

        with self.assertRaises(KeyError) as error:
            evaluator._calibration_metrics(
                [{"confidence_score": 0.5, "confidence_brier": 0.0}]
            )
        self.assertEqual(error.exception.args, ("exact_factored_verdict",))

        with self.assertRaises(KeyError) as error:
            evaluator._calibration_metrics(
                [{"confidence_score": 1.1, "exact_factored_verdict": True}]
            )
        self.assertEqual(error.exception.args, ("confidence_brier",))

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


if __name__ == "__main__":
    unittest.main()
