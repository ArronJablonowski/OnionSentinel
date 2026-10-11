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
