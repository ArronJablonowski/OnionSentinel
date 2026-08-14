#!/usr/bin/env python3
"""Replay labeled, production-shaped AI artifacts through runtime normalization.

The default mode is entirely offline: it never contacts Ollama, Codex CLI,
Security Onion, or the network. Recorded model responses pass through the same
normalizer, verdict reconciliation, deterministic evidence guard, calibration,
and reviewer comparison used in production.
"""
from __future__ import annotations

import argparse
import copy
import importlib.util
import inspect
import json
import os
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNNER = ROOT / "n8n" / "bin" / "run-local-ai-analysis.py"
DEFAULT_FIXTURES = ROOT / "operations" / "fixtures" / "analysis-replays.json"
DEFAULT_DETECTION_VALIDATOR = ROOT / "n8n" / "bin" / "detection_validation.py"
DEFAULT_DETECTION_PLAYBOOKS = ROOT / "n8n" / "config" / "detection_playbooks.json"
REPLAY_SCHEMA = "onion-sentinel-analysis-replays-v1"
MAX_REPLAY_BYTES = 32 * 1024 * 1024
MAX_CASES = 10000
FACTORED_FIELDS = (
    "event_status",
    "detection_validity",
    "activity_disposition",
    "handling",
    "duplicate_of",
)
HIGH_RISK_HANDLING = {"contain", "escalate"}
ACTIVE_HANDLING = {"contain", "escalate", "investigate"}
LOW_RISK_DISPOSITIONS = {"benign", "authorized_benign"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate recorded production-shaped analysis replays without model calls"
    )
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument("--runner", type=Path, default=DEFAULT_RUNNER)
    parser.add_argument("--out", type=Path, help="Optional path for the full JSON report")
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Exit nonzero when a case misses any required expected field",
    )
    return parser.parse_args()


def load_module(path: Path):
    spec = importlib.util.spec_from_file_location("onion_sentinel_replay_runner", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load analysis runner: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _suite_metadata(payload: object) -> tuple[list[Any], object, object]:
    if not isinstance(payload, dict) or payload.get("schema") != REPLAY_SCHEMA:
        raise ValueError("unsupported analysis replay suite schema")
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("analysis replay suite must contain at least one case")
    if len(cases) > MAX_CASES:
        raise ValueError(f"analysis replay suite exceeds {MAX_CASES} cases")
    response_defaults = payload.get("response_defaults")
    prompt_defaults = payload.get("prompt_defaults")
    if response_defaults is not None and not isinstance(response_defaults, dict):
        raise ValueError("response_defaults must be an object")
    if prompt_defaults is not None and not isinstance(prompt_defaults, dict):
        raise ValueError("prompt_defaults must be an object")
    return cases, response_defaults, prompt_defaults


def _validate_detection_fixture(case_id: str, fixture: object) -> None:
    if not isinstance(fixture, dict):
        raise ValueError(f"{case_id}.detection_validation_fixture must be an object")
    if not str(fixture.get("rule") or "") or not str(fixture.get("sid") or ""):
        raise ValueError(f"{case_id}.detection_validation_fixture is missing rule identity")
    packets = fixture.get("packets")
    if not isinstance(packets, list) or not packets or len(packets) > 100:
        raise ValueError(f"{case_id}.detection_validation_fixture packets are invalid")


def _validate_replay_case(case: object, index: int, identifiers: set[str]) -> None:
    if not isinstance(case, dict):
        raise ValueError(f"cases[{index}] must be an object")
    case_id = str(case.get("case_id") or "").strip()
    if not case_id or case_id in identifiers:
        raise ValueError(f"cases[{index}].case_id is missing or duplicated")
    identifiers.add(case_id)
    if not isinstance(case.get("expected"), dict):
        raise ValueError(f"{case_id}.expected must be an object")
    if not isinstance(case.get("primary_response"), dict):
        raise ValueError(f"{case_id}.primary_response must be an object")
    if not isinstance(case.get("prompt_package"), dict):
        raise ValueError(f"{case_id}.prompt_package must be an object")
    fixture = case.get("detection_validation_fixture")
    if fixture is not None:
        _validate_detection_fixture(case_id, fixture)


def _apply_replay_defaults(
    case: dict[str, Any],
    response_defaults: object,
    prompt_defaults: object,
) -> None:
    case["primary_response"] = {
        **copy.deepcopy(response_defaults or {}),
        **case["primary_response"],
    }
    case["prompt_package"] = {
        **copy.deepcopy(prompt_defaults or {}),
        **case["prompt_package"],
    }
    if isinstance(case.get("reviewer_response"), dict):
        case["reviewer_response"] = {
            **copy.deepcopy(response_defaults or {}),
            **case["reviewer_response"],
        }


def load_suite(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > MAX_REPLAY_BYTES:
        raise ValueError("analysis replay suite exceeds its byte limit")
    payload = json.loads(raw.decode("utf-8"))
    cases, response_defaults, prompt_defaults = _suite_metadata(payload)
    identifiers: set[str] = set()
    for index, case in enumerate(cases):
        _validate_replay_case(case, index, identifiers)
        _apply_replay_defaults(case, response_defaults, prompt_defaults)
    return payload


def _detection_packet_rows(
    case: dict[str, Any],
    fixture: dict[str, Any],
    sid: str,
    ruleset: str,
    raw_base: dict[str, Any],
    message_base: dict[str, Any],
) -> list[dict[str, Any]]:
    rows = []
    for packet in fixture["packets"]:
        if not isinstance(packet, dict):
            raise ValueError(f"{case['case_id']} detection packet must be an object")
        packet_base64 = str(packet.get("packet_base64") or "")
        if not packet_base64:
            raise ValueError(f"{case['case_id']} detection packet is missing packet_base64")
        rows.append(
            {
                "rule_id": sid,
                "raw_event_json": {
                    **raw_base,
                    "message": {
                        **message_base,
                        "packet": packet_base64,
                        "packet_info": {"linktype": int(packet.get("linktype") or 1)},
                    },
                },
                "alert_json": {"rule_id": sid, "rule_ruleset": ruleset},
            }
        )
    return rows


def rebuild_detection_validation(
    case: dict[str, Any],
    detection_module: Any | None = None,
) -> dict[str, Any] | None:
    fixture = case.get("detection_validation_fixture")
    if not isinstance(fixture, dict):
        return None
    module = detection_module or load_module(DEFAULT_DETECTION_VALIDATOR)
    sid = str(fixture.get("sid") or "")
    revision = fixture.get("revision")
    ruleset = str(fixture.get("ruleset") or "")
    rule = str(fixture.get("rule") or "")
    message_base = {
        "alert": {
            "signature_id": sid,
            "rev": revision,
            "signature": str(fixture.get("name") or "replay fixture"),
            "rule": rule,
        },
    }
    raw_base = {
        "rule": {"rule": rule, "rev": revision, "ruleset": ruleset},
        "message": message_base,
    }
    context = module.extract_rule_context(
        {"rule_id": sid, "rule_ruleset": ruleset},
        raw_base,
        sid,
    )
    registry = module.load_detection_playbooks(DEFAULT_DETECTION_PLAYBOOKS)
    playbook = module.resolve_detection_playbook(registry, context)
    rows = _detection_packet_rows(
        case,
        fixture,
        sid,
        ruleset,
        raw_base,
        message_base,
    )
    features = module.extract_group_packet_features(
        rows,
        module.marker_specs(context, playbook),
    )
    return module.build_detection_validation(context, features, playbook)


def normalize_with_runtime(runner: Any, response: dict[str, Any], prompt_package: dict[str, Any]) -> dict[str, Any]:
    validate = runner.validate_response
    parameters = inspect.signature(validate).parameters
    if len(parameters) >= 2:
        normalized = validate(copy.deepcopy(response), copy.deepcopy(prompt_package))
    else:
        normalized = validate(copy.deepcopy(response))
        guard = getattr(runner, "apply_deterministic_evidence_guard", None)
        if callable(guard):
            guarded = guard(normalized, copy.deepcopy(prompt_package))
            if isinstance(guarded, dict):
                normalized = guarded
    return normalized


def _field_result(expected: dict[str, Any], actual: dict[str, Any], field: str) -> dict[str, Any]:
    expected_value = expected.get(field)
    actual_value = actual.get(field)
    return {
        "expected": expected_value,
        "actual": actual_value,
        "correct": actual_value == expected_value,
    }


def _case_field_results(expected: dict[str, Any], primary: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], bool]:
    fields = {
        field: _field_result(expected, primary, field)
        for field in (*FACTORED_FIELDS, "detection_outcome")
        if field in expected
    }
    factor_results = [fields[field]["correct"] for field in FACTORED_FIELDS if field in fields]
    exact_factors = (
        all(factor_results)
        if factor_results
        else bool(fields) and all(value["correct"] for value in fields.values())
    )
    return fields, exact_factors


def _reviewer_analysis(
    runner: Any, case: dict[str, Any], prompt_package: dict[str, Any], primary: dict[str, Any],
) -> tuple[dict[str, Any] | None, Any | None]:
    reviewer = None
    comparison = None
    if isinstance(case.get("reviewer_response"), dict):
        reviewer = normalize_with_runtime(runner, case["reviewer_response"], prompt_package)
        comparison_fn = getattr(runner, "compare_analysis_results", None)
        if callable(comparison_fn):
            comparison = comparison_fn(primary, reviewer)
    return reviewer, comparison


def _unsupported_evidence_refs(case: dict[str, Any], primary: dict[str, Any]) -> list[str]:
    evidence_used = primary.get("evidence_used") if isinstance(primary.get("evidence_used"), list) else []
    has_evidence_catalog = isinstance(case.get("allowed_evidence_refs"), list)
    allowed_refs = {
        str(item) for item in case.get("allowed_evidence_refs", [])
    } if has_evidence_catalog else set()
    return [
        str(item)
        for item in evidence_used
        if has_evidence_catalog and str(item) not in allowed_refs
    ]


def _risk_flags(expected: dict[str, Any], primary: dict[str, Any]) -> tuple[bool, bool]:
    expected_handling = str(expected.get("handling") or "")
    actual_handling = str(primary.get("handling") or "")
    expected_disposition = str(expected.get("activity_disposition") or "")
    dangerous_dismissal = expected_handling in ACTIVE_HANDLING and actual_handling not in ACTIVE_HANDLING
    over_escalation = expected_disposition in LOW_RISK_DISPOSITIONS and actual_handling in HIGH_RISK_HANDLING
    return dangerous_dismissal, over_escalation


def _confidence_probability(primary: dict[str, Any]) -> float:
    confidence_score = primary.get("confidence_score")
    try:
        return min(1.0, max(0.0, float(confidence_score)))
    except (TypeError, ValueError, OverflowError):
        return 0.0


def evaluate_case(
    runner: Any,
    case: dict[str, Any],
    detection_module: Any | None = None,
) -> dict[str, Any]:
    prompt_package = copy.deepcopy(case["prompt_package"])
    rebuilt_validation = rebuild_detection_validation(case, detection_module)
    if rebuilt_validation is not None:
        prompt_package["detection_validation"] = rebuilt_validation
    primary = normalize_with_runtime(runner, case["primary_response"], prompt_package)
    expected = case["expected"]
    fields, exact_factors = _case_field_results(expected, primary)
    reviewer, comparison = _reviewer_analysis(runner, case, prompt_package, primary)
    unsupported_refs = _unsupported_evidence_refs(case, primary)
    dangerous_dismissal, over_escalation = _risk_flags(expected, primary)
    probability_correct = _confidence_probability(primary)
    correctness_target = 1.0 if exact_factors else 0.0
    verdict_validation = (
        primary.get("_verdict_validation")
        if isinstance(primary.get("_verdict_validation"), dict)
        else {}
    )
    return {
        "case_id": case["case_id"],
        "label_source": case.get("label_source"),
        "label_provenance": case.get("label_provenance"),
        "fields": fields,
        "exact_factored_verdict": exact_factors,
        "dangerous_dismissal": dangerous_dismissal,
        "over_escalation": over_escalation,
        "confidence_score": probability_correct,
        "confidence_brier": round((probability_correct - correctness_target) ** 2, 6),
        "schema_repaired": bool(primary.get("_schema_repair")),
        "unsupported_evidence_refs": unsupported_refs,
        "deterministic_guard": (
            verdict_validation.get("deterministic_evidence_guard")
            or primary.get("_deterministic_evidence_guard")
        ),
        "final_disposition_status": primary.get("final_disposition_status"),
        "detection_validation_rebuilt": rebuilt_validation is not None,
        "rebuilt_detection_validation": rebuilt_validation,
        "primary": primary,
        "reviewer": reviewer,
        "review_comparison": comparison,
    }


def _true_positive_count(results: list[dict[str, Any]], field: str, label: str) -> int:
    return sum(
        1
        for item in results
        if field in item["fields"]
        and str(item["fields"][field]["expected"]) == label
        and str(item["fields"][field]["actual"]) == label
    )


def _false_positive_count(results: list[dict[str, Any]], field: str, label: str) -> int:
    return sum(
        1
        for item in results
        if field in item["fields"]
        and str(item["fields"][field]["expected"]) != label
        and str(item["fields"][field]["actual"]) == label
    )


def _false_negative_count(results: list[dict[str, Any]], field: str, label: str) -> int:
    return sum(
        1
        for item in results
        if field in item["fields"]
        and str(item["fields"][field]["expected"]) == label
        and str(item["fields"][field]["actual"]) != label
    )


def _classification_label_metrics(
    results: list[dict[str, Any]], field: str, label: str,
) -> dict[str, Any]:
    true_positive = _true_positive_count(results, field, label)
    false_positive = _false_positive_count(results, field, label)
    false_negative = _false_negative_count(results, field, label)
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else None
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "support": true_positive + false_negative,
        "precision": round(precision, 6) if precision is not None else None,
        "recall": round(recall, 6) if recall is not None else None,
        "f1": round(f1, 6) if f1 is not None else None,
    }


def _classification_labels(results: list[dict[str, Any]], field: str) -> list[str]:
    expected = {str(item["fields"][field]["expected"]) for item in results if field in item["fields"]}
    actual = {str(item["fields"][field]["actual"]) for item in results if field in item["fields"]}
    return sorted(expected | actual)


def _classification_metrics(results: list[dict[str, Any]], field: str) -> dict[str, Any]:
    labels = _classification_labels(results, field)
    confusion: dict[str, Counter[str]] = defaultdict(Counter)
    per_label = {}
    for item in results:
        if field not in item["fields"]:
            continue
        expected = str(item["fields"][field]["expected"])
        actual = str(item["fields"][field]["actual"])
        confusion[expected][actual] += 1
    for label in labels:
        per_label[label] = _classification_label_metrics(results, field, label)
    total = sum(sum(counts.values()) for counts in confusion.values())
    correct = sum(confusion[label][label] for label in labels)
    return {
        "total": total,
        "correct": correct,
        "accuracy": round(correct / total, 6) if total else None,
        "confusion": {label: dict(confusion[label]) for label in labels},
        "per_label": per_label,
    }


def _calibration_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    if not results:
        return {"brier_score": None, "expected_calibration_error": None, "bins": []}
    bins = []
    weighted_gap = 0.0
    for bin_index in range(10):
        lower = bin_index / 10
        upper = (bin_index + 1) / 10
        members = [
            item
            for item in results
            if lower <= item["confidence_score"] <= upper
            and (bin_index == 9 or item["confidence_score"] < upper)
        ]
        if not members:
            continue
        mean_confidence = sum(item["confidence_score"] for item in members) / len(members)
        accuracy = sum(1 for item in members if item["exact_factored_verdict"]) / len(members)
        gap = abs(mean_confidence - accuracy)
        weighted_gap += gap * len(members) / len(results)
        bins.append(
            {
                "lower": lower,
                "upper": upper,
                "count": len(members),
                "mean_confidence": round(mean_confidence, 6),
                "accuracy": round(accuracy, 6),
                "gap": round(gap, 6),
            }
        )
    return {
        "brier_score": round(
            sum(item["confidence_brier"] for item in results) / len(results),
            6,
        ),
        "expected_calibration_error": round(weighted_gap, 6),
        "bins": bins,
    }


def summarize(suite: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, Any]:
    field_metrics = {
        field: _classification_metrics(results, field)
        for field in (*FACTORED_FIELDS, "detection_outcome")
        if any(field in item["fields"] for item in results)
    }
    reviewer_cases = [item for item in results if isinstance(item.get("reviewer"), dict)]
    reviewer_correct = 0
    primary_correct_on_reviewer_cases = 0
    for item in reviewer_cases:
        expected = {
            field: data["expected"]
            for field, data in item["fields"].items()
            if field in FACTORED_FIELDS
        }
        reviewer_correct += int(
            bool(expected)
            and all(item["reviewer"].get(field) == value for field, value in expected.items())
        )
        primary_correct_on_reviewer_cases += int(item["exact_factored_verdict"])
    return {
        "schema": "onion-sentinel-analysis-replay-report-v1",
        "suite_name": suite.get("suite_name"),
        "suite_version": suite.get("version"),
        "case_count": len(results),
        "exact_factored_verdicts": sum(1 for item in results if item["exact_factored_verdict"]),
        "exact_factored_accuracy": round(
            sum(1 for item in results if item["exact_factored_verdict"]) / len(results),
            6,
        ),
        "dangerous_dismissals": [
            item["case_id"] for item in results if item["dangerous_dismissal"]
        ],
        "over_escalations": [
            item["case_id"] for item in results if item["over_escalation"]
        ],
        "schema_repair_cases": [
            item["case_id"] for item in results if item["schema_repaired"]
        ],
        "unsupported_evidence_reference_cases": {
            item["case_id"]: item["unsupported_evidence_refs"]
            for item in results
            if item["unsupported_evidence_refs"]
        },
        "deterministic_guard_cases": [
            item["case_id"]
            for item in results
            if isinstance(item.get("deterministic_guard"), dict)
            and (
                item["deterministic_guard"].get("override_applied")
                or item["deterministic_guard"].get("confidence_cap") is not None
            )
        ],
        "field_metrics": field_metrics,
        "calibration": _calibration_metrics(results),
        "reviewer": {
            "case_count": len(reviewer_cases),
            "primary_exact": primary_correct_on_reviewer_cases,
            "reviewer_exact": reviewer_correct,
            "net_exact_gain": reviewer_correct - primary_correct_on_reviewer_cases,
        },
        "cases": results,
    }


def atomic_private_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        temporary.replace(path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    args = parse_args()
    suite = load_suite(args.fixtures)
    runner = load_module(args.runner)
    results = [evaluate_case(runner, case) for case in suite["cases"]]
    report = summarize(suite, results)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        atomic_private_text(args.out, rendered + "\n")
    print(
        json.dumps(
            {
                key: report[key]
                for key in (
                    "suite_name",
                    "case_count",
                    "exact_factored_accuracy",
                    "dangerous_dismissals",
                    "over_escalations",
                    "schema_repair_cases",
                    "deterministic_guard_cases",
                    "calibration",
                    "reviewer",
                )
            },
            indent=2,
            sort_keys=True,
        )
    )
    failures = [
        item["case_id"]
        for item in results
        if not all(value["correct"] for value in item["fields"].values())
    ]
    return 1 if args.fail_on_regression and failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
