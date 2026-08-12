"""Deterministic decision and generated-query benchmark scoring."""
from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Any


def _results_by_id(run: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    supplied = ((run.get("response") or {}).get("results")) if run.get("ok") else []
    supplied = supplied if isinstance(supplied, list) else []
    by_id: dict[str, list[dict[str, Any]]] = {}
    for item in supplied:
        if isinstance(item, dict):
            by_id.setdefault(str(item.get("id") or ""), []).append(item)
    return by_id


def _score_summary(
    cases: Sequence[Any],
    by_id: dict[str, list[dict[str, Any]]],
    details: list[dict[str, Any]],
) -> dict[str, Any]:
    expected_ids = {case.case_id for case in cases}
    actual_ids = {key for key in by_id if key}
    return {
        "points": sum(item["points"] for item in details),
        "possible": len(details) * 5,
        "missing_ids": sorted(expected_ids - actual_ids),
        "unexpected_ids": sorted(actual_ids - expected_ids),
        "duplicate_ids": sorted(
            key for key, values in by_id.items() if key and len(values) != 1
        ),
        "details": details,
    }


def normalized_answer(value: Any) -> str:
    text = str(value or "").strip().upper()
    return text[:1] if text[:1] in {"A", "B", "C", "D"} else text


def _decision_evidence_checks(
    case: Any,
    item: dict[str, Any],
) -> tuple[set[str], bool, bool]:
    cited_raw = item.get("evidence")
    cited = {
        str(value).strip() for value in cited_raw
    } if isinstance(cited_raw, list) else set()
    required_ok = all(
        evidence_id in cited for evidence_id in case.required_evidence
    )
    allowed_evidence = {line.split(None, 1)[0] for line in case.evidence}
    return cited, required_ok, bool(cited) and cited.issubset(allowed_evidence)


def _decision_answer_checks(
    case: Any,
    item: dict[str, Any],
) -> tuple[str, bool, bool]:
    if not item:
        return "", False, False
    actual_answer = normalized_answer(item.get("answer"))
    rationale_ok = bool(str(item.get("rationale") or "").strip())
    return actual_answer, actual_answer == case.expected_answer, rationale_ok


def _decision_detail(case: Any, matches: list[dict[str, Any]]) -> dict[str, Any]:
    item = matches[0] if matches else {}
    cited, required_ok, evidence_scope_ok = _decision_evidence_checks(case, item)
    actual_answer, answer_ok, rationale_ok = _decision_answer_checks(case, item)
    points = (
        (2 if answer_ok else 0)
        + int(required_ok)
        + int(evidence_scope_ok)
        + int(rationale_ok)
    )
    return {
        "id": case.case_id,
        "category": case.category,
        "title": case.title,
        "points": points,
        "possible": 5,
        "answer_ok": answer_ok,
        "required_evidence_ok": required_ok,
        "evidence_scope_ok": evidence_scope_ok,
        "rationale_ok": rationale_ok,
        "unique_result_ok": len(matches) == 1,
        "expected_answer": case.expected_answer,
        "actual_answer": actual_answer,
        "cited_evidence": sorted(cited),
    }


def score_decisions(cases: Sequence[Any], run: dict[str, Any]) -> dict[str, Any]:
    """Score evidence discipline separately from the selected verdict."""
    by_id = _results_by_id(run)
    details = [_decision_detail(case, by_id.get(case.case_id, [])) for case in cases]
    return _score_summary(cases, by_id, details)


def normalized_query(value: Any) -> str:
    if isinstance(value, dict):
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
    return str(value or "").strip()


def _validate_kql(query: str, normalized: str) -> tuple[bool, bool]:
    syntax_ok = (
        ":" in query
        and not query.lstrip().startswith("{")
        and not re.match(r"(?is)^\s*select\b", query)
    )
    return bool(syntax_ok), "@timestamp" in normalized and "now-" in normalized


def _validate_dsl(case: Any, query: str) -> tuple[bool, bool]:
    try:
        payload = json.loads(query)
    except (json.JSONDecodeError, TypeError):
        return False, False
    if not isinstance(payload, dict):
        return False, False
    size = payload.get("size")
    source = payload.get("_source")
    syntax_ok = isinstance(payload.get("query"), dict) and isinstance(source, list)
    bounded_ok = (
        isinstance(size, int)
        and not isinstance(size, bool)
        and 0 < size <= case.max_results
        and bool(source)
    )
    return syntax_ok, bounded_ok


def _validate_osquery(case: Any, query: str) -> tuple[bool, bool]:
    statements = [item.strip() for item in query.split(";") if item.strip()]
    syntax_ok = (
        len(statements) == 1
        and bool(re.match(r"(?is)^select\b", statements[0]))
    )
    limits = [int(value) for value in re.findall(r"(?i)\blimit\s+(\d+)\b", query)]
    bounded_ok = len(limits) == 1 and 0 < limits[0] <= case.max_results
    return syntax_ok, bounded_ok


def query_validation(case: Any, query: str) -> dict[str, bool]:
    normalized = re.sub(r"\s+", " ", query.strip()).lower()
    required_ok = all(
        token.lower() in normalized for token in case.required_tokens
    )
    safe_ok = bool(normalized) and not any(
        token.lower() in normalized for token in case.forbidden_tokens
    )
    validators = {
        "kql": lambda: _validate_kql(query, normalized),
        "elasticsearch_dsl": lambda: _validate_dsl(case, query),
        "osquery": lambda: _validate_osquery(case, query),
    }
    syntax_ok, bounded_ok = validators.get(
        case.language,
        lambda: (False, False),
    )()
    return {
        "query_present": bool(query.strip()),
        "required_tokens_ok": required_ok,
        "safe_read_only_ok": safe_ok,
        "syntax_ok": syntax_ok,
        "bounded_ok": bounded_ok,
    }


def _query_detail(case: Any, matches: list[dict[str, Any]]) -> dict[str, Any]:
    item = matches[0] if matches else {}
    query = normalized_query(item.get("query")) if item else ""
    checks = query_validation(case, query)
    language_ok = (
        str(item.get("language") or "").strip().lower() == case.language
        if item else False
    )
    points = (
        int(checks["query_present"])
        + int(language_ok)
        + int(checks["required_tokens_ok"])
        + int(checks["safe_read_only_ok"])
        + int(checks["syntax_ok"] and checks["bounded_ok"])
    )
    return {
        "id": case.case_id,
        "category": "query_generation",
        "title": case.title,
        "language": case.language,
        "points": points,
        "possible": 5,
        "language_ok": language_ok,
        **checks,
        "query": query[:4000],
    }


def score_queries(cases: Sequence[Any], run: dict[str, Any]) -> dict[str, Any]:
    """Score generated syntax, scope, bounds, and read-only safety."""
    by_id = _results_by_id(run)
    details = [_query_detail(case, by_id.get(case.case_id, [])) for case in cases]
    return _score_summary(cases, by_id, details)
