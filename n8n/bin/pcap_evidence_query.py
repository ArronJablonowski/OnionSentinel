#!/usr/bin/env python3
"""Typed, allowlisted pivots over sanitized, derived PCAP evidence."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from pcap_analysis_core import sanitize_evidence_text, sanitize_evidence_value
import pcap_evidence_query_matching as _matching
from pcap_evidence_query_policy import *  # noqa: F403
import pcap_evidence_query_projection as _projection
import pcap_evidence_query_response as _response
import pcap_evidence_query_selection as _selection
import pcap_evidence_query_validation as _validation


class PcapEvidenceQueryError(ValueError):
    """The requested operation violated the derived-evidence query contract."""


def _nested(record: dict[str, Any], path: tuple[str, ...]) -> Any:
    return _selection.nested(record, path)


def _text(value: Any, field: str, max_chars: int = MAX_REQUEST_TEXT_CHARS) -> str:  # noqa: F405
    return _validation.text_filter(
        value, field, max_chars, control_pattern=CONTROL_OR_ESCAPE,  # noqa: F405
        error=PcapEvidenceQueryError,
    )


def _integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    return _validation.integer_filter(
        value, field, minimum, maximum, error=PcapEvidenceQueryError,
    )


def _epoch(value: Any, field: str) -> float:
    return _validation.epoch_filter(value, field, error=PcapEvidenceQueryError)


def _normalize_filters(operation: str, raw: Any) -> dict[str, Any]:
    return _validation.normalize_filters(
        operation, raw, filters_by_operation=FILTERS_BY_OPERATION,  # noqa: F405
        ip_filters=IP_FILTERS, integer_ranges=INTEGER_FILTER_RANGES,  # noqa: F405
        time_filters=TIME_FILTERS, boolean_filters=BOOLEAN_FILTERS,  # noqa: F405
        parse_text=_text, parse_integer=_integer, parse_epoch=_epoch,
        max_text_chars=MAX_REQUEST_TEXT_CHARS, error=PcapEvidenceQueryError,  # noqa: F405
    )


def _iter_scalars(value: Any):
    return _matching.iter_scalars(value)


def _field_values(value: Any, aliases: set[str]) -> list[Any]:
    return _matching.field_values(value, aliases)


def _equals(candidate: Any, expected: Any) -> bool:
    return _matching.equals(
        candidate, expected, sanitize_text=sanitize_evidence_text,
        max_text_chars=MAX_REQUEST_TEXT_CHARS,  # noqa: F405
    )


def _numeric_values(candidate: Any, field: str) -> list[float]:
    return _matching.numeric_values(candidate, field, aliases=FILTER_FIELD_ALIASES)  # noqa: F405


def _filter_matches(candidate: Any, field: str, expected: Any) -> bool:
    return _matching.filter_matches(
        candidate, field, expected, ip_filters=IP_FILTERS,  # noqa: F405
        aliases=FILTER_FIELD_ALIASES, compare=_equals, numeric=_numeric_values,  # noqa: F405
        sanitize_text=sanitize_evidence_text,
        max_text_chars=MAX_REQUEST_TEXT_CHARS,  # noqa: F405
    )


def _matches_indicator(value: Any, indicator: str) -> bool:
    return _matching.matches_indicator(
        value, indicator, sanitize_text=sanitize_evidence_text,
        max_text_chars=MAX_REQUEST_TEXT_CHARS,  # noqa: F405
    )


def _scrub_nested(value: Any, container: str = "") -> Any:
    """Defend in depth against raw/parser fields inside an approved container."""
    return _projection.scrub_nested(
        value, container, nested_output_fields=NESTED_OUTPUT_FIELDS,  # noqa: F405
        forbidden=_forbidden_output_key, sanitize_text=sanitize_evidence_text,
        sanitize_value=sanitize_evidence_value,
    )


def _forbidden_output_key(key: Any) -> bool:
    return _projection.forbidden_output_key(key, FORBIDDEN_OUTPUT_KEYS)  # noqa: F405


def _project_coverage(value: Any) -> Any:
    """Keep coverage telemetry without trusting arbitrary coverage keys."""
    return _projection.project_coverage(
        value, scalar_fields=COVERAGE_SCALAR_FIELDS,  # noqa: F405
        sanitize_text=sanitize_evidence_text,
        sanitize_value=sanitize_evidence_value,
    )


def _project_record(operation: str, candidate: Any) -> Any:
    return _projection.project_record(
        operation, candidate, output_fields=OUTPUT_FIELDS_BY_OPERATION,  # noqa: F405
        project_coverage_record=_project_coverage, scrub=_scrub_nested,
        forbidden=_forbidden_output_key, sanitize_text=sanitize_evidence_text,
    )


def _query_candidates(
    evidence: list[Any], operation: str,
) -> tuple[list[Any], list[str], bool]:
    return _selection.query_candidates(
        evidence, operation, query_paths=QUERY_PATHS,  # noqa: F405
        max_scan_records=MAX_QUERY_SCAN_RECORDS,  # noqa: F405
    )


def query_derived_pcap_evidence(
    pcap_context: dict[str, Any], requests: Any,
) -> dict[str, Any]:
    """Execute typed read-only pivots and return bounded audit metadata."""
    if requests in (None, ""):
        return {"executed": [], "results": []}
    if not isinstance(pcap_context, dict):
        raise PcapEvidenceQueryError("PCAP evidence context must be an object")
    if not isinstance(requests, list):
        raise PcapEvidenceQueryError("pcap_query_requests must be an array")
    if len(requests) > MAX_QUERY_REQUESTS:  # noqa: F405
        raise PcapEvidenceQueryError(
            f"at most {MAX_QUERY_REQUESTS} PCAP evidence queries are allowed"  # noqa: F405
        )
    parsed = pcap_context.get("parsed_evidence")
    evidence = parsed if isinstance(parsed, list) else []
    executed: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for raw in requests:
        request = _normalize_request(raw)
        executed.append(request)
        results.append(_execute_request(evidence, request))
    return _response.compose_payload(
        contract=QUERY_CONTRACT, executed=executed, results=results,  # noqa: F405
        max_result_bytes=MAX_QUERY_RESULT_BYTES, error=PcapEvidenceQueryError,  # noqa: F405
    )


def _normalize_request(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise PcapEvidenceQueryError("each PCAP evidence query must be an object")
    operation = str(raw.get("operation") or "").strip().lower()
    if operation not in QUERY_PATHS:  # noqa: F405
        raise PcapEvidenceQueryError(
            f"unsupported PCAP evidence operation: {operation or 'missing'}"
        )
    unknown = set(raw).difference({"operation", "indicator", "filters", "limit"})
    if unknown:
        fields = ", ".join(sorted(str(item) for item in unknown))
        raise PcapEvidenceQueryError(
            f"unsupported PCAP evidence query fields: {fields}"
        )
    indicator = ""
    if raw.get("indicator") not in (None, ""):
        indicator = _text(raw.get("indicator"), "indicator", 253)
    return {
        "operation": operation,
        "filters": _normalize_filters(operation, raw.get("filters")),
        "indicator": indicator,
        "limit": _integer(raw.get("limit", 10), "limit", 1, MAX_QUERY_LIMIT),  # noqa: F405
    }


def _execute_request(
    evidence: list[Any], request: dict[str, Any],
) -> dict[str, Any]:
    candidates, source_views, scan_truncated = _query_candidates(
        evidence, request["operation"],
    )
    return _response.execute_request(
        request, candidates, source_views=source_views,
        scan_truncated=scan_truncated, contract=QUERY_CONTRACT,  # noqa: F405
        matches_indicator=_matches_indicator, filter_matches=_filter_matches,
        project_record=_project_record,
    )
