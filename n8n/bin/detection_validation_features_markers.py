"""Marker decoding, constraint evaluation, and bounded marker projection."""
from __future__ import annotations

import hashlib
from typing import Any

from detection_validation_packet import (
    MAX_MARKER_MATCHES_PER_PACKET,
    _bounded_counter,
    _content_constraint,
    _content_evaluation_supported,
    _ordered_deployed_content_constraints,
)
from detection_validation_features_state import FeatureState


def decode_marker_values(
    markers: list[dict[str, Any]] | None,
) -> list[tuple[dict[str, Any], bytes]]:
    """Decode valid non-empty marker hex values and ignore invalid entries."""
    decoded_values: list[tuple[dict[str, Any], bytes]] = []
    for item in markers or []:
        try:
            decoded = bytes.fromhex(str(item.get("hex") or ""))
        except ValueError:
            continue
        if decoded:
            decoded_values.append((item, decoded))
    return decoded_values


def select_markers(
    marker_values: list[tuple[dict[str, Any], bytes]],
    *buffers: str,
) -> list[tuple[dict[str, Any], bytes]]:
    """Select markers whose normalized sticky buffer is in ``buffers``."""
    allowed = set(buffers)
    return [
        (spec, marker)
        for spec, marker in marker_values
        if str(spec.get("buffer") or "").strip().lower() in allowed
    ]


def _evaluate_constraint(
    payload: bytes,
    spec: dict[str, Any],
    marker: bytes,
    ordered_constraints: dict[str, bool | None],
    state: FeatureState,
) -> None:
    marker_id = str(spec["id"])
    constraint = (
        ordered_constraints.get(marker_id)
        if spec.get("source") == "deployed_rule"
        else _content_constraint(payload, marker, spec)
    )
    if constraint is None:
        state.marker_constraint_unsupported.add(marker_id)
        return
    state.marker_constraint_evaluated[marker_id] += 1
    if constraint:
        state.marker_constraint_satisfied[marker_id] += 1
    else:
        state.marker_constraint_violated[marker_id] += 1


def _record_matches(
    payload: bytes,
    spec: dict[str, Any],
    marker: bytes,
    state: FeatureState,
) -> None:
    modifiers = spec.get("modifiers") if isinstance(spec.get("modifiers"), dict) else {}
    haystack = payload.lower() if "nocase" in modifiers else payload
    needle = marker.lower() if "nocase" in modifiers else marker
    marker_id = str(spec["id"])
    start = 0
    matches = 0
    while matches < MAX_MARKER_MATCHES_PER_PACKET:
        position = haystack.find(needle, start)
        if position < 0:
            break
        state.marker_offsets[marker_id][position] += 1
        matches += 1
        start = position + 1
    if matches:
        state.marker_packets[marker_id] += 1


def observe_content(
    payload: bytes,
    selected_markers: list[tuple[dict[str, Any], bytes]],
    state: FeatureState,
    *,
    application_buffer: str | None = None,
) -> bool:
    """Evaluate selected markers against one bounded content buffer."""
    if not selected_markers:
        return False
    ordered_constraints = _ordered_deployed_content_constraints(
        payload,
        selected_markers,
        application_buffer=application_buffer,
    )
    for spec, marker in selected_markers:
        _evaluate_constraint(payload, spec, marker, ordered_constraints, state)
        if _content_evaluation_supported(spec, application_buffer=application_buffer):
            _record_matches(payload, spec, marker, state)
    return True


def _expected_offset(spec: dict[str, Any]) -> int | None:
    raw = spec.get("expected_offset")
    try:
        return int(raw) if raw not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _marker_result(
    spec: dict[str, Any],
    marker: bytes,
    state: FeatureState,
) -> dict[str, Any]:
    marker_id = str(spec["id"])
    expected_offset = _expected_offset(spec)
    offset_counts = state.marker_offsets[marker_id]
    application_buffer = str(spec.get("buffer") or "").strip().lower() or None
    return {
        "id": marker_id,
        "source": spec.get("source"),
        "sha256": hashlib.sha256(marker).hexdigest(),
        "length": len(marker),
        "packets_with_marker": int(state.marker_packets[marker_id]),
        "observations": int(sum(offset_counts.values())),
        "expected_offset": expected_offset,
        "expected_offset_observations": (
            int(offset_counts.get(expected_offset, 0))
            if expected_offset is not None
            else None
        ),
        "offsets": _bounded_counter(offset_counts),
        "constraint_supported": (
            marker_id not in state.marker_constraint_unsupported
            and _content_evaluation_supported(
                spec,
                application_buffer=application_buffer,
            )
        ),
        "packets_evaluated_for_constraint": int(state.marker_constraint_evaluated[marker_id]),
        "packets_satisfying_constraint": int(state.marker_constraint_satisfied[marker_id]),
        "packets_violating_constraint": int(state.marker_constraint_violated[marker_id]),
    }


def marker_results(
    marker_values: list[tuple[dict[str, Any], bytes]],
    state: FeatureState,
) -> list[dict[str, Any]]:
    """Project bounded marker metadata without retaining marker bytes."""
    return [_marker_result(spec, marker, state) for spec, marker in marker_values]
