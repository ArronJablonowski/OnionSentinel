"""Suricata content-clause semantics over bounded packet buffers."""

from __future__ import annotations

import re
from typing import Any

from detection_validation_rule import MAX_MARKER_MATCHES_PER_PACKET


def _nonnegative_modifier(value: object) -> int | None:
    text = str(value or "").strip()
    if not re.fullmatch(r"\d+", text):
        return None
    return int(text)


def _content_evaluation_supported(
    spec: dict[str, Any],
    *,
    application_buffer: str | None = None,
) -> bool:
    """Return whether a content clause can use the supplied bounded buffer."""
    if spec.get("source") != "deployed_rule":
        return True
    buffer_name = str(spec.get("buffer") or "").strip().lower()
    modifiers = spec.get("modifiers") if isinstance(spec.get("modifiers"), dict) else {}
    if application_buffer is None:
        if buffer_name not in {"", "pkt_data"}:
            return False
        if any(name in modifiers for name in ("dotprefix", "bsize")):
            return False
    elif buffer_name != application_buffer:
        return False
    if "rawbytes" in modifiers:
        return False
    if "bsize" in modifiers and _nonnegative_modifier(modifiers.get("bsize")) is None:
        return False
    return True


def _prepare_content_payload(
    payload: bytes,
    spec: dict[str, Any],
    *,
    application_buffer: str | None,
) -> tuple[str, bytes, dict[str, Any]]:
    if not _content_evaluation_supported(spec, application_buffer=application_buffer):
        return "unsupported", payload, {}
    modifiers = spec.get("modifiers") if isinstance(spec.get("modifiers"), dict) else {}
    if "bsize" in modifiers:
        expected_size = _nonnegative_modifier(modifiers.get("bsize"))
        if expected_size is None:
            return "unsupported", payload, modifiers
        if len(payload) != expected_size:
            return "no_match", payload, modifiers
    if application_buffer is not None and "dotprefix" in modifiers:
        payload = b"." + payload.lstrip(b".")
    return "ready", payload, modifiers


def _content_bounds(
    payload: bytes,
    modifiers: dict[str, Any],
    *,
    previous_match_end: int | None,
) -> tuple[int, int] | None:
    relative = "distance" in modifiers or "within" in modifiers
    if relative and any(key in modifiers for key in ("offset", "depth")):
        return None
    if relative:
        if previous_match_end is None:
            return None
        distance = 0
        if "distance" in modifiers:
            distance = _nonnegative_modifier(modifiers.get("distance"))
            if distance is None:
                return None
        start = previous_match_end + distance
        end = len(payload)
        if "within" in modifiers:
            within = _nonnegative_modifier(modifiers.get("within"))
            if within is None:
                return None
            end = min(len(payload), start + within)
        return start, end
    start = 0
    if "offset" in modifiers:
        start = _nonnegative_modifier(modifiers.get("offset"))
        if start is None:
            return None
    end = len(payload)
    if "depth" in modifiers:
        depth = _nonnegative_modifier(modifiers.get("depth"))
        if depth is None:
            return None
        end = min(len(payload), start + depth)
    return start, end


def _anchored_content_positions(
    payload: bytes,
    marker: bytes,
    modifiers: dict[str, Any],
    *,
    start: int,
    end: int,
) -> list[int] | None:
    haystack = payload.lower() if "nocase" in modifiers else payload
    needle = marker.lower() if "nocase" in modifiers else marker
    if "startswith" in modifiers:
        if start <= 0 and len(needle) <= end and haystack.startswith(needle):
            return [0]
        return []
    if "endswith" in modifiers:
        position = len(haystack) - len(needle)
        if position >= start and position + len(needle) <= end and haystack.endswith(needle):
            return [position]
        return []
    return None


def _find_content_positions(
    payload: bytes,
    marker: bytes,
    modifiers: dict[str, Any],
    *,
    start: int,
    end: int,
) -> list[int]:
    if start < 0 or start > len(payload) or end < start:
        return []
    anchored = _anchored_content_positions(
        payload, marker, modifiers, start=start, end=end
    )
    if anchored is not None:
        return anchored
    haystack = payload.lower() if "nocase" in modifiers else payload
    needle = marker.lower() if "nocase" in modifiers else marker
    positions: list[int] = []
    cursor = start
    while len(positions) < MAX_MARKER_MATCHES_PER_PACKET:
        position = haystack.find(needle, cursor, end)
        if position < 0:
            break
        positions.append(position)
        cursor = position + 1
    return positions


def _content_match_positions(
    payload: bytes,
    marker: bytes,
    spec: dict[str, Any],
    *,
    previous_match_end: int | None = None,
    application_buffer: str | None = None,
) -> list[int] | None:
    """Return bounded matches for one absolute or cursor-relative content clause."""
    state, payload, modifiers = _prepare_content_payload(
        payload, spec, application_buffer=application_buffer
    )
    if state == "unsupported":
        return None
    if state == "no_match":
        return []
    bounds = _content_bounds(
        payload, modifiers, previous_match_end=previous_match_end
    )
    if bounds is None:
        return None
    return _find_content_positions(
        payload, marker, modifiers, start=bounds[0], end=bounds[1]
    )


def _content_constraint(
    payload: bytes,
    marker: bytes,
    spec: dict[str, Any],
) -> bool | None:
    """Evaluate the supported subset of Suricata payload-content semantics."""
    positions = _content_match_positions(payload, marker, spec)
    if positions is None:
        return None
    present = bool(positions)
    return not present if bool(spec.get("negated")) else present


def _evaluate_content_candidates(
    payload: bytes,
    marker: bytes,
    spec: dict[str, Any],
    candidates: list[int | None],
    *,
    relative: bool,
    application_buffer: str | None,
    existing_cursors: set[int | None],
) -> tuple[bool, bool, set[int | None]]:
    supported = True
    satisfied = False
    next_cursors: set[int | None] = set()
    for previous_end in candidates[:MAX_MARKER_MATCHES_PER_PACKET]:
        positions = _content_match_positions(
            payload,
            marker,
            spec,
            previous_match_end=previous_end,
            application_buffer=application_buffer,
        )
        if positions is None:
            supported = False
            continue
        if spec.get("negated"):
            if not positions:
                satisfied = True
                if relative:
                    next_cursors.add(previous_end)
                else:
                    next_cursors.update(existing_cursors)
            continue
        if positions:
            satisfied = True
            next_cursors.update(
                position + len(marker)
                for position in positions[:MAX_MARKER_MATCHES_PER_PACKET]
            )
    return supported, satisfied, next_cursors


def _ordered_deployed_content_constraints(
    payload: bytes,
    marker_values: list[tuple[dict[str, Any], bytes]],
    *,
    application_buffer: str | None = None,
) -> dict[str, bool | None]:
    """Evaluate deployed content clauses in rule order with bounded cursor paths."""
    results: dict[str, bool | None] = {}
    cursors: set[int | None] = {None}
    cursor_unknown = False
    current_buffer: str | None = None
    for spec, marker in marker_values:
        if spec.get("source") != "deployed_rule":
            continue
        marker_id = str(spec["id"])
        modifiers = spec.get("modifiers") if isinstance(spec.get("modifiers"), dict) else {}
        relative = "distance" in modifiers or "within" in modifiers
        buffer_name = str(spec.get("buffer") or "pkt_data").strip().lower()
        if buffer_name != current_buffer:
            current_buffer = buffer_name
            cursors = {None}
            cursor_unknown = False
        if relative and not cursors:
            results[marker_id] = None if cursor_unknown else False
            continue
        candidates = (
            sorted(cursors, key=lambda value: -1 if value is None else value)
            if relative
            else [None]
        )
        supported, satisfied, next_cursors = _evaluate_content_candidates(
            payload,
            marker,
            spec,
            candidates,
            relative=relative,
            application_buffer=application_buffer,
            existing_cursors=cursors,
        )
        if not supported:
            results[marker_id] = None
            cursors = set()
            cursor_unknown = True
            continue
        results[marker_id] = satisfied
        cursors = next_cursors if satisfied else set()
        cursor_unknown = False
    return results
