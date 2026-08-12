"""Bounded detection-playbook registry admission."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from detection_validation_rule import (
    MAX_MARKERS,
    MAX_PACKET_BYTES,
    MAX_PLAYBOOK_BYTES,
    PLAYBOOK_SCHEMA,
)


_PREDICATE_FIELDS = {
    "icmp.type",
    "icmp.code",
    "icmp.identifier",
    "icmp.sequence",
    "icmp.payload_length",
    "frame.length",
}


def _read_registry(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_PLAYBOOK_BYTES:
            raise ValueError("detection playbook registry exceeds its byte limit")
        with path.open("rb") as handle:
            raw = handle.read(MAX_PLAYBOOK_BYTES + 1)
    except FileNotFoundError:
        return {"schema": PLAYBOOK_SCHEMA, "version": 0, "playbooks": []}
    if len(raw) > MAX_PLAYBOOK_BYTES:
        raise ValueError("detection playbook registry exceeds its byte limit")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or payload.get("schema") != PLAYBOOK_SCHEMA:
        raise ValueError("unsupported detection playbook registry")
    if payload.get("version") != 1:
        raise ValueError("unsupported detection playbook registry version")
    return payload


def _validate_match(identifier: str, playbook: dict[str, Any]) -> None:
    match = playbook.get("match")
    if not isinstance(match, dict):
        raise ValueError(f"{identifier}.match must be an object")
    sids = _validated_sids(identifier, match)
    revisions = _validated_revisions(identifier, match)
    ruleset = str(match.get("ruleset") or "")
    if len(ruleset) > 200 or not (sids or revisions or ruleset):
        raise ValueError(f"{identifier}.match must define a bounded exact scope")
    _validate_rule_hash(identifier, match)


def _validated_sids(identifier: str, match: dict[str, Any]) -> list[Any]:
    sids = match.get("sids", [])
    if not isinstance(sids, list) or any(
        not re.fullmatch(r"\d{1,20}", str(value)) for value in sids
    ):
        raise ValueError(f"{identifier}.match.sids is invalid")
    return sids


def _validated_revisions(identifier: str, match: dict[str, Any]) -> list[Any]:
    revisions = match.get("revisions", [])
    if not isinstance(revisions, list) or any(
        not isinstance(value, int) or value < 1 for value in revisions
    ):
        raise ValueError(f"{identifier}.match.revisions is invalid")
    return revisions


def _validate_rule_hash(identifier: str, match: dict[str, Any]) -> None:
    rule_sha256 = str(match.get("rule_sha256") or "")
    if rule_sha256 and not re.fullmatch(r"[0-9a-f]{64}", rule_sha256):
        raise ValueError(f"{identifier}.match.rule_sha256 is invalid")


def _validate_predicate(
    identifier: str,
    collection_name: str,
    predicate: Any,
) -> None:
    if not isinstance(predicate, dict):
        raise ValueError(f"{identifier}.{collection_name} entries must be objects")
    if str(predicate.get("field") or "") not in _PREDICATE_FIELDS:
        raise ValueError(f"{identifier}.{collection_name} field is unsupported")
    if str(predicate.get("operator") or "equals") not in {"equals", "contains"}:
        raise ValueError(f"{identifier}.{collection_name} operator is unsupported")
    _validate_applies_to_sids(
        identifier,
        collection_name,
        predicate.get("applies_to_sids", []),
    )
    _validate_expected(identifier, collection_name, predicate)


def _validate_applies_to_sids(
    identifier: str,
    collection_name: str,
    applies_to_sids: Any,
) -> None:
    if not isinstance(applies_to_sids, list) or any(
        not re.fullmatch(r"\d{1,20}", str(value)) for value in applies_to_sids
    ):
        raise ValueError(
            f"{identifier}.{collection_name} applies_to_sids is invalid"
        )


def _validate_expected(
    identifier: str,
    collection_name: str,
    predicate: dict[str, Any],
) -> None:
    expected = predicate.get("expected", predicate.get("value"))
    expected_values = expected if isinstance(expected, list) else [expected]
    if not expected_values:
        raise ValueError(f"{identifier}.{collection_name} expected value is missing")
    try:
        [int(value) for value in expected_values]
    except (TypeError, ValueError) as error:
        raise ValueError(
            f"{identifier}.{collection_name} expected value is invalid"
        ) from error


def _validate_predicates(identifier: str, playbook: dict[str, Any]) -> None:
    for collection_name in ("required_predicates", "supporting_predicates"):
        predicates = playbook.get(collection_name, [])
        if not isinstance(predicates, list) or len(predicates) > 64:
            raise ValueError(f"{identifier}.{collection_name} is invalid")
        for predicate in predicates:
            _validate_predicate(identifier, collection_name, predicate)


def _validate_marker(identifier: str, marker: Any) -> None:
    if not isinstance(marker, dict):
        raise ValueError(f"{identifier}.marker_predicates entries must be objects")
    _validate_marker_hex(identifier, marker)
    _validate_marker_offset(identifier, marker)
    _validate_applies_to_sids(
        identifier,
        "marker_predicates",
        marker.get("applies_to_sids", []),
    )


def _validate_marker_hex(identifier: str, marker: dict[str, Any]) -> None:
    marker_hex = str(marker.get("hex") or "")
    if (
        not marker_hex
        or len(marker_hex) > 512
        or len(marker_hex) % 2
        or not re.fullmatch(r"[0-9A-Fa-f]+", marker_hex)
    ):
        raise ValueError(f"{identifier}.marker_predicates hex is invalid")


def _validate_marker_offset(identifier: str, marker: dict[str, Any]) -> None:
    expected_offset = marker.get("expected_offset")
    if expected_offset is not None and (
        not isinstance(expected_offset, int)
        or expected_offset < 0
        or expected_offset > MAX_PACKET_BYTES
    ):
        raise ValueError(f"{identifier}.marker_predicates expected_offset is invalid")


def _validate_markers(identifier: str, playbook: dict[str, Any]) -> None:
    markers = playbook.get("marker_predicates", [])
    if not isinstance(markers, list) or len(markers) > MAX_MARKERS:
        raise ValueError(f"{identifier}.marker_predicates is invalid")
    for marker in markers:
        _validate_marker(identifier, marker)


def _validate_playbook(
    playbook: Any,
    *,
    index: int,
    identifiers: set[str],
) -> dict[str, Any]:
    if not isinstance(playbook, dict):
        raise ValueError(f"playbooks[{index}] must be an object")
    identifier = str(playbook.get("id") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", identifier):
        raise ValueError(f"playbooks[{index}].id is invalid")
    if identifier in identifiers:
        raise ValueError(f"duplicate detection playbook id: {identifier}")
    identifiers.add(identifier)
    if not isinstance(playbook.get("version"), int) or int(playbook["version"]) < 1:
        raise ValueError(f"{identifier}.version must be a positive integer")
    _validate_match(identifier, playbook)
    _validate_predicates(identifier, playbook)
    _validate_markers(identifier, playbook)
    return playbook


def load_detection_playbooks(path: Path) -> dict[str, Any]:
    payload = _read_registry(path)
    if payload.get("version") == 0:
        return payload
    playbooks = payload.get("playbooks")
    if not isinstance(playbooks, list):
        raise ValueError("detection playbooks must be a list")
    if len(playbooks) > 500:
        raise ValueError("detection playbook registry has too many playbooks")
    identifiers: set[str] = set()
    validated = [
        _validate_playbook(playbook, index=index, identifiers=identifiers)
        for index, playbook in enumerate(playbooks)
    ]
    return {
        "schema": PLAYBOOK_SCHEMA,
        "version": payload.get("version"),
        "generated_at": payload.get("generated_at"),
        "playbooks": validated,
    }
