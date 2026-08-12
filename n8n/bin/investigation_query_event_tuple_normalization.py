"""Event-tuple normalization, pack projection, and role semantics."""
from __future__ import annotations

from investigation_query_schema import *  # noqa: F401,F403
from investigation_query_normalization_primitives import (
    _require_exact_keys,
    _require_mapping,
)
from investigation_query_observable_normalization import _normalize_observable


def _normalize_event_tuple(value: object, *, label: str) -> dict[str, Any]:
    """Normalize one exact, role-preserving ECS event constraint tuple."""
    data = _require_mapping(value, label)
    unknown = set(data) - set(EVENT_TUPLE_FIELDS)
    if unknown:
        raise InvestigationQueryContractError(
            f"{label} contains unsupported fields: {', '.join(sorted(unknown))}"
        )
    if not data:
        raise InvestigationQueryContractError(f"{label} must not be empty")
    clean: dict[str, Any] = {}
    for field in EVENT_TUPLE_FIELDS:
        if field not in data:
            continue
        clean[field] = _normalize_event_tuple_value(field, data[field], label)
    return clean


def _normalize_event_tuple_value(field: str, raw: object, label: str) -> Any:
    if field in {"source_ip", "destination_ip"}:
        return _normalize_observable("ips", raw)
    if field in {"source_port", "destination_port"}:
        return _normalize_port(raw, label, field)
    if field in {"transport", "protocol"}:
        return _normalize_protocol(raw, label, field)
    if field == "community_id":
        return _normalize_community_id(raw, label)
    return _normalize_rule_id(raw, label)


def _normalize_port(raw: object, label: str, field: str) -> int:
    if isinstance(raw, bool):
        raise InvestigationQueryContractError(f"{label}.{field} is invalid")
    try:
        port = int(raw)
    except (TypeError, ValueError) as exc:
        raise InvestigationQueryContractError(f"{label}.{field} is invalid") from exc
    if port < 0 or port > 65535:
        raise InvestigationQueryContractError(
            f"{label}.{field} is outside the port range"
        )
    return port


def _normalize_protocol(raw: object, label: str, field: str) -> str:
    protocol = str(raw or "").strip().lower()
    if not SAFE_ATOM_RE.fullmatch(protocol):
        raise InvestigationQueryContractError(f"{label}.{field} is invalid")
    return protocol


def _normalize_community_id(raw: object, label: str) -> str:
    community_id = str(raw or "").strip()
    if not SAFE_COMMUNITY_ID_RE.fullmatch(community_id):
        raise InvestigationQueryContractError(f"{label}.community_id is invalid")
    return community_id


def _normalize_rule_id(raw: object, label: str) -> str:
    rule_id = str(raw or "").strip()
    if not SAFE_ATOM_RE.fullmatch(rule_id):
        raise InvestigationQueryContractError(f"{label}.rule_id is invalid")
    return rule_id


def _normalize_context_event_tuples(
    value: object,
    *,
    limit: int = MAX_CONTEXT_EVENT_TUPLES,
    reject_duplicates: bool = False,
) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > limit:
        raise InvestigationQueryContractError(
            "authorization permitted_event_tuples exceeds its limit"
        )
    clean: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        normalized = _normalize_context_event_tuple(raw, index)
        if normalized in clean:
            if reject_duplicates:
                raise InvestigationQueryContractError(
                    "authorization event tuple is duplicated"
                )
            continue
        clean.append(normalized)
    return clean


def _normalize_context_event_tuple(raw: object, index: int) -> dict[str, Any]:
    label = f"authorization event tuple {index}"
    item = _require_mapping(raw, label)
    _require_exact_keys(
        item,
        allowed={"event_tuple", "role_semantics", "source", "evidence_ref"},
        required={"event_tuple", "role_semantics", "source", "evidence_ref"},
        label=label,
    )
    source = str(item["source"] or "")
    role_semantics = str(item["role_semantics"] or "")
    evidence_ref = str(item["evidence_ref"] or "")
    if source not in {"trusted_context", "prior_evidence"}:
        raise InvestigationQueryContractError(
            "authorization event tuple source is unsupported"
        )
    if role_semantics not in ALLOWED_ROLE_SEMANTICS:
        raise InvestigationQueryContractError(
            "authorization event tuple role semantics are unsupported"
        )
    if not SAFE_EVIDENCE_REF_RE.fullmatch(evidence_ref):
        raise InvestigationQueryContractError(
            "authorization event tuple evidence_ref is invalid"
        )
    return {
        "event_tuple": _normalize_event_tuple(
            item["event_tuple"], label=f"{label}.event_tuple"
        ),
        "role_semantics": role_semantics,
        "source": source,
        "evidence_ref": evidence_ref,
    }


def pack_event_tuple_fields(pack_name: str) -> dict[str, str]:
    """Return tuple constraints that can also be authenticated in hit sources."""
    projected = set(PACKS[pack_name]["fields"])
    return {
        key: EVENT_TUPLE_FIELDS[key]
        for key, paths in EVENT_TUPLE_PATHS.items()
        if projected.intersection(paths)
    }


def tuple_match_semantics(
    pack_name: str,
    event_tuple: dict[str, Any] | None,
    role_semantics: str | None,
) -> str:
    """Return the exact role/correlation interpretation used by the broker."""
    if not event_tuple:
        return "observable_exact_any_field"
    mode = PACK_ROLE_MODE[pack_name]
    role = str(role_semantics or "")
    if mode == "cross_sensor" or (
        mode == "zeek_originator_responder"
        and role != "zeek_originator_responder"
    ):
        return "community_id_cross_sensor"
    if mode == "zeek_originator_responder":
        return "zeek_originator_responder_exact"
    if role == "packet_direction":
        return "packet_direction_exact"
    return "event_native_exact"


def _validate_tuple_role_compatibility(
    event_tuple: dict[str, Any],
    *,
    pack_name: str,
    role_semantics: str,
    label: str,
) -> None:
    mode = PACK_ROLE_MODE[pack_name]
    if mode == "cross_sensor":
        if "community_id" not in event_tuple:
            raise InvestigationQueryContractError(
                f"{label} requires community_id for deterministic "
                f"cross-sensor correlation in pack {pack_name}"
            )
        return
    if (
        mode == "zeek_originator_responder"
        and role_semantics != "zeek_originator_responder"
        and "community_id" not in event_tuple
    ):
        raise InvestigationQueryContractError(
            f"{label} cannot project {role_semantics or 'unknown'} roles onto "
            "Zeek originator/responder fields without community_id"
        )
