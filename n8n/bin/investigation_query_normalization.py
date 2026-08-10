"""Normalization and event-tuple semantics for investigation requests."""
from __future__ import annotations

from investigation_query_schema import *  # noqa: F401,F403


def _require_mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvestigationQueryContractError(f"{label} must be an object")
    return value


def _require_exact_keys(
    value: dict[str, Any],
    *,
    allowed: set[str],
    required: set[str],
    label: str,
) -> None:
    missing = required - set(value)
    unknown = set(value) - allowed
    if missing:
        raise InvestigationQueryContractError(
            f"{label} is missing required fields: {', '.join(sorted(missing))}"
        )
    if unknown:
        raise InvestigationQueryContractError(
            f"{label} contains unsupported fields: {', '.join(sorted(unknown))}"
        )


def _safe_id(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not SAFE_ID_RE.fullmatch(text):
        raise InvestigationQueryContractError(f"{label} is invalid")
    return text


def _parse_utc(value: object, label: str) -> dt.datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise InvestigationQueryContractError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise InvestigationQueryContractError(f"{label} must use UTC")
    return parsed.astimezone(dt.timezone.utc)


def _iso_utc(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def _normalize_window(
    value: object,
    *,
    label: str,
    max_duration: dt.timedelta,
) -> tuple[dict[str, str], dt.datetime, dt.datetime]:
    window = _require_mapping(value, label)
    _require_exact_keys(
        window,
        allowed={"start", "end"},
        required={"start", "end"},
        label=label,
    )
    start = _parse_utc(window["start"], f"{label} start")
    end = _parse_utc(window["end"], f"{label} end")
    if end <= start or end - start > max_duration:
        raise InvestigationQueryContractError(
            f"{label} must be positive and no longer than {max_duration}"
        )
    return {"start": _iso_utc(start), "end": _iso_utc(end)}, start, end


def _normalize_observable(kind: str, value: object) -> str:
    text = str(value or "").strip().rstrip(".")
    if kind == "ips":
        try:
            return str(ipaddress.ip_address(text))
        except ValueError as exc:
            raise InvestigationQueryContractError("invalid exact IP observable") from exc
    if kind == "domains":
        if not SAFE_DOMAIN_RE.fullmatch(text):
            raise InvestigationQueryContractError("invalid exact domain observable")
        return text.lower()
    if kind in {"hosts", "users"} and SAFE_ATOM_RE.fullmatch(text):
        return text
    raise InvestigationQueryContractError(f"invalid exact {kind} observable")


def _normalize_observables(
    value: object,
    *,
    per_kind_limit: int,
    total_limit: int,
    require_one: bool,
    label: str,
) -> dict[str, list[str]]:
    data = _require_mapping(value, label)
    if set(data) - set(OBSERVABLE_KINDS):
        raise InvestigationQueryContractError(f"{label} contains an unsupported kind")
    normalized: dict[str, list[str]] = {}
    for kind in OBSERVABLE_KINDS:
        items = data.get(kind, [])
        if not isinstance(items, list) or len(items) > per_kind_limit:
            raise InvestigationQueryContractError(
                f"{label}.{kind} exceeds its {per_kind_limit}-value limit"
            )
        clean: list[str] = []
        for item in items:
            candidate = _normalize_observable(kind, item)
            if candidate not in clean:
                clean.append(candidate)
        normalized[kind] = clean
    count = sum(len(items) for items in normalized.values())
    if require_one and count == 0:
        raise InvestigationQueryContractError(f"{label} requires an exact observable")
    if count > total_limit:
        raise InvestigationQueryContractError(
            f"{label} exceeds its {total_limit}-value total limit"
        )
    return normalized


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
        raw = data[field]
        if field in {"source_ip", "destination_ip"}:
            clean[field] = _normalize_observable("ips", raw)
        elif field in {"source_port", "destination_port"}:
            if isinstance(raw, bool):
                raise InvestigationQueryContractError(f"{label}.{field} is invalid")
            try:
                port = int(raw)
            except (TypeError, ValueError) as exc:
                raise InvestigationQueryContractError(
                    f"{label}.{field} is invalid"
                ) from exc
            if port < 0 or port > 65535:
                raise InvestigationQueryContractError(
                    f"{label}.{field} is outside the port range"
                )
            clean[field] = port
        elif field in {"transport", "protocol"}:
            protocol = str(raw or "").strip().lower()
            if not SAFE_ATOM_RE.fullmatch(protocol):
                raise InvestigationQueryContractError(f"{label}.{field} is invalid")
            clean[field] = protocol
        elif field == "community_id":
            community_id = str(raw or "").strip()
            if not SAFE_COMMUNITY_ID_RE.fullmatch(community_id):
                raise InvestigationQueryContractError(
                    f"{label}.community_id is invalid"
                )
            clean[field] = community_id
        else:
            rule_id = str(raw or "").strip()
            if not SAFE_ATOM_RE.fullmatch(rule_id):
                raise InvestigationQueryContractError(f"{label}.rule_id is invalid")
            clean[field] = rule_id
    return clean


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
        item = _require_mapping(raw, f"authorization event tuple {index}")
        _require_exact_keys(
            item,
            allowed={
                "event_tuple", "role_semantics", "source", "evidence_ref",
            },
            required={
                "event_tuple", "role_semantics", "source", "evidence_ref",
            },
            label=f"authorization event tuple {index}",
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
        normalized = {
            "event_tuple": _normalize_event_tuple(
                item["event_tuple"],
                label=f"authorization event tuple {index}.event_tuple",
            ),
            "role_semantics": role_semantics,
            "source": source,
            "evidence_ref": evidence_ref,
        }
        if normalized in clean:
            if reject_duplicates:
                raise InvestigationQueryContractError(
                    "authorization event tuple is duplicated"
                )
            continue
        clean.append(normalized)
    return clean


def _index_matches_scope(index_name: str, index_scope: list[str]) -> bool:
    return any(
        fnmatch.fnmatchcase(index_name, pattern)
        or fnmatch.fnmatchcase(index_name, f".ds-{pattern}-*")
        for pattern in index_scope
    )


def _normalize_anchor(value: object) -> dict[str, str]:
    anchor = _require_mapping(value, "authorization anchor")
    _require_exact_keys(
        anchor,
        allowed={"index", "id"},
        required={"index", "id"},
        label="authorization anchor",
    )
    index_name = str(anchor["index"] or "").strip()
    document_id = str(anchor["id"] or "").strip()
    if (
        not index_name
        or not SAFE_ELASTIC_INDEX_RE.fullmatch(index_name)
        or not _index_matches_scope(index_name, ALERT_INDEX_SCOPE)
    ):
        raise InvestigationQueryContractError(
            "authorization anchor index is outside the reviewed alert scope"
        )
    if not SAFE_ELASTIC_ID_RE.fullmatch(document_id):
        raise InvestigationQueryContractError("authorization anchor id is invalid")
    return {"index": index_name, "id": document_id}


def _normalize_authorization_context(value: object) -> dict[str, Any]:
    context = _require_mapping(value, "authorization context")
    _require_exact_keys(
        context,
        allowed={
            "context_id", "case_id", "group_id", "actor_role", "anchor",
            "anchor_time", "time_envelope", "permitted_observables",
            "discovered_observables", "permitted_event_tuples",
        },
        required={
            "context_id", "case_id", "actor_role", "anchor", "anchor_time",
            "time_envelope", "permitted_observables",
        },
        label="authorization context",
    )
    envelope, envelope_start, envelope_end = _normalize_window(
        context["time_envelope"],
        label="authorization time envelope",
        max_duration=MAX_AUTHORIZATION_WINDOW,
    )
    actor_role = str(context["actor_role"] or "").strip()
    if actor_role not in ALLOWED_ACTOR_ROLES:
        raise InvestigationQueryContractError("authorization actor_role is unsupported")
    anchor_time = _parse_utc(
        context["anchor_time"],
        "authorization anchor_time",
    )
    if anchor_time < envelope_start or anchor_time > envelope_end:
        raise InvestigationQueryContractError(
            "authorization anchor_time escapes its time envelope"
        )
    permitted = _normalize_observables(
        context["permitted_observables"],
        per_kind_limit=MAX_CONTEXT_OBSERVABLES_PER_KIND,
        total_limit=MAX_CONTEXT_OBSERVABLES_PER_KIND * len(OBSERVABLE_KINDS),
        require_one=True,
        label="authorization permitted_observables",
    )
    discoveries = context.get("discovered_observables", [])
    if not isinstance(discoveries, list) or len(discoveries) > MAX_DISCOVERED_OBSERVABLES:
        raise InvestigationQueryContractError(
            "authorization discovered_observables exceeds its limit"
        )
    normalized_discoveries: list[dict[str, str]] = []
    for index, item in enumerate(discoveries):
        discovery = _require_mapping(item, f"discovered observable {index}")
        _require_exact_keys(
            discovery,
            allowed={"kind", "value", "evidence_ref"},
            required={"kind", "value", "evidence_ref"},
            label=f"discovered observable {index}",
        )
        kind = str(discovery["kind"] or "").strip()
        if kind not in OBSERVABLE_KINDS:
            raise InvestigationQueryContractError("discovered observable kind is unsupported")
        evidence_ref = str(discovery["evidence_ref"] or "").strip()
        if not SAFE_EVIDENCE_REF_RE.fullmatch(evidence_ref):
            raise InvestigationQueryContractError("discovered observable evidence_ref is invalid")
        normalized = {
            "kind": kind,
            "value": _normalize_observable(kind, discovery["value"]),
            "evidence_ref": evidence_ref,
        }
        if normalized not in normalized_discoveries:
            normalized_discoveries.append(normalized)
    normalized = {
        "context_id": _safe_id(context["context_id"], "authorization context_id"),
        "case_id": _safe_id(context["case_id"], "authorization case_id"),
        "group_id": (
            _safe_id(context["group_id"], "authorization group_id")
            if context.get("group_id")
            else ""
        ),
        "actor_role": actor_role,
        "anchor": _normalize_anchor(context["anchor"]),
        "anchor_time": _iso_utc(anchor_time),
        "time_envelope": envelope,
        "permitted_observables": permitted,
        "discovered_observables": normalized_discoveries,
        "permitted_event_tuples": _normalize_context_event_tuples(
            context.get("permitted_event_tuples")
        ),
    }
    normalized["_envelope_start"] = envelope_start
    normalized["_envelope_end"] = envelope_end
    return normalized


def _observable_authorizations(context: dict[str, Any]) -> dict[tuple[str, str], dict[str, str]]:
    authorized: dict[tuple[str, str], dict[str, str]] = {}
    context_id = context["context_id"]
    for kind, values in context["permitted_observables"].items():
        for value in values:
            authorized[(kind, value)] = {
                "kind": kind,
                "value": value,
                "source": "trusted_context",
                "evidence_ref": f"context:{context_id}:{kind}",
            }
    for item in context["discovered_observables"]:
        authorized[(item["kind"], item["value"])] = {
            "kind": item["kind"],
            "value": item["value"],
            "source": "prior_evidence",
            "evidence_ref": item["evidence_ref"],
        }
    return authorized


def pack_event_tuple_fields(pack_name: str) -> dict[str, str]:
    """Return tuple constraints that can also be authenticated in hit sources."""
    projected = set(PACKS[pack_name]["fields"])
    return {
        key: EVENT_TUPLE_FIELDS[key]
        for key, paths in EVENT_TUPLE_PATHS.items()
        if projected.intersection(paths)
    }


def pack_observable_fields(pack_name: str) -> dict[str, list[str]]:
    """Return only observable paths that the reviewed pack also projects."""
    projected = set(PACKS[pack_name]["fields"])
    return {
        kind: [field for field in fields if field in projected]
        for kind, fields in OBSERVABLE_FIELDS.items()
    }


def validate_pack_observables(
    observables: dict[str, list[str]],
    pack_name: str,
    *,
    label: str,
) -> None:
    """Reject values that the selected pack cannot possibly represent."""
    fields_by_kind = pack_observable_fields(pack_name)
    unsupported = sorted(
        kind
        for kind, values in observables.items()
        if values and not fields_by_kind.get(kind)
    )
    if unsupported:
        raise InvestigationQueryContractError(
            f"{label} uses observable kind(s) unsupported by pack "
            f"{pack_name}: {', '.join(unsupported)}"
        )
    if not any(
        values and fields_by_kind.get(kind)
        for kind, values in observables.items()
    ):
        raise InvestigationQueryContractError(
            f"{label} has no queryable observable in pack {pack_name}"
        )


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


def _event_tuple_authorization(
    requested: dict[str, Any],
    context: dict[str, Any],
    *,
    pack_name: str,
    observables: dict[str, list[str]],
    label: str,
) -> dict[str, Any]:
    unsupported = set(requested) - set(pack_event_tuple_fields(pack_name))
    if unsupported:
        raise InvestigationQueryContractError(
            f"{label} uses fields unavailable in pack {pack_name}: "
            + ", ".join(sorted(unsupported))
        )
    for field in ("source_ip", "destination_ip"):
        if field in requested and requested[field] not in observables["ips"]:
            raise InvestigationQueryContractError(
                f"{label}.{field} must also be an authorized IP observable"
            )
    matches = [
        entry
        for entry in context["permitted_event_tuples"]
        if all(
            entry["event_tuple"].get(field) == value
            for field, value in requested.items()
        )
    ]
    if not matches:
        raise InvestigationQueryContractError(
            f"{label} does not match one trusted role-aware event tuple"
        )
    # A subset can match duplicate group rows. Select deterministically and
    # carry the complete trusted tuple as provenance; caller values never
    # become authority merely by being present in the proposal.
    selected = min(
        matches,
        key=lambda item: canonical_digest(item),
    )
    if (
        {"source_ip", "destination_ip"}.intersection(
            selected["event_tuple"]
        )
        and not {"source_ip", "destination_ip"}.intersection(requested)
    ):
        raise InvestigationQueryContractError(
            f"{label} must retain a trusted source or destination IP role"
        )
    _validate_tuple_role_compatibility(
        requested,
        pack_name=pack_name,
        role_semantics=selected["role_semantics"],
        label=label,
    )
    return selected
