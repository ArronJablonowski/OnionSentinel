"""Trusted authorization-context projection and tuple authorization."""
from __future__ import annotations

from investigation_query_schema import *  # noqa: F401,F403
from investigation_query_event_tuple_normalization import (
    _normalize_context_event_tuples,
    _validate_tuple_role_compatibility,
    pack_event_tuple_fields,
)
from investigation_query_normalization_primitives import (
    _iso_utc,
    _normalize_window,
    _parse_utc,
    _require_exact_keys,
    _require_mapping,
    _safe_id,
)
from investigation_query_observable_normalization import (
    _normalize_observable,
    _normalize_observables,
)


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
    components = _authorization_context_components(context)
    normalized = {
        "context_id": _safe_id(context["context_id"], "authorization context_id"),
        "case_id": _safe_id(context["case_id"], "authorization case_id"),
        "group_id": (
            _safe_id(context["group_id"], "authorization group_id")
            if context.get("group_id")
            else ""
        ),
        "actor_role": components["actor_role"],
        "anchor": _normalize_anchor(context["anchor"]),
        "anchor_time": _iso_utc(components["anchor_time"]),
        "time_envelope": components["envelope"],
        "permitted_observables": components["permitted_observables"],
        "discovered_observables": components["discovered_observables"],
        "permitted_event_tuples": _normalize_context_event_tuples(
            context.get("permitted_event_tuples")
        ),
    }
    normalized["_envelope_start"] = components["envelope_start"]
    normalized["_envelope_end"] = components["envelope_end"]
    return normalized


def _authorization_context_components(context: dict[str, Any]) -> dict[str, Any]:
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
    normalized_discoveries = _normalize_discovered_observables(
        context.get("discovered_observables", [])
    )
    return {
        "envelope": envelope,
        "envelope_start": envelope_start,
        "envelope_end": envelope_end,
        "actor_role": actor_role,
        "anchor_time": anchor_time,
        "permitted_observables": permitted,
        "discovered_observables": normalized_discoveries,
    }


def _normalize_discovered_observables(discoveries: object) -> list[dict[str, str]]:
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
    return normalized_discoveries


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


def _event_tuple_authorization(
    requested: dict[str, Any],
    context: dict[str, Any],
    *,
    pack_name: str,
    observables: dict[str, list[str]],
    label: str,
) -> dict[str, Any]:
    _validate_tuple_pack_fields(requested, pack_name, label)
    _validate_tuple_ip_authority(requested, observables, label)
    matches = _trusted_tuple_matches(requested, context)
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
    _validate_trusted_ip_role(requested, selected, label)
    _validate_tuple_role_compatibility(
        requested,
        pack_name=pack_name,
        role_semantics=selected["role_semantics"],
        label=label,
    )
    return selected


def _validate_tuple_pack_fields(
    requested: dict[str, Any], pack_name: str, label: str
) -> None:
    unsupported = set(requested) - set(pack_event_tuple_fields(pack_name))
    if unsupported:
        raise InvestigationQueryContractError(
            f"{label} uses fields unavailable in pack {pack_name}: "
            + ", ".join(sorted(unsupported))
        )


def _validate_tuple_ip_authority(
    requested: dict[str, Any],
    observables: dict[str, list[str]],
    label: str,
) -> None:
    for field in ("source_ip", "destination_ip"):
        if field in requested and requested[field] not in observables["ips"]:
            raise InvestigationQueryContractError(
                f"{label}.{field} must also be an authorized IP observable"
            )


def _trusted_tuple_matches(
    requested: dict[str, Any], context: dict[str, Any]
) -> list[dict[str, Any]]:
    return [
        entry
        for entry in context["permitted_event_tuples"]
        if all(
            entry["event_tuple"].get(field) == value
            for field, value in requested.items()
        )
    ]


def _validate_trusted_ip_role(
    requested: dict[str, Any], selected: dict[str, Any], label: str
) -> None:
    if (
        {"source_ip", "destination_ip"}.intersection(
            selected["event_tuple"]
        )
        and not {"source_ip", "destination_ip"}.intersection(requested)
    ):
        raise InvestigationQueryContractError(
            f"{label} must retain a trusted source or destination IP role"
        )
