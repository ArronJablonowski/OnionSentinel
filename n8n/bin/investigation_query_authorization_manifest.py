"""Authorization-manifest shape, context, and normalization."""
from __future__ import annotations

import datetime as dt
from typing import Any

from investigation_query_schema import (
    ALLOWED_ACTOR_ROLES,
    INVESTIGATION_QUERY_CONTRACT,
    INVESTIGATION_QUERY_OPERATION,
    MAX_AUTHORIZATION_WINDOW,
    MAX_BATCH_OBSERVABLES,
    OBSERVABLE_KINDS,
    SAFE_EVIDENCE_REF_RE,
    SHA256_RE,
    InvestigationQueryContractError,
    canonical_digest,
)
from investigation_query_normalization import (
    _iso_utc,
    _normalize_anchor,
    _normalize_observable,
    _normalize_window,
    _parse_utc,
    _require_exact_keys,
    _require_mapping,
    _safe_id,
)


def _authorized_request_root(
    payload: object,
) -> tuple[dict[str, Any], dict[str, Any]]:
    request = _require_mapping(payload, "authorized investigation request")
    _require_exact_keys(
        request,
        allowed={"query_contract", "operation", "batch_id", "authorization", "queries"},
        required={"query_contract", "operation", "batch_id", "authorization", "queries"},
        label="authorized investigation request",
    )
    if request["query_contract"] != INVESTIGATION_QUERY_CONTRACT:
        raise InvestigationQueryContractError("investigation query contract is unsupported")
    if request["operation"] != INVESTIGATION_QUERY_OPERATION:
        raise InvestigationQueryContractError("investigation query operation is unsupported")
    authorization = _require_mapping(request["authorization"], "authorization manifest")
    _require_exact_keys(
        authorization,
        allowed={
            "context_id", "case_id", "group_id", "actor_role", "anchor",
            "anchor_time", "time_envelope", "context_digest", "observables",
            "manifest_digest", "event_tuples",
        },
        required={
            "context_id", "case_id", "group_id", "actor_role", "anchor",
            "anchor_time", "time_envelope", "context_digest", "observables",
            "manifest_digest",
        },
        label="authorization manifest",
    )
    expected_digest = canonical_digest({
        key: value for key, value in authorization.items() if key != "manifest_digest"
    })
    if (
        not SHA256_RE.fullmatch(str(authorization["manifest_digest"] or ""))
        or authorization["manifest_digest"] != expected_digest
    ):
        raise InvestigationQueryContractError("authorization manifest digest is invalid")
    if not SHA256_RE.fullmatch(str(authorization["context_digest"] or "")):
        raise InvestigationQueryContractError("authorization context digest is invalid")
    return request, authorization


def _authorization_context(
    authorization: dict[str, Any]
) -> tuple[dict[str, str], dt.datetime, dt.datetime, str, dt.datetime]:
    envelope, envelope_start, envelope_end = _normalize_window(
        authorization["time_envelope"],
        label="authorization time envelope",
        max_duration=MAX_AUTHORIZATION_WINDOW,
    )
    actor_role = str(authorization["actor_role"] or "")
    if actor_role not in ALLOWED_ACTOR_ROLES:
        raise InvestigationQueryContractError("authorization actor role is unsupported")
    anchor_time = _parse_utc(authorization["anchor_time"], "authorization anchor_time")
    if anchor_time < envelope_start or anchor_time > envelope_end:
        raise InvestigationQueryContractError(
            "authorization anchor_time escapes its time envelope"
        )
    return envelope, envelope_start, envelope_end, actor_role, anchor_time


def _clean_authorization_observable(
    item: object, index: int
) -> tuple[tuple[str, str], dict[str, str]]:
    entry = _require_mapping(item, f"authorization observable {index}")
    _require_exact_keys(
        entry,
        allowed={"kind", "value", "source", "evidence_ref"},
        required={"kind", "value", "source", "evidence_ref"},
        label=f"authorization observable {index}",
    )
    kind = str(entry["kind"] or "")
    source = str(entry["source"] or "")
    evidence_ref = str(entry["evidence_ref"] or "")
    if kind not in OBSERVABLE_KINDS or source not in {
        "trusted_context", "prior_evidence"
    }:
        raise InvestigationQueryContractError(
            "authorization observable metadata is invalid"
        )
    if not SAFE_EVIDENCE_REF_RE.fullmatch(evidence_ref):
        raise InvestigationQueryContractError("authorization evidence_ref is invalid")
    clean = {
        "kind": kind,
        "value": _normalize_observable(kind, entry["value"]),
        "source": source,
        "evidence_ref": evidence_ref,
    }
    return (kind, clean["value"]), clean


def _authorization_observables(
    authorization: dict[str, Any]
) -> tuple[dict[tuple[str, str], dict[str, str]], list[dict[str, str]]]:
    entries = authorization["observables"]
    if not isinstance(entries, list) or len(entries) > MAX_BATCH_OBSERVABLES:
        raise InvestigationQueryContractError(
            "authorization observable manifest exceeds its limit"
        )
    authorized_values: dict[tuple[str, str], dict[str, str]] = {}
    clean_entries: list[dict[str, str]] = []
    for index, item in enumerate(entries):
        key, clean = _clean_authorization_observable(item, index)
        if key in authorized_values and authorized_values[key] != clean:
            raise InvestigationQueryContractError(
                "authorization observable provenance conflicts"
            )
        authorized_values[key] = clean
        if clean not in clean_entries:
            clean_entries.append(clean)
    return authorized_values, clean_entries


def _clean_authorization(
    authorization: dict[str, Any], context: dict[str, Any]
) -> dict[str, Any]:
    clean = {
        "context_id": _safe_id(authorization["context_id"], "authorization context_id"),
        "case_id": _safe_id(authorization["case_id"], "authorization case_id"),
        "group_id": (
            _safe_id(authorization["group_id"], "authorization group_id")
            if authorization["group_id"]
            else ""
        ),
        "actor_role": context["actor_role"],
        "anchor": _normalize_anchor(authorization["anchor"]),
        "anchor_time": _iso_utc(context["anchor_time"]),
        "time_envelope": context["envelope"],
        "context_digest": str(authorization["context_digest"]),
        "observables": context["clean_entries"],
    }
    if context["authorized_event_tuples"]:
        clean["event_tuples"] = context["authorized_event_tuples"]
    clean["manifest_digest"] = canonical_digest(clean)
    if clean["manifest_digest"] != authorization["manifest_digest"]:
        raise InvestigationQueryContractError(
            "normalized authorization manifest does not match its digest"
        )
    return clean
