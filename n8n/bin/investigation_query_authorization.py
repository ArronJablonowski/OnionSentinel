"""Authorization and validation boundaries for investigation requests."""
from __future__ import annotations

from investigation_query_schema import *  # noqa: F401,F403
from investigation_query_normalization import *  # noqa: F401,F403
from investigation_query_normalization import (  # noqa: F401
    _event_tuple_authorization,
    _iso_utc,
    _normalize_anchor,
    _normalize_authorization_context,
    _normalize_context_event_tuples,
    _normalize_event_tuple,
    _normalize_observable,
    _normalize_observables,
    _normalize_window,
    _observable_authorizations,
    _parse_utc,
    _require_exact_keys,
    _require_mapping,
    _safe_id,
    _validate_tuple_role_compatibility,
)


def authorize_investigation_query_request(
    proposal: object,
    authorization_context: object,
) -> dict[str, Any]:
    """Combine an untrusted model proposal with a trusted local context."""
    proposed = _require_mapping(proposal, "investigation query proposal")
    _require_exact_keys(
        proposed,
        allowed={"query_contract", "batch_id", "queries"},
        required={"batch_id", "queries"},
        label="investigation query proposal",
    )
    if (
        "query_contract" in proposed
        and proposed["query_contract"] != INVESTIGATION_QUERY_CONTRACT
    ):
        raise InvestigationQueryContractError("investigation query contract is unsupported")
    queries = proposed["queries"]
    if not isinstance(queries, list) or not queries or len(queries) > MAX_QUERIES:
        raise InvestigationQueryContractError(
            f"investigation query proposal must contain 1-{MAX_QUERIES} queries"
        )
    context = _normalize_authorization_context(authorization_context)
    authorized_values = _observable_authorizations(context)
    normalized_queries: list[dict[str, Any]] = []
    query_ids: set[str] = set()
    batch_value_keys: set[tuple[str, str]] = set()
    total_hit_budget = 0
    total_window = dt.timedelta()
    used_authorizations: dict[tuple[str, str], dict[str, str]] = {}
    used_event_tuple_authorizations: list[dict[str, Any]] = []
    for index, raw_query in enumerate(queries):
        query = _require_mapping(raw_query, f"investigation query {index}")
        _require_exact_keys(
            query,
            allowed={
                "query_id", "dialect", "pack", "purpose", "window",
                "observables", "event_tuple", "size", "aggregation",
            },
            required={
                "query_id", "dialect", "pack", "purpose", "window",
                "observables", "size", "aggregation",
            },
            label=f"investigation query {index}",
        )
        query_id = _safe_id(query["query_id"], f"investigation query {index} query_id")
        if query_id in query_ids:
            raise InvestigationQueryContractError("investigation query ids must be unique")
        query_ids.add(query_id)
        dialect = str(query["dialect"] or "").strip()
        pack = str(query["pack"] or "").strip()
        purpose = str(query["purpose"] or "").strip()
        aggregation = str(query["aggregation"] or "").strip()
        if dialect not in ALLOWED_DIALECTS:
            raise InvestigationQueryContractError("investigation dialect is unsupported")
        if pack not in PACKS:
            raise InvestigationQueryContractError("investigation pack is unsupported")
        if purpose not in ALLOWED_PURPOSES:
            raise InvestigationQueryContractError("investigation purpose is unsupported")
        if aggregation not in ALLOWED_AGGREGATIONS:
            raise InvestigationQueryContractError("investigation aggregation is unsupported")
        window, start, end = _normalize_window(
            query["window"],
            label=f"investigation query {query_id} window",
            max_duration=MAX_WINDOW,
        )
        if start < context["_envelope_start"] or end > context["_envelope_end"]:
            raise InvestigationQueryContractError(
                f"investigation query {query_id} escapes its trusted time envelope"
            )
        total_window += end - start
        observables = _normalize_observables(
            query["observables"],
            per_kind_limit=MAX_QUERY_OBSERVABLES,
            total_limit=MAX_QUERY_OBSERVABLES,
            require_one=True,
            label=f"investigation query {query_id} observables",
        )
        validate_pack_observables(
            observables,
            pack,
            label=f"investigation query {query_id}",
        )
        provenance: dict[str, list[dict[str, str]]] = {
            kind: [] for kind in OBSERVABLE_KINDS
        }
        for kind, values in observables.items():
            for observable in values:
                key = (kind, observable)
                authorization = authorized_values.get(key)
                if authorization is None:
                    raise InvestigationQueryContractError(
                        f"investigation query {query_id} uses an observable "
                        "outside its trusted authorization context"
                    )
                provenance[kind].append(dict(authorization))
                used_authorizations[key] = dict(authorization)
                batch_value_keys.add(key)
        event_tuple = None
        event_tuple_provenance = None
        if "event_tuple" in query:
            event_tuple = _normalize_event_tuple(
                query["event_tuple"],
                label=f"investigation query {query_id} event_tuple",
            )
            event_tuple_provenance = _event_tuple_authorization(
                event_tuple,
                context,
                pack_name=pack,
                observables=observables,
                label=f"investigation query {query_id} event_tuple",
            )
            if event_tuple_provenance not in used_event_tuple_authorizations:
                used_event_tuple_authorizations.append(event_tuple_provenance)
        if aggregation == "anchor_nearest" and dialect != "elastic":
            raise InvestigationQueryContractError(
                "anchor_nearest is available only through compiled Elastic DSL"
            )
        try:
            size = int(query["size"])
        except (TypeError, ValueError) as exc:
            raise InvestigationQueryContractError("investigation size must be an integer") from exc
        if isinstance(query["size"], bool) or size < 1 or size > MAX_QUERY_HITS:
            raise InvestigationQueryContractError(
                f"investigation size must be between 1 and {MAX_QUERY_HITS}"
            )
        total_hit_budget += 0 if aggregation == "count" else size
        normalized_query = {
            "query_id": query_id,
            "dialect": dialect,
            "pack": pack,
            "purpose": purpose,
            "window": window,
            "observables": observables,
            "observable_provenance": provenance,
            "size": size,
            "aggregation": aggregation,
            "match_semantics": tuple_match_semantics(
                pack,
                event_tuple,
                (
                    event_tuple_provenance.get("role_semantics")
                    if event_tuple_provenance
                    else None
                ),
            ),
        }
        if aggregation == "anchor_nearest":
            normalized_query["anchor_time"] = context["anchor_time"]
        if event_tuple is not None:
            normalized_query["event_tuple"] = event_tuple
            normalized_query["event_tuple_provenance"] = dict(
                event_tuple_provenance or {}
            )
        normalized_queries.append(normalized_query)
    if len(batch_value_keys) > MAX_BATCH_OBSERVABLES:
        raise InvestigationQueryContractError(
            f"investigation batch exceeds {MAX_BATCH_OBSERVABLES} distinct observables"
        )
    if total_hit_budget > MAX_BATCH_HITS:
        raise InvestigationQueryContractError(
            f"investigation batch exceeds its {MAX_BATCH_HITS}-hit budget"
        )
    if total_window > dt.timedelta(hours=96):
        raise InvestigationQueryContractError(
            "investigation batch exceeds its cumulative 96-hour window budget"
        )
    context_for_digest = {
        key: value
        for key, value in context.items()
        if not key.startswith("_")
    }
    authorization = {
        "context_id": context["context_id"],
        "case_id": context["case_id"],
        "group_id": context["group_id"],
        "actor_role": context["actor_role"],
        "anchor": context["anchor"],
        "anchor_time": context["anchor_time"],
        "time_envelope": context["time_envelope"],
        "context_digest": canonical_digest(context_for_digest),
        "observables": sorted(
            used_authorizations.values(),
            key=lambda item: (item["kind"], item["value"], item["evidence_ref"]),
        ),
    }
    if used_event_tuple_authorizations:
        authorization["event_tuples"] = sorted(
            used_event_tuple_authorizations,
            key=canonical_digest,
        )
    authorization["manifest_digest"] = canonical_digest(authorization)
    return {
        "query_contract": INVESTIGATION_QUERY_CONTRACT,
        "operation": INVESTIGATION_QUERY_OPERATION,
        "batch_id": _safe_id(proposed["batch_id"], "investigation batch_id"),
        "authorization": authorization,
        "queries": normalized_queries,
    }


def validate_investigation_query_request(
    payload: object,
    *,
    authorization_context: object | None = None,
    allowed_observables: object | None = None,
    allowed_windows: object | None = None,
) -> dict[str, Any]:
    """Public request validator used by both SOC and Incident Response.

    `authorization_context` is the preferred interface.  The two legacy-style
    keyword names are accepted only together and are converted into a minimal
    trusted context for adapters that landed before this contract.
    """
    if authorization_context is not None:
        return authorize_investigation_query_request(payload, authorization_context)
    if allowed_observables is not None or allowed_windows is not None:
        if allowed_observables is None or not isinstance(allowed_windows, list) or not allowed_windows:
            raise InvestigationQueryContractError(
                "allowed_observables and allowed_windows must be supplied together"
            )
        first = _require_mapping(allowed_windows[0], "allowed window")
        last = _require_mapping(allowed_windows[-1], "allowed window")
        first_start = _parse_utc(first.get("start"), "allowed window start")
        last_end = _parse_utc(last.get("end"), "allowed window end")
        authorization_context = {
            "context_id": "adapter-context",
            "case_id": "adapter-case",
            "actor_role": "incident_responder",
            "anchor": {
                "index": "logs-suricata.alerts-so",
                "id": "adapter-anchor",
            },
            "anchor_time": _iso_utc(
                first_start + (last_end - first_start) / 2
            ),
            "time_envelope": {"start": first.get("start"), "end": last.get("end")},
            "permitted_observables": allowed_observables,
            "discovered_observables": [],
        }
        return authorize_investigation_query_request(payload, authorization_context)
    return validate_authorized_investigation_query_request(payload)


def validate_authorized_investigation_query_request(payload: object) -> dict[str, Any]:
    """Validate and normalize the already-authorized forced-command payload."""
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
    expected_manifest_digest = canonical_digest({
        key: value for key, value in authorization.items() if key != "manifest_digest"
    })
    if (
        not SHA256_RE.fullmatch(str(authorization["manifest_digest"] or ""))
        or authorization["manifest_digest"] != expected_manifest_digest
    ):
        raise InvestigationQueryContractError("authorization manifest digest is invalid")
    if not SHA256_RE.fullmatch(str(authorization["context_digest"] or "")):
        raise InvestigationQueryContractError("authorization context digest is invalid")
    envelope, envelope_start, envelope_end = _normalize_window(
        authorization["time_envelope"],
        label="authorization time envelope",
        max_duration=MAX_AUTHORIZATION_WINDOW,
    )
    actor_role = str(authorization["actor_role"] or "")
    if actor_role not in ALLOWED_ACTOR_ROLES:
        raise InvestigationQueryContractError("authorization actor role is unsupported")
    anchor_time = _parse_utc(
        authorization["anchor_time"],
        "authorization anchor_time",
    )
    if anchor_time < envelope_start or anchor_time > envelope_end:
        raise InvestigationQueryContractError(
            "authorization anchor_time escapes its time envelope"
        )
    authorized_entries = authorization["observables"]
    if not isinstance(authorized_entries, list) or len(authorized_entries) > MAX_BATCH_OBSERVABLES:
        raise InvestigationQueryContractError("authorization observable manifest exceeds its limit")
    authorized_values: dict[tuple[str, str], dict[str, str]] = {}
    clean_entries: list[dict[str, str]] = []
    for index, item in enumerate(authorized_entries):
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
        if kind not in OBSERVABLE_KINDS or source not in {"trusted_context", "prior_evidence"}:
            raise InvestigationQueryContractError("authorization observable metadata is invalid")
        if not SAFE_EVIDENCE_REF_RE.fullmatch(evidence_ref):
            raise InvestigationQueryContractError("authorization evidence_ref is invalid")
        clean = {
            "kind": kind,
            "value": _normalize_observable(kind, entry["value"]),
            "source": source,
            "evidence_ref": evidence_ref,
        }
        key = (kind, clean["value"])
        if key in authorized_values and authorized_values[key] != clean:
            raise InvestigationQueryContractError("authorization observable provenance conflicts")
        authorized_values[key] = clean
        if clean not in clean_entries:
            clean_entries.append(clean)
    authorized_event_tuples = _normalize_context_event_tuples(
        authorization.get("event_tuples"),
        limit=MAX_QUERIES,
        reject_duplicates=True,
    )
    queries = request["queries"]
    if not isinstance(queries, list) or not queries or len(queries) > MAX_QUERIES:
        raise InvestigationQueryContractError(
            f"authorized request must contain 1-{MAX_QUERIES} queries"
        )
    clean_queries: list[dict[str, Any]] = []
    query_ids: set[str] = set()
    total_hits = 0
    total_window = dt.timedelta()
    used_values: set[tuple[str, str]] = set()
    used_event_tuple_digests: set[str] = set()
    for index, raw_query in enumerate(queries):
        query = _require_mapping(raw_query, f"authorized query {index}")
        _require_exact_keys(
            query,
            allowed={
                "query_id", "dialect", "pack", "purpose", "window",
                "observables", "observable_provenance", "size", "aggregation",
                "event_tuple", "event_tuple_provenance", "match_semantics",
                "anchor_time",
            },
            required={
                "query_id", "dialect", "pack", "purpose", "window",
                "observables", "observable_provenance", "size", "aggregation",
                "match_semantics",
            },
            label=f"authorized query {index}",
        )
        query_id = _safe_id(query["query_id"], f"authorized query {index} query_id")
        if query_id in query_ids:
            raise InvestigationQueryContractError("authorized query ids must be unique")
        query_ids.add(query_id)
        dialect = str(query["dialect"] or "")
        pack = str(query["pack"] or "")
        purpose = str(query["purpose"] or "")
        aggregation = str(query["aggregation"] or "")
        if dialect not in ALLOWED_DIALECTS or pack not in PACKS:
            raise InvestigationQueryContractError("authorized query dialect or pack is invalid")
        if purpose not in ALLOWED_PURPOSES or aggregation not in ALLOWED_AGGREGATIONS:
            raise InvestigationQueryContractError("authorized query purpose or aggregation is invalid")
        window, start, end = _normalize_window(
            query["window"],
            label=f"authorized query {query_id} window",
            max_duration=MAX_WINDOW,
        )
        if start < envelope_start or end > envelope_end:
            raise InvestigationQueryContractError("authorized query escapes its time envelope")
        total_window += end - start
        observables = _normalize_observables(
            query["observables"],
            per_kind_limit=MAX_QUERY_OBSERVABLES,
            total_limit=MAX_QUERY_OBSERVABLES,
            require_one=True,
            label=f"authorized query {query_id} observables",
        )
        validate_pack_observables(
            observables,
            pack,
            label=f"authorized query {query_id}",
        )
        provenance = _require_mapping(
            query["observable_provenance"],
            f"authorized query {query_id} observable_provenance",
        )
        if set(provenance) != set(OBSERVABLE_KINDS):
            raise InvestigationQueryContractError(
                "authorized query observable provenance kinds are incomplete"
            )
        clean_provenance: dict[str, list[dict[str, str]]] = {}
        for kind in OBSERVABLE_KINDS:
            entries = provenance[kind]
            if not isinstance(entries, list):
                raise InvestigationQueryContractError(
                    "authorized query observable provenance must be arrays"
                )
            expected = []
            for value in observables[kind]:
                entry = authorized_values.get((kind, value))
                if entry is None:
                    raise InvestigationQueryContractError(
                        "authorized query uses an observable absent from its manifest"
                    )
                expected.append(entry)
                used_values.add((kind, value))
            if entries != expected:
                raise InvestigationQueryContractError(
                    "authorized query observable provenance does not match its manifest"
                )
            clean_provenance[kind] = [dict(item) for item in entries]
        event_tuple = None
        event_tuple_provenance = None
        tuple_fields_present = {
            field
            for field in ("event_tuple", "event_tuple_provenance")
            if field in query
        }
        if tuple_fields_present and tuple_fields_present != {
            "event_tuple", "event_tuple_provenance"
        }:
            raise InvestigationQueryContractError(
                "authorized query event tuple and provenance must be supplied together"
            )
        if tuple_fields_present:
            event_tuple = _normalize_event_tuple(
                query["event_tuple"],
                label=f"authorized query {query_id} event_tuple",
            )
            unsupported = set(event_tuple) - set(pack_event_tuple_fields(pack))
            if unsupported:
                raise InvestigationQueryContractError(
                    f"authorized query {query_id} event tuple is unsupported by its pack"
                )
            for field in ("source_ip", "destination_ip"):
                if field in event_tuple and event_tuple[field] not in observables["ips"]:
                    raise InvestigationQueryContractError(
                        "authorized query role-aware IP is absent from observables"
                    )
            event_tuple_provenance = _require_mapping(
                query["event_tuple_provenance"],
                f"authorized query {query_id} event_tuple_provenance",
            )
            if (
                event_tuple_provenance not in authorized_event_tuples
                or not all(
                    event_tuple_provenance["event_tuple"].get(field) == value
                    for field, value in event_tuple.items()
                )
            ):
                raise InvestigationQueryContractError(
                    "authorized query event tuple provenance does not match its manifest"
                )
            if (
                {"source_ip", "destination_ip"}.intersection(
                    event_tuple_provenance["event_tuple"]
                )
                and not {"source_ip", "destination_ip"}.intersection(event_tuple)
            ):
                raise InvestigationQueryContractError(
                    "authorized query event tuple dropped its trusted IP role"
                )
            _validate_tuple_role_compatibility(
                event_tuple,
                pack_name=pack,
                role_semantics=event_tuple_provenance["role_semantics"],
                label=f"authorized query {query_id} event_tuple",
            )
            used_event_tuple_digests.add(canonical_digest(event_tuple_provenance))
        expected_match_semantics = tuple_match_semantics(
            pack,
            event_tuple,
            (
                event_tuple_provenance.get("role_semantics")
                if event_tuple_provenance
                else None
            ),
        )
        if query["match_semantics"] != expected_match_semantics:
            raise InvestigationQueryContractError(
                f"authorized query {query_id} match semantics are invalid"
            )
        if aggregation == "anchor_nearest":
            if dialect != "elastic":
                raise InvestigationQueryContractError(
                    "anchor_nearest is available only through compiled Elastic DSL"
                )
            if query.get("anchor_time") != _iso_utc(anchor_time):
                raise InvestigationQueryContractError(
                    f"authorized query {query_id} anchor_time is invalid"
                )
        elif "anchor_time" in query:
            raise InvestigationQueryContractError(
                f"authorized query {query_id} unexpectedly supplied anchor_time"
            )
        try:
            size = int(query["size"])
        except (TypeError, ValueError) as exc:
            raise InvestigationQueryContractError("authorized query size is invalid") from exc
        if isinstance(query["size"], bool) or size < 1 or size > MAX_QUERY_HITS:
            raise InvestigationQueryContractError("authorized query size is out of bounds")
        total_hits += 0 if aggregation == "count" else size
        clean_query = {
            "query_id": query_id,
            "dialect": dialect,
            "pack": pack,
            "purpose": purpose,
            "window": window,
            "observables": observables,
            "observable_provenance": clean_provenance,
            "size": size,
            "aggregation": aggregation,
            "match_semantics": expected_match_semantics,
        }
        if aggregation == "anchor_nearest":
            clean_query["anchor_time"] = _iso_utc(anchor_time)
        if event_tuple is not None:
            clean_query["event_tuple"] = event_tuple
            clean_query["event_tuple_provenance"] = dict(
                event_tuple_provenance or {}
            )
        clean_queries.append(clean_query)
    if used_values != set(authorized_values):
        raise InvestigationQueryContractError(
            "authorization manifest contains unused or missing observable entries"
        )
    if used_event_tuple_digests != {
        canonical_digest(item) for item in authorized_event_tuples
    }:
        raise InvestigationQueryContractError(
            "authorization event tuple manifest contains unused or missing entries"
        )
    if total_hits > MAX_BATCH_HITS:
        raise InvestigationQueryContractError("authorized request exceeds its hit budget")
    if total_window > dt.timedelta(hours=96):
        raise InvestigationQueryContractError("authorized request exceeds its window budget")
    clean_authorization = {
        "context_id": _safe_id(authorization["context_id"], "authorization context_id"),
        "case_id": _safe_id(authorization["case_id"], "authorization case_id"),
        "group_id": (
            _safe_id(authorization["group_id"], "authorization group_id")
            if authorization["group_id"]
            else ""
        ),
        "actor_role": actor_role,
        "anchor": _normalize_anchor(authorization["anchor"]),
        "anchor_time": _iso_utc(anchor_time),
        "time_envelope": envelope,
        "context_digest": str(authorization["context_digest"]),
        "observables": clean_entries,
    }
    if authorized_event_tuples:
        clean_authorization["event_tuples"] = authorized_event_tuples
    clean_authorization["manifest_digest"] = canonical_digest(clean_authorization)
    if clean_authorization["manifest_digest"] != authorization["manifest_digest"]:
        raise InvestigationQueryContractError(
            "normalized authorization manifest does not match its digest"
        )
    return {
        "query_contract": INVESTIGATION_QUERY_CONTRACT,
        "operation": INVESTIGATION_QUERY_OPERATION,
        "batch_id": _safe_id(request["batch_id"], "investigation batch_id"),
        "authorization": clean_authorization,
        "queries": clean_queries,
    }
