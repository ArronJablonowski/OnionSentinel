"""Bounded evidence validation owner."""
from __future__ import annotations

import datetime as dt



import ipaddress


















def require_exact_keys(
    r,
    value: dict,
    *,
    allowed: set[str],
    required: set[str],
    label: str,
) -> None:
    missing = required - set(value)
    unknown = set(value) - allowed
    if missing:
        r.fail(f"{label} is missing required fields: {', '.join(sorted(missing))}")
    if unknown:
        r.fail(f"{label} contains unsupported fields: {', '.join(sorted(unknown))}")


def validated_pivot_id(r, value: object, label: str) -> str:
    text = str(value or "").strip()
    if not r.SAFE_PIVOT_ID.fullmatch(text):
        r.fail(f"{label} is invalid")
    return text


def validated_pivot_window(
    r,
    value: object,
    *,
    label: str,
    max_duration: dt.timedelta,
) -> tuple[dict[str, str], dt.datetime, dt.datetime]:
    if not isinstance(value, dict):
        r.fail(f"{label} must be an object")
    r.require_exact_keys(
        value,
        allowed={"start", "end"},
        required={"start", "end"},
        label=label,
    )
    try:
        start, end = r.parse_time(value["start"]), r.parse_time(value["end"])
    except (TypeError, ValueError) as exc:
        r.fail(f"{label} is invalid: {exc}")
    if start.utcoffset() != dt.timedelta(0) or end.utcoffset() != dt.timedelta(0):
        r.fail(f"{label} must use UTC")
    if end <= start or end - start > max_duration:
        r.fail(f"{label} is outside its duration bound")
    return {"start": r.iso_utc(start), "end": r.iso_utc(end)}, start, end


def validated_pivot_observable(r, kind: str, value: object) -> str:
    text = str(value or "").strip().rstrip(".")
    if kind == "ips":
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            r.fail("invalid exact IP pivot observable")
    if kind == "domains":
        if not r.SAFE_DOMAIN.fullmatch(text):
            r.fail("invalid exact domain pivot observable")
        return text.lower()
    if kind in {"hosts", "users"} and r.SAFE_VALUE.fullmatch(text):
        return text
    r.fail(f"invalid exact {kind} pivot observable")
    raise AssertionError("unreachable")


def validated_pivot_observables(r, value: object, label: str) -> dict[str, list[str]]:
    if not isinstance(value, dict) or set(value) != set(r.OBSERVABLE_FIELDS):
        r.fail(f"{label} must contain exactly {', '.join(r.OBSERVABLE_FIELDS)}")
    clean: dict[str, list[str]] = {}
    for kind in r.OBSERVABLE_FIELDS:
        items = value[kind]
        if not isinstance(items, list) or len(items) > r.MAX_PIVOT_QUERY_OBSERVABLES:
            r.fail(f"{label}.{kind} exceeds its value limit")
        normalized = []
        for item in items:
            candidate = r.validated_pivot_observable(kind, item)
            if candidate not in normalized:
                normalized.append(candidate)
        clean[kind] = normalized
    count = sum(len(items) for items in clean.values())
    if count < 1 or count > r.MAX_PIVOT_QUERY_OBSERVABLES:
        r.fail(f"{label} must contain 1-{r.MAX_PIVOT_QUERY_OBSERVABLES} exact values")
    return clean


def validated_event_tuple(r, value: object, label: str) -> dict:
    if not isinstance(value, dict):
        r.fail(f"{label} must be an object")
    unknown = set(value) - set(r.EVENT_TUPLE_FIELDS)
    if unknown:
        r.fail(f"{label} contains unsupported fields: {', '.join(sorted(unknown))}")
    if not value:
        r.fail(f"{label} must not be empty")
    clean = {}
    for field in r.EVENT_TUPLE_FIELDS:
        if field not in value:
            continue
        raw = value[field]
        if field in {"source_ip", "destination_ip"}:
            clean[field] = r.validated_pivot_observable("ips", raw)
        elif field in {"source_port", "destination_port"}:
            if isinstance(raw, bool):
                r.fail(f"{label}.{field} is invalid")
            try:
                port = int(raw)
            except (TypeError, ValueError):
                r.fail(f"{label}.{field} is invalid")
            if port < 0 or port > 65535:
                r.fail(f"{label}.{field} is outside the port range")
            clean[field] = port
        elif field in {"transport", "protocol"}:
            protocol = str(raw or "").strip().lower()
            if not r.SAFE_VALUE.fullmatch(protocol):
                r.fail(f"{label}.{field} is invalid")
            clean[field] = protocol
        elif field == "community_id":
            community_id = str(raw or "").strip()
            if not r.SAFE_COMMUNITY_ID.fullmatch(community_id):
                r.fail(f"{label}.community_id is invalid")
            clean[field] = community_id
        else:
            rule_id = str(raw or "").strip()
            if not r.SAFE_VALUE.fullmatch(rule_id):
                r.fail(f"{label}.rule_id is invalid")
            clean[field] = rule_id
    return clean


def validated_event_tuple_manifest(r, value: object) -> list[dict]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > r.MAX_PIVOT_EVENT_TUPLES:
        r.fail("investigation pivot event tuple manifest is out of bounds")
    clean = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            r.fail(f"investigation pivot event tuple {index} must be an object")
        r.require_exact_keys(
            item,
            allowed={
                "event_tuple", "role_semantics", "source", "evidence_ref",
            },
            required={
                "event_tuple", "role_semantics", "source", "evidence_ref",
            },
            label=f"investigation pivot event tuple {index}",
        )
        source = str(item["source"] or "")
        role_semantics = str(item["role_semantics"] or "")
        evidence_ref = str(item["evidence_ref"] or "")
        if source not in {"trusted_context", "prior_evidence"}:
            r.fail("investigation pivot event tuple source is unsupported")
        if role_semantics not in r.PIVOT_ROLE_SEMANTICS:
            r.fail("investigation pivot event tuple role semantics are unsupported")
        if not r.SAFE_EVIDENCE_REF.fullmatch(evidence_ref):
            r.fail("investigation pivot event tuple evidence reference is invalid")
        normalized = {
            "event_tuple": r.validated_event_tuple(
                item["event_tuple"],
                f"investigation pivot event tuple {index}.event_tuple",
            ),
            "role_semantics": role_semantics,
            "source": source,
            "evidence_ref": evidence_ref,
        }
        if normalized in clean:
            r.fail("investigation pivot event tuple authorization is duplicated")
        clean.append(normalized)
    return clean


def pack_event_tuple_fields(r, pack_name: str) -> dict[str, str]:
    projected = set(r.PACKS[pack_name]["fields"])
    return {
        key: r.EVENT_TUPLE_FIELDS[key]
        for key, paths in r.EVENT_TUPLE_PATHS.items()
        if projected.intersection(paths)
    }


def validate_pack_observables(
    r,
    observables: dict[str, list[str]],
    pack_name: str,
    label: str,
) -> None:
    fields_by_kind = r.pack_observable_fields(pack_name)
    unsupported = sorted(
        kind
        for kind, values in observables.items()
        if values and not fields_by_kind.get(kind)
    )
    if unsupported:
        r.fail(
            f"{label} uses observable kind(s) unsupported by pack "
            f"{pack_name}: {', '.join(unsupported)}"
        )
    if not any(
        values and fields_by_kind.get(kind)
        for kind, values in observables.items()
    ):
        r.fail(f"{label} has no queryable observable in pack {pack_name}")


def tuple_match_semantics(
    r,
    pack_name: str,
    event_tuple: dict | None,
    role_semantics: str | None,
) -> str:
    if not event_tuple:
        return "observable_exact_any_field"
    mode = r.PACK_ROLE_MODE[pack_name]
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


def validate_tuple_role_compatibility(
    r,
    event_tuple: dict,
    *,
    pack_name: str,
    role_semantics: str,
    label: str,
) -> None:
    mode = r.PACK_ROLE_MODE[pack_name]
    if mode == "cross_sensor":
        if "community_id" not in event_tuple:
            r.fail(
                f"{label} requires community_id for deterministic "
                f"cross-sensor correlation in pack {pack_name}"
            )
        return
    if (
        mode == "zeek_originator_responder"
        and role_semantics != "zeek_originator_responder"
        and "community_id" not in event_tuple
    ):
        r.fail(
            f"{label} cannot project {role_semantics or 'unknown'} roles onto "
            "Zeek originator/responder fields without community_id"
        )


def validated_pivot_request(r, data: dict) -> dict:
    """Independently validate a Mac-authorized iterative query batch."""
    r.require_exact_keys(
        data,
        allowed={"query_contract", "operation", "batch_id", "authorization", "queries"},
        required={"query_contract", "operation", "batch_id", "authorization", "queries"},
        label="investigation pivot request",
    )
    if data["query_contract"] != r.INVESTIGATION_QUERY_CONTRACT:
        r.fail("investigation pivot query contract is unsupported")
    if data["operation"] != r.INVESTIGATION_QUERY_OPERATION:
        r.fail("investigation pivot operation is unsupported")
    authorization = data["authorization"]
    if not isinstance(authorization, dict):
        r.fail("investigation pivot authorization must be an object")
    r.require_exact_keys(
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
        label="investigation pivot authorization",
    )
    supplied_manifest_digest = str(authorization["manifest_digest"] or "")
    if (
        not r.SHA256.fullmatch(supplied_manifest_digest)
        or r.canonical_digest({
            key: value
            for key, value in authorization.items()
            if key != "manifest_digest"
        }) != supplied_manifest_digest
    ):
        r.fail("investigation pivot authorization manifest digest is invalid")
    context_digest = str(authorization["context_digest"] or "")
    if not r.SHA256.fullmatch(context_digest):
        r.fail("investigation pivot context digest is invalid")
    actor_role = str(authorization["actor_role"] or "")
    if actor_role not in r.PIVOT_ACTOR_ROLES:
        r.fail("investigation pivot actor role is unsupported")
    envelope, envelope_start, envelope_end = r.validated_pivot_window(
        authorization["time_envelope"],
        label="investigation pivot authorization window",
        max_duration=r.MAX_AUTHORIZATION_WINDOW,
    )
    if authorization["time_envelope"] != envelope:
        r.fail("investigation pivot authorization window is not canonical UTC")
    try:
        anchor_time_value = r.parse_time(authorization["anchor_time"])
    except (TypeError, ValueError) as exc:
        r.fail(f"investigation pivot anchor_time is invalid: {exc}")
    if (
        anchor_time_value < envelope_start
        or anchor_time_value > envelope_end
        or authorization["anchor_time"] != r.iso_utc(anchor_time_value)
    ):
        r.fail("investigation pivot anchor_time is outside its canonical envelope")
    anchor = r.validated_anchor(authorization["anchor"])
    if anchor is None:
        r.fail("investigation pivot authorization anchor is required")
    authorization_entries = authorization["observables"]
    if (
        not isinstance(authorization_entries, list)
        or not authorization_entries
        or len(authorization_entries) > r.MAX_PIVOT_BATCH_OBSERVABLES
    ):
        r.fail("investigation pivot authorization observable manifest is out of bounds")
    authorized: dict[tuple[str, str], dict[str, str]] = {}
    clean_entries: list[dict[str, str]] = []
    for index, item in enumerate(authorization_entries):
        if not isinstance(item, dict):
            r.fail(f"investigation pivot authorization observable {index} must be an object")
        r.require_exact_keys(
            item,
            allowed={"kind", "value", "source", "evidence_ref"},
            required={"kind", "value", "source", "evidence_ref"},
            label=f"investigation pivot authorization observable {index}",
        )
        kind = str(item["kind"] or "")
        source = str(item["source"] or "")
        evidence_ref = str(item["evidence_ref"] or "")
        if kind not in r.OBSERVABLE_FIELDS:
            r.fail("investigation pivot authorization observable kind is unsupported")
        if source not in {"trusted_context", "prior_evidence"}:
            r.fail("investigation pivot observable provenance source is unsupported")
        if not r.SAFE_EVIDENCE_REF.fullmatch(evidence_ref):
            r.fail("investigation pivot observable evidence reference is invalid")
        clean = {
            "kind": kind,
            "value": r.validated_pivot_observable(kind, item["value"]),
            "source": source,
            "evidence_ref": evidence_ref,
        }
        key = (kind, clean["value"])
        if key in authorized and authorized[key] != clean:
            r.fail("investigation pivot observable authorization conflicts")
        if key in authorized:
            r.fail("investigation pivot observable authorization is duplicated")
        authorized[key] = clean
        clean_entries.append(clean)
    authorized_event_tuples = r.validated_event_tuple_manifest(
        authorization.get("event_tuples")
    )
    queries = data["queries"]
    if not isinstance(queries, list) or not queries or len(queries) > r.MAX_PIVOT_QUERIES:
        r.fail(f"investigation pivot request must contain 1-{r.MAX_PIVOT_QUERIES} queries")
    clean_queries = []
    query_ids = set()
    used_authorizations = set()
    used_event_tuple_digests = set()
    hit_budget = 0
    window_budget = dt.timedelta()
    for index, item in enumerate(queries):
        if not isinstance(item, dict):
            r.fail(f"investigation pivot query {index} must be an object")
        r.require_exact_keys(
            item,
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
            label=f"investigation pivot query {index}",
        )
        query_id = r.validated_pivot_id(item["query_id"], f"pivot query {index} id")
        if query_id in query_ids:
            r.fail("investigation pivot query ids must be unique")
        query_ids.add(query_id)
        dialect = str(item["dialect"] or "")
        pack = str(item["pack"] or "")
        purpose = str(item["purpose"] or "")
        aggregation = str(item["aggregation"] or "")
        if dialect not in r.PIVOT_DIALECTS:
            r.fail("investigation pivot dialect is unsupported")
        if pack not in r.PACKS:
            r.fail("investigation pivot pack is unsupported")
        if purpose not in r.PIVOT_PURPOSES:
            r.fail("investigation pivot purpose is unsupported")
        if aggregation not in r.PIVOT_AGGREGATIONS:
            r.fail("investigation pivot aggregation is unsupported")
        window, start, end = r.validated_pivot_window(
            item["window"],
            label=f"investigation pivot query {query_id} window",
            max_duration=r.MAX_PIVOT_WINDOW,
        )
        if item["window"] != window:
            r.fail("investigation pivot query window is not canonical UTC")
        if start < envelope_start or end > envelope_end:
            r.fail("investigation pivot query escapes its authorization time envelope")
        window_budget += end - start
        observables = r.validated_pivot_observables(
            item["observables"],
            f"investigation pivot query {query_id} observables",
        )
        r.validate_pack_observables(
            observables,
            pack,
            f"investigation pivot query {query_id}",
        )
        provenance = item["observable_provenance"]
        if not isinstance(provenance, dict) or set(provenance) != set(r.OBSERVABLE_FIELDS):
            r.fail("investigation pivot observable provenance is incomplete")
        clean_provenance = {}
        for kind in r.OBSERVABLE_FIELDS:
            expected = []
            for observable in observables[kind]:
                key = (kind, observable)
                if key not in authorized:
                    r.fail("investigation pivot observable is absent from its authorization manifest")
                expected.append(authorized[key])
                used_authorizations.add(key)
            if provenance[kind] != expected:
                r.fail("investigation pivot observable provenance does not match its manifest")
            clean_provenance[kind] = [dict(entry) for entry in expected]
        event_tuple = None
        event_tuple_provenance = None
        tuple_fields_present = {
            field
            for field in ("event_tuple", "event_tuple_provenance")
            if field in item
        }
        if tuple_fields_present and tuple_fields_present != {
            "event_tuple", "event_tuple_provenance"
        }:
            r.fail("investigation pivot event tuple and provenance must be supplied together")
        if tuple_fields_present:
            event_tuple = r.validated_event_tuple(
                item["event_tuple"],
                f"investigation pivot query {query_id} event_tuple",
            )
            unsupported = set(event_tuple) - set(r.pack_event_tuple_fields(pack))
            if unsupported:
                r.fail("investigation pivot event tuple is unsupported by its pack")
            for field in ("source_ip", "destination_ip"):
                if field in event_tuple and event_tuple[field] not in observables["ips"]:
                    r.fail("investigation pivot role-aware IP is absent from observables")
            event_tuple_provenance = item["event_tuple_provenance"]
            if (
                not isinstance(event_tuple_provenance, dict)
                or event_tuple_provenance not in authorized_event_tuples
                or not all(
                    event_tuple_provenance["event_tuple"].get(field) == value
                    for field, value in event_tuple.items()
                )
            ):
                r.fail("investigation pivot event tuple provenance does not match its manifest")
            if (
                {"source_ip", "destination_ip"}.intersection(
                    event_tuple_provenance["event_tuple"]
                )
                and not {"source_ip", "destination_ip"}.intersection(event_tuple)
            ):
                r.fail("investigation pivot event tuple dropped its trusted IP role")
            r.validate_tuple_role_compatibility(
                event_tuple,
                pack_name=pack,
                role_semantics=event_tuple_provenance["role_semantics"],
                label=f"investigation pivot query {query_id} event_tuple",
            )
            used_event_tuple_digests.add(r.canonical_digest(event_tuple_provenance))
        expected_match_semantics = r.tuple_match_semantics(
            pack,
            event_tuple,
            (
                event_tuple_provenance.get("role_semantics")
                if event_tuple_provenance
                else None
            ),
        )
        if item["match_semantics"] != expected_match_semantics:
            r.fail("investigation pivot match semantics are invalid")
        if aggregation == "anchor_nearest":
            if dialect != "elastic":
                r.fail("anchor_nearest requires compiled Elastic DSL")
            if item.get("anchor_time") != authorization["anchor_time"]:
                r.fail("investigation pivot anchor_time does not match authorization")
        elif "anchor_time" in item:
            r.fail("investigation pivot unexpectedly supplied anchor_time")
        size = item["size"]
        if isinstance(size, bool) or not isinstance(size, int):
            r.fail("investigation pivot query size must be an integer")
        if size < 1 or size > r.MAX_PIVOT_HITS:
            r.fail(f"investigation pivot query size must be between 1 and {r.MAX_PIVOT_HITS}")
        hit_budget += 0 if aggregation == "count" else size
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
            clean_query["anchor_time"] = authorization["anchor_time"]
        if event_tuple is not None:
            clean_query["event_tuple"] = event_tuple
            clean_query["event_tuple_provenance"] = dict(
                event_tuple_provenance or {}
            )
        clean_queries.append(clean_query)
    if used_authorizations != set(authorized):
        r.fail("investigation pivot authorization contains an unused observable")
    if used_event_tuple_digests != {
        r.canonical_digest(item) for item in authorized_event_tuples
    }:
        r.fail("investigation pivot authorization contains an unused event tuple")
    if hit_budget > r.MAX_PIVOT_BATCH_HITS:
        r.fail("investigation pivot request exceeds its batch hit budget")
    if window_budget > r.MAX_PIVOT_BATCH_WINDOW:
        r.fail("investigation pivot request exceeds its cumulative time budget")
    clean_authorization = {
        "context_id": r.validated_pivot_id(
            authorization["context_id"], "investigation pivot context id"
        ),
        "case_id": r.validated_pivot_id(
            authorization["case_id"], "investigation pivot case id"
        ),
        "group_id": (
            r.validated_pivot_id(
                authorization["group_id"], "investigation pivot group id"
            )
            if authorization["group_id"]
            else ""
        ),
        "actor_role": actor_role,
        "anchor": anchor,
        "anchor_time": authorization["anchor_time"],
        "time_envelope": envelope,
        "context_digest": context_digest,
        "observables": clean_entries,
    }
    if authorized_event_tuples:
        clean_authorization["event_tuples"] = authorized_event_tuples
    clean_authorization["manifest_digest"] = r.canonical_digest(clean_authorization)
    if clean_authorization["manifest_digest"] != supplied_manifest_digest:
        r.fail("investigation pivot normalized authorization manifest digest is invalid")
    return {
        "query_contract": r.INVESTIGATION_QUERY_CONTRACT,
        "operation": r.INVESTIGATION_QUERY_OPERATION,
        "batch_id": r.validated_pivot_id(data["batch_id"], "investigation pivot batch id"),
        "authorization": clean_authorization,
        "queries": clean_queries,
    }
