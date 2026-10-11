"""Bounded evidence query execution owner."""
from __future__ import annotations



import hashlib


import json











import time






def pack_observable_fields(r, pack_name: str) -> dict[str, list[str]]:
    projected = set(r.PACKS[pack_name]["fields"])
    return {
        kind: [field for field in fields if field in projected]
        for kind, fields in r.OBSERVABLE_FIELDS.items()
    }


def observable_clause(
    r,
    observables: dict[str, list[str]],
    pack_name: str | None = None,
) -> dict:
    should = []
    fields_by_kind = (
        r.pack_observable_fields(pack_name)
        if pack_name is not None
        else r.OBSERVABLE_FIELDS
    )
    for kind, fields in fields_by_kind.items():
        for value in observables.get(kind, []):
            should.extend({"term": {field: value}} for field in fields)
    if not should:
        r.fail(
            f"pack {pack_name or 'incident-evidence'} produced no "
            "observable query clauses"
        )
    return {"bool": {"should": should, "minimum_should_match": 1}}


def pivot_event_tuple_fields(r, query: dict) -> list[str]:
    if query.get("match_semantics") == "community_id_cross_sensor":
        return ["community_id"]
    return list(query.get("event_tuple") or {})


def pivot_event_tuple_term_clause(r, field: str, value: object) -> dict:
    paths = r.EVENT_TUPLE_PATHS[field]
    if len(paths) == 1:
        return {"term": {paths[0]: value}}
    return {
        "bool": {
            "should": [
                {"term": {path: value}}
                for path in paths
            ],
            "minimum_should_match": 1,
        }
    }


def event_tuple_clause(r, query: dict) -> dict:
    event_tuple = query.get("event_tuple") or {}
    fields = r.pivot_event_tuple_fields(query)
    if not fields:
        r.fail("event tuple produced no role-compatible query clauses")
    return {
        "bool": {
            "filter": [
                r.pivot_event_tuple_term_clause(field, event_tuple[field])
                for field in fields
            ]
        }
    }


def dataset_clause(r, datasets: list[str]) -> dict:
    if not datasets:
        r.fail("reviewed query pack has no datasets")
    return {
        "bool": {
            "should": [
                {"term": {"event.dataset": dataset}}
                for dataset in datasets
            ],
            "minimum_should_match": 1,
        }
    }


def kql_equivalent(
    r,
    window: dict,
    pack_name: str,
    observables: dict[str, list[str]],
) -> str:
    pack = r.PACKS[pack_name]
    dataset = " or ".join(
        f'event.dataset : "{value}"'
        for value in pack["datasets"]
    )
    obs = []
    for kind, fields in r.pack_observable_fields(pack_name).items():
        for value in observables.get(kind, []):
            obs.append("(" + " or ".join(f'{field} : "{value}"' for field in fields) + ")")
    return f'@timestamp >= "{window["start"]}" and @timestamp <= "{window["end"]}" and ({dataset}) and (' + " or ".join(obs) + ")"


def query_endpoint(r, index_scope: list[str]) -> str:
    indices = ",".join(index_scope)
    return (
        f"{indices}/_search"
        f"?ignore_unavailable=true&expand_wildcards=open&preference={r.QUERY_PREFERENCE}"
    )


def canonical_digest(r, value: object) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(encoded.encode()).hexdigest()


def search_audit(r, body: dict, index_scope: list[str]) -> dict:
    endpoint = r.query_endpoint(index_scope)
    return {
        "query_digest": r.canonical_digest(body),
        "execution_digest": r.canonical_digest({
            "index_scope": index_scope,
            "query_endpoint": endpoint,
            "query_dsl": body,
        }),
        "query_dsl": body,
        "index_scope": list(index_scope),
        "query_endpoint": endpoint,
    }


def bounded_error(r, value: object) -> str:
    if isinstance(value, str):
        return value[:1000]
    try:
        return json.dumps(value, separators=(",", ":"), sort_keys=True)[:1000]
    except (TypeError, ValueError):
        return str(value)[:1000]


def empty_search_result(r, body: dict, index_scope: list[str], status: str, duration_ms: int, **extra) -> dict:
    return {
        **r.search_audit(body, index_scope),
        "status": status,
        "semantic_valid": False,
        "total_hits": 0,
        "total_hits_relation": "eq",
        "returned_hits": 0,
        "truncated": False,
        "duration_ms": duration_ms,
        "timed_out": status == "timeout",
        "took_ms": 0,
        "shards": {
            "total": 0,
            "successful": 0,
            "skipped": 0,
            "failed": 0,
            "failures": [],
        },
        "hits": [],
        **extra,
    }


def parse_shards(r, value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("Elasticsearch response is missing _shards metadata")
    parsed = {}
    for field in ("total", "successful", "failed"):
        item = value.get(field)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise ValueError(f"Elasticsearch _shards.{field} is invalid")
        parsed[field] = item
    skipped = value.get("skipped", 0)
    if isinstance(skipped, bool) or not isinstance(skipped, int) or skipped < 0:
        raise ValueError("Elasticsearch _shards.skipped is invalid")
    if parsed["failed"] > parsed["total"] or parsed["successful"] > parsed["total"]:
        raise ValueError("Elasticsearch shard counts are inconsistent")
    failures = value.get("failures") or []
    if not isinstance(failures, list):
        raise ValueError("Elasticsearch _shards.failures is invalid")
    parsed["skipped"] = skipped
    parsed["failures"] = [
        {
            "index": str(item.get("index") or "")[:255],
            "type": str(((item.get("reason") or {}).get("type") if isinstance(item.get("reason"), dict) else "") or "")[:255],
            "reason": str(((item.get("reason") or {}).get("reason") if isinstance(item.get("reason"), dict) else item.get("reason")) or "")[:1000],
        }
        for item in failures[:20]
        if isinstance(item, dict)
    ]
    return parsed


def execute_search(r, body: dict, index_scope: list[str]) -> dict:
    r.AUDIT_CONTEXT["elastic_search_count"] = int(
        r.AUDIT_CONTEXT.get("elastic_search_count", 0)
    ) + 1
    audit = r.search_audit(body, index_scope)
    encoded = json.dumps(body, separators=(",", ":"), sort_keys=True)
    started = time.monotonic()
    try:
        proc = r.run_bounded_command(
            [str(r.SO_QUERY), audit["query_endpoint"], "-d", encoded],
            timeout_seconds=r.QUERY_TIMEOUT_SECONDS,
            max_stdout_bytes=r.MAX_OUTPUT_BYTES,
            max_stderr_bytes=r.MAX_STDERR_BYTES,
        )
    except r.BoundedCommandError as exc:
        status = "timeout" if exc.reason == "timeout" else "output_limit"
        return r.empty_search_result(
            body,
            index_scope,
            status,
            round((time.monotonic() - started) * 1000),
            error=(
                "Elasticsearch query exceeded the wrapper timeout"
                if status == "timeout"
                else "Elasticsearch response exceeded the wrapper output limit"
            ),
        )
    duration_ms = round((time.monotonic() - started) * 1000)
    if proc.returncode != 0:
        error = proc.stderr.decode("utf-8", "replace")[:1000]
        return r.empty_search_result(body, index_scope, "error", duration_ms, error=error)
    try:
        parsed = json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return r.empty_search_result(body, index_scope, "invalid_response", duration_ms, error=str(exc))
    if not isinstance(parsed, dict):
        return r.empty_search_result(
            body,
            index_scope,
            "invalid_response",
            duration_ms,
            error="Elasticsearch response root must be an object",
        )
    if parsed.get("error") is not None:
        return r.empty_search_result(
            body,
            index_scope,
            "error",
            duration_ms,
            error=r.bounded_error(parsed.get("error")),
        )
    try:
        shards = r.parse_shards(parsed.get("_shards"))
    except ValueError as exc:
        return r.empty_search_result(body, index_scope, "invalid_response", duration_ms, error=str(exc))
    timed_out = parsed.get("timed_out")
    if not isinstance(timed_out, bool):
        return r.empty_search_result(
            body,
            index_scope,
            "invalid_response",
            duration_ms,
            shards=shards,
            error="Elasticsearch timed_out flag is missing or invalid",
        )
    took_ms = parsed.get("took")
    if isinstance(took_ms, bool) or not isinstance(took_ms, int) or took_ms < 0:
        return r.empty_search_result(
            body,
            index_scope,
            "invalid_response",
            duration_ms,
            timed_out=timed_out,
            shards=shards,
            error="Elasticsearch took value is missing or invalid",
        )
    if timed_out:
        return r.empty_search_result(
            body,
            index_scope,
            "timeout",
            duration_ms,
            timed_out=True,
            took_ms=took_ms,
            shards=shards,
            error="Elasticsearch reported a timed-out partial response",
        )
    if (
        shards["failed"]
        or shards["successful"] != shards["total"]
        or shards["skipped"] > shards["successful"]
    ):
        return r.empty_search_result(
            body,
            index_scope,
            "invalid_response" if not shards["failed"] else "error",
            duration_ms,
            took_ms=took_ms,
            shards=shards,
            error=(
                f"Elasticsearch returned {shards['failed']} failed shard(s)"
                if shards["failed"]
                else "Elasticsearch shard coverage is incomplete or inconsistent"
            ),
        )
    if shards["total"] == 0 or shards["successful"] == 0:
        return r.empty_search_result(
            body,
            index_scope,
            "invalid_response",
            duration_ms,
            took_ms=took_ms,
            shards=shards,
            error="Elasticsearch query matched no searchable shards in its reviewed index scope",
        )
    hits_root = parsed.get("hits")
    if not isinstance(hits_root, dict) or not isinstance(hits_root.get("hits"), list):
        return r.empty_search_result(
            body,
            index_scope,
            "invalid_response",
            duration_ms,
            took_ms=took_ms,
            shards=shards,
            error="Elasticsearch hits.hits must be an array",
        )
    raw_hits = hits_root["hits"]
    requested_size = body.get("size")
    if (
        isinstance(requested_size, bool)
        or not isinstance(requested_size, int)
        or requested_size < 0
        or len(raw_hits) > requested_size
    ):
        return r.empty_search_result(
            body,
            index_scope,
            "invalid_response",
            duration_ms,
            took_ms=took_ms,
            shards=shards,
            error="Elasticsearch returned more hits than the reviewed request size",
        )
    hits = []
    for hit in raw_hits:
        if not isinstance(hit, dict):
            return r.empty_search_result(
                body,
                index_scope,
                "invalid_response",
                duration_ms,
                took_ms=took_ms,
                shards=shards,
                error="Elasticsearch hit entries must be objects",
            )
        document_id = str(hit.get("_id") or "")
        index_name = str(hit.get("_index") or "")
        source = hit.get("_source")
        if (
            not document_id
            or not index_name
            or not isinstance(source, dict)
            or not r.index_matches_scope(index_name, index_scope)
        ):
            return r.empty_search_result(
                body,
                index_scope,
                "invalid_response",
                duration_ms,
                took_ms=took_ms,
                shards=shards,
                error=f"Elasticsearch returned an invalid or out-of-scope hit index: {index_name[:255]}",
            )
        hits.append({"id": document_id, "index": index_name, "source": source})
    total = hits_root.get("total")
    relation = "eq"
    if isinstance(total, dict):
        relation = total.get("relation")
        total = total.get("value")
    if (
        isinstance(total, bool)
        or not isinstance(total, int)
        or total < len(hits)
        or relation not in {"eq", "gte"}
    ):
        return r.empty_search_result(
            body,
            index_scope,
            "invalid_response",
            duration_ms,
            took_ms=took_ms,
            shards=shards,
            error="Elasticsearch hits.total metadata is invalid",
        )
    return {
        **audit,
        "status": "ok",
        "semantic_valid": True,
        "total_hits": total,
        "total_hits_relation": relation,
        "returned_hits": len(hits),
        "truncated": relation != "eq" or total > len(hits),
        "duration_ms": duration_ms,
        "timed_out": False,
        "took_ms": took_ms,
        "shards": shards,
        "hits": hits,
    }
