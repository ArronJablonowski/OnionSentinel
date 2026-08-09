"""Authorization, evidence binding, and custody for live endpoint OSQuery."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Callable, Type


@dataclass(frozen=True)
class Policy:
    schema: str
    support_schema: str
    maximum_rounds: int
    maximum_queries: int
    maximum_support_bindings: int = 16


@dataclass(frozen=True)
class Dependencies:
    text: Callable[[Any, int], str]
    normalize_query: Callable[[Any], str]
    now: Callable[[], str]
    client_error: Type[Exception]


COLUMN_KINDS = {
    "remote_address": "ips", "local_address": "ips", "address": "ips",
    "source_ip": "ips", "destination_ip": "ips", "remote_port": "ports",
    "local_port": "ports", "port": "ports", "hostname": "hosts",
    "host": "hosts", "domain": "domains", "query": "domains",
    "username": "users", "user": "users",
}
TABLE_KINDS = {
    "process_open_sockets": frozenset({"ips", "ports"}),
    "listening_ports": frozenset({"ips", "ports"}),
    "logged_in_users": frozenset({"users"}),
    "users": frozenset({"users"}),
}


def _empty_observables() -> dict[str, set[str]]:
    return {
        "ips": set(), "hosts": set(), "domains": set(), "users": set(),
        "ports": set(),
    }


def _add_permitted_observables(
    values: dict[str, set[str]],
    permitted: Any,
) -> None:
    if not isinstance(permitted, dict):
        return
    for key in ("ips", "hosts", "domains", "users"):
        items = permitted.get(key)
        for raw in items if isinstance(items, list) else []:
            text = str(raw or "").strip().rstrip(".")
            if not text:
                continue
            if key == "ips":
                try:
                    text = str(ipaddress.ip_address(text))
                except ValueError:
                    continue
            else:
                text = text.lower()
            values[key].add(text)


def _add_event_tuple(values: dict[str, set[str]], entry: Any) -> None:
    event = entry.get("event_tuple") if isinstance(entry, dict) else None
    if not isinstance(event, dict):
        return
    for field in ("source_ip", "destination_ip"):
        try:
            values["ips"].add(
                str(ipaddress.ip_address(str(event.get(field)).strip()))
            )
        except ValueError:
            pass
    for field in ("source_port", "destination_port"):
        raw = event.get(field)
        if isinstance(raw, bool) or raw in (None, ""):
            continue
        try:
            port = int(raw)
        except (TypeError, ValueError):
            continue
        if 0 <= port <= 65535:
            values["ports"].add(str(port))


def authorized_observables(
    prompt_package: dict[str, Any],
) -> dict[str, set[str]]:
    """Return collector-owned observables authorized for this case."""
    values = _empty_observables()
    local = prompt_package.get("_local_investigation_query_context")
    if not isinstance(local, dict):
        return values
    _add_permitted_observables(values, local.get("permitted_observables"))
    tuples = local.get("permitted_event_tuples")
    for entry in tuples if isinstance(tuples, list) else []:
        _add_event_tuple(values, entry)
    return values


def target_bound(
    prompt_package: dict[str, Any],
    target_alias: Any,
    config: dict[str, Any],
    *,
    dependencies: Dependencies,
) -> bool:
    """Require one opaque target alias to match the trusted case asset."""
    alias = dependencies.text(target_alias, 64).lower()
    bindings = config.get("target_bindings")
    binding = bindings.get(alias) if isinstance(bindings, dict) else None
    if not isinstance(binding, dict):
        return False
    observables = authorized_observables(prompt_package)
    bound_ips = {
        str(item).strip() for item in binding.get("ips", []) if str(item).strip()
    }
    bound_hosts = {
        str(item).strip().lower().rstrip(".")
        for item in binding.get("hosts", []) if str(item).strip()
    }
    return bool(
        bound_ips.intersection(observables["ips"])
        or bound_hosts.intersection(observables["hosts"])
    )


def _result_table(result: dict[str, Any]) -> str:
    match = re.search(
        r"\bfrom\s+([A-Za-z_][A-Za-z0-9_]*)",
        str(result.get("query") or ""),
        re.IGNORECASE,
    )
    return match.group(1).lower() if match else ""


def _binding_for_value(
    result: dict[str, Any],
    table: str,
    row_index: int,
    raw_column: Any,
    raw_value: Any,
    observables: dict[str, set[str]],
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any] | None:
    column = str(raw_column or "").strip().lower()
    kind = COLUMN_KINDS.get(column)
    if kind not in TABLE_KINDS.get(table, frozenset()):
        return None
    value = str(raw_value or "").strip().rstrip(".")
    if kind in {"hosts", "domains", "users"}:
        value = value.lower()
    if value not in observables[kind]:
        return None
    return {
        "schema": policy.support_schema,
        "target_alias": dependencies.text(result.get("target_alias"), 64),
        "query_digest": dependencies.text(result.get("query_digest"), 64),
        "table": table,
        "row_index": row_index,
        "column": column,
        "observable_kind": kind[:-1],
        "observable_digest": hashlib.sha256(
            f"{kind}\0{value}".encode("utf-8")
        ).hexdigest(),
        "source": "trusted-investigation-context",
        "temporal_scope": "collection_snapshot",
    }


def support_bindings(
    prompt_package: dict[str, Any],
    result: dict[str, Any],
    config: dict[str, Any],
    *,
    policy: Policy,
    dependencies: Dependencies,
) -> list[dict[str, Any]]:
    """Bind positive result cells to authorized observables without copying them."""
    if not target_bound(
        prompt_package, result.get("target_alias"), config,
        dependencies=dependencies,
    ):
        return []
    table = _result_table(result)
    if table not in TABLE_KINDS:
        return []
    observables = authorized_observables(prompt_package)
    bindings: list[dict[str, Any]] = []
    rows = result.get("rows")
    for row_index, row in enumerate(rows if isinstance(rows, list) else []):
        if not isinstance(row, dict):
            continue
        for column, value in row.items():
            binding = _binding_for_value(
                result, table, row_index, column, value, observables, policy,
                dependencies,
            )
            if binding is not None:
                bindings.append(binding)
            if len(bindings) >= policy.maximum_support_bindings:
                return bindings
    return bindings


def _new_accumulator(case_id: str, policy: Policy) -> dict[str, Any]:
    return {
        "schema": policy.schema,
        "case_id": case_id,
        "generated_at": "",
        "read_only": True,
        "control_plane_writes": False,
        "control_plane_write_status": "none",
        "complete": True,
        "partial": False,
        "collection_error": "",
        "batches": [],
        "results": [],
    }


def _validated_accumulator(
    prompt_package: dict[str, Any],
    case_id: str,
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any]:
    key = "_live_osquery_evidence_accumulator"
    current = prompt_package.get(key)
    if current is None:
        current = _new_accumulator(case_id, policy)
        prompt_package[key] = current
    if (
        not isinstance(current, dict)
        or current.get("schema") != policy.schema
        or current.get("case_id") != case_id
        or current.get("read_only") is not True
        or not isinstance(current.get("batches"), list)
        or not isinstance(current.get("results"), list)
    ):
        raise dependencies.client_error(
            "existing live OSQuery evidence accumulator is invalid"
        )
    if len(current["batches"]) >= policy.maximum_rounds:
        raise dependencies.client_error(
            "live OSQuery evidence accumulator exceeded the round limit"
        )
    return current


def _update_cumulative_state(
    current: dict[str, Any],
    status: str,
    dependencies: Dependencies,
) -> None:
    ranks = {"none": 0, "possible": 1, "confirmed": 2}
    if status not in ranks:
        raise dependencies.client_error(
            "invalid live OSQuery control-plane write status"
        )
    existing = str(current.get("control_plane_write_status") or "none")
    if ranks[status] > ranks.get(existing, 0):
        current["control_plane_write_status"] = status
    current["control_plane_writes"] = (
        current.get("control_plane_write_status") != "none"
    )
    current["complete"] = all(
        item.get("complete") is True and item.get("validated") is True
        for item in current["batches"] if isinstance(item, dict)
    )
    current["partial"] = not current["complete"]
    errors = [
        dependencies.text(item.get("collection_error"), 1000)
        for item in current["batches"]
        if isinstance(item, dict) and item.get("collection_error")
    ]
    current["collection_error"] = "; ".join(errors)[-2000:]


def append_batch(
    prompt_package: dict[str, Any],
    *,
    case_id: str,
    generated_at: str,
    results: list[dict[str, Any]],
    complete: bool,
    partial: bool,
    validated: bool,
    control_plane_write_status: str,
    collection_error: str,
    policy: Policy,
    dependencies: Dependencies,
) -> None:
    """Append one bounded runtime-owned collection attempt."""
    current = _validated_accumulator(
        prompt_package, case_id, policy, dependencies
    )
    batch_results = copy.deepcopy(results)
    if len(current["results"]) + len(batch_results) > policy.maximum_queries:
        raise dependencies.client_error(
            "live OSQuery evidence accumulator exceeded the query limit"
        )
    result_start = len(current["results"])
    current["results"].extend(batch_results)
    current["batches"].append({
        "batch": len(current["batches"]) + 1,
        "generated_at": dependencies.text(generated_at, 100),
        "complete": complete is True,
        "partial": partial is True,
        "validated": validated is True,
        "collection_error": dependencies.text(collection_error, 1000),
        "result_start": result_start,
        "result_count": len(batch_results),
    })
    current["generated_at"] = dependencies.text(generated_at, 100)
    _update_cumulative_state(current, control_plane_write_status, dependencies)


def accumulate_evidence(
    prompt_package: dict[str, Any],
    evidence: dict[str, Any],
    *,
    policy: Policy,
    dependencies: Dependencies,
) -> None:
    """Retain one collector-validated evidence batch for final audit."""
    if (
        evidence.get("schema") != policy.schema
        or evidence.get("read_only") is not True
        or not isinstance(evidence.get("results"), list)
    ):
        raise dependencies.client_error(
            "live OSQuery evidence accumulator received an invalid artifact"
        )
    case_id = dependencies.text(evidence.get("case_id"), 160)
    if not case_id:
        raise dependencies.client_error(
            "live OSQuery evidence accumulator received no case identity"
        )
    append_batch(
        prompt_package,
        case_id=case_id,
        generated_at=dependencies.text(evidence.get("generated_at"), 100),
        results=evidence["results"],
        complete=evidence.get("complete") is True,
        partial=evidence.get("partial") is True,
        validated=True,
        control_plane_write_status="confirmed",
        collection_error="",
        policy=policy,
        dependencies=dependencies,
    )


def accumulate_failure(
    prompt_package: dict[str, Any],
    *,
    case_id: str,
    requests: list[dict[str, Any]],
    error: str,
    dispatch_possible: bool,
    policy: Policy,
    dependencies: Dependencies,
) -> None:
    """Record a failed collection attempt with exact normalized query digests."""
    failure_results: list[dict[str, Any]] = []
    for request in requests:
        query = dependencies.normalize_query(request.get("query"))
        failure_results.append({
            "target_alias": dependencies.text(request.get("target_alias"), 64),
            "query": query,
            "purpose": dependencies.text(request.get("purpose"), 500),
            "query_digest": hashlib.sha256(query.encode("utf-8")).hexdigest(),
            "status": "error",
            "rows": [],
            "total_rows": 0,
            "truncated": False,
            "duration_ms": 0,
            "error": dependencies.text(error, 1000),
        })
    append_batch(
        prompt_package,
        case_id=case_id,
        generated_at=dependencies.now(),
        results=failure_results,
        complete=False,
        partial=True,
        validated=False,
        control_plane_write_status="possible" if dispatch_possible else "none",
        collection_error=error,
        policy=policy,
        dependencies=dependencies,
    )
