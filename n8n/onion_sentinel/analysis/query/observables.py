"""Bounded promotion of validated observables from query results."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Pattern, Sequence


TRUSTED_BACKENDS = frozenset({"security_onion", "pcap_zeek"})
PROMOTABLE_STATUSES = frozenset({"ok", "partial"})

IP_FIELDS = frozenset({
    "source.ip", "destination.ip", "client.ip", "server.ip",
    "host.ip", "dns.resolved_ip", "related.ip", "source.address",
    "src_ip", "dst_ip", "source_ip", "destination_ip",
})
DOMAIN_FIELDS = frozenset({
    "dns.question.name", "dns.query.name", "domain", "query",
    "dns_query", "query_name", "server_name", "sni",
    "tls.server.name", "ssl.server_name", "http.virtual_host",
    "quic.server_name",
})
HOST_FIELDS = frozenset({
    "host.name", "host.hostname", "host.id", "agent.id",
    "agent.name", "related.hosts", "hostname", "computer_name",
})
USER_FIELDS = frozenset({
    "user.name", "user.id", "related.user", "username", "user_name",
})


@dataclass(frozen=True)
class ValidationPolicy:
    safe_domain_pattern: Pattern[str]
    safe_atom_pattern: Pattern[str]
    maximum_queries_per_round: int
    maximum_mapping_children: int = 128
    maximum_list_children: int = 200
    maximum_rows: int = 200
    maximum_value_characters: int = 255


@dataclass(frozen=True)
class ValidationDependencies:
    text: Callable[[Any, int], str]
    evidence_ref_component: Callable[[Any, int], str]


@dataclass(frozen=True)
class Result:
    observables: tuple[dict[str, Any], ...]
    source_count: int
    promoted_count: int


def _field_kind(path: tuple[str, ...]) -> str:
    fields = {
        ".".join(path[-count:])
        for count in (1, 2, 3)
        if len(path) >= count
    }
    for kind, allowed in (
        ("ips", IP_FIELDS),
        ("domains", DOMAIN_FIELDS),
        ("hosts", HOST_FIELDS),
        ("users", USER_FIELDS),
    ):
        if fields.intersection(allowed):
            return kind
    return ""


def _normalized_value(
    value: Any,
    kind: str,
    policy: ValidationPolicy,
    dependencies: ValidationDependencies,
) -> str:
    text = dependencies.text(value, policy.maximum_value_characters).rstrip(".")
    if not kind or not text:
        return ""
    if kind == "ips":
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return ""
    if kind == "domains":
        return text.lower() if policy.safe_domain_pattern.fullmatch(text) else ""
    return text if policy.safe_atom_pattern.fullmatch(text) else ""


def _visit_values(
    item: Any,
    evidence_base: str,
    discovered: list[dict[str, str]],
    seen: set[tuple[str, str]],
    limit: int,
    policy: ValidationPolicy,
    dependencies: ValidationDependencies,
    path: tuple[str, ...] = (),
) -> None:
    if len(discovered) >= limit:
        return
    if isinstance(item, dict):
        for key, child in list(item.items())[:policy.maximum_mapping_children]:
            _visit_values(
                child, evidence_base, discovered, seen, limit, policy,
                dependencies, (*path, str(key).lower()),
            )
        return
    if isinstance(item, list):
        for child in item[:policy.maximum_list_children]:
            _visit_values(
                child, evidence_base, discovered, seen, limit, policy,
                dependencies, path,
            )
        return
    kind = _field_kind(path)
    value = _normalized_value(item, kind, policy, dependencies)
    key = (kind, value)
    if not value or key in seen:
        return
    seen.add(key)
    field_path = ".".join(path)
    discovered.append({
        "kind": kind,
        "value": value,
        "evidence_ref": (
            f"{evidence_base}#"
            f"{dependencies.evidence_ref_component(field_path, 72)}"
        )[:256],
    })


def _trusted_audits(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    trusted = result.get("trusted_query_audit")
    return {
        str(item.get("query_id")): item
        for item in trusted if isinstance(item, dict) and item.get("status") == "ok"
    } if isinstance(trusted, list) else {}


def _security_onion_query_rows(
    query_result: Any,
    response_digest: str,
    audits: dict[str, dict[str, Any]],
    policy: ValidationPolicy,
    dependencies: ValidationDependencies,
) -> list[tuple[Any, str]]:
    if not isinstance(query_result, dict) or query_result.get("status") != "ok":
        return []
    query_id = dependencies.text(query_result.get("query_id"), 128)
    audit = audits.get(query_id)
    query_digest = dependencies.text(
        audit.get("query_digest") if isinstance(audit, dict) else "", 64
    )
    hits = query_result.get("hits")
    if (
        not isinstance(audit, dict)
        or not re.fullmatch(r"[a-f0-9]{64}", query_digest)
        or query_result.get("query_digest") != query_digest
        or not isinstance(hits, list)
    ):
        return []
    rows: list[tuple[Any, str]] = []
    for index, hit in enumerate(hits[:policy.maximum_rows]):
        if not isinstance(hit, dict) or not isinstance(hit.get("source"), dict):
            continue
        base = (
            f"so:{response_digest[:20]}:"
            f"{dependencies.evidence_ref_component(query_id, 32)}:"
            f"{query_digest[:20]}:"
            f"{dependencies.evidence_ref_component(hit.get('index'), 32)}:"
            f"{dependencies.evidence_ref_component(hit.get('id'), 32)}:"
            f"hit-{index}"
        )
        rows.append((hit["source"], base))
    return rows


def _security_onion_rows(
    result: dict[str, Any],
    policy: ValidationPolicy,
    dependencies: ValidationDependencies,
) -> list[tuple[Any, str]]:
    evidence = result.get("evidence")
    if not isinstance(evidence, dict):
        return []
    response_digest = dependencies.text(
        result.get("security_onion_response_digest"), 64
    )
    evidence_results = evidence.get("results")
    if (
        not re.fullmatch(r"[a-f0-9]{64}", response_digest)
        or evidence.get("controls_valid") is not True
        or not isinstance(evidence_results, list)
    ):
        return []
    audits = _trusted_audits(result)
    rows: list[tuple[Any, str]] = []
    for query_result in evidence_results[:policy.maximum_queries_per_round]:
        rows.extend(_security_onion_query_rows(
            query_result, response_digest, audits, policy, dependencies
        ))
    return rows


def _pcap_zeek_rows(
    result: dict[str, Any],
    policy: ValidationPolicy,
    dependencies: ValidationDependencies,
) -> list[tuple[Any, str]]:
    evidence = result.get("evidence")
    if not isinstance(evidence, dict):
        return []
    records = evidence.get("records")
    query_id = dependencies.text(result.get("query_id"), 128)
    audit = _trusted_audits(result).get(query_id)
    query_digest = dependencies.text(evidence.get("query_digest"), 64)
    result_digest = dependencies.text(evidence.get("result_digest"), 64)
    source_ref = dependencies.text(evidence.get("evidence_ref"), 256)
    if (
        not isinstance(records, list)
        or not isinstance(audit, dict)
        or audit.get("query_digest") != query_digest
        or audit.get("result_digest") != result_digest
        or audit.get("evidence_ref") != source_ref
        or not re.fullmatch(r"[a-f0-9]{64}", query_digest)
        or not re.fullmatch(r"[a-f0-9]{64}", result_digest)
    ):
        return []
    rows: list[tuple[Any, str]] = []
    for index, record in enumerate(records[:policy.maximum_rows]):
        if not isinstance(record, dict):
            continue
        record_digest = hashlib.sha256(json.dumps(
            record, sort_keys=True, separators=(",", ":"), default=str,
        ).encode("utf-8")).hexdigest()
        base = (
            f"pcap:{dependencies.evidence_ref_component(source_ref, 32)}:"
            f"{dependencies.evidence_ref_component(query_id, 32)}:"
            f"{query_digest[:16]}:{result_digest[:16]}:"
            f"record-{index}-{record_digest[:16]}"
        )
        rows.append((record, base))
    return rows


def validate(
    results: Any,
    *,
    limit: int,
    policy: ValidationPolicy,
    dependencies: ValidationDependencies,
) -> list[dict[str, str]]:
    """Extract only provenance-bound observables from positive evidence rows."""
    discovered: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    if not isinstance(results, list):
        return discovered
    for result in results:
        if len(discovered) >= limit or not isinstance(result, dict):
            break
        backend = result.get("backend")
        status = result.get("status")
        if status != "ok" and not (backend == "security_onion" and status == "partial"):
            continue
        if backend == "security_onion":
            rows = _security_onion_rows(result, policy, dependencies)
        elif backend == "pcap_zeek":
            rows = _pcap_zeek_rows(result, policy, dependencies)
        else:
            continue
        for row, evidence_base in rows:
            _visit_values(
                row, evidence_base, discovered, seen, limit, policy, dependencies
            )
    return discovered


def _sources(results: Any) -> list[dict[str, Any]]:
    if not isinstance(results, list):
        return []
    return [
        item for item in results
        if isinstance(item, dict)
        and item.get("backend") in TRUSTED_BACKENDS
        and item.get("status") in PROMOTABLE_STATUSES
    ]


def promote(
    existing: Any,
    round_results: Any,
    *,
    limit: int,
    validate: Callable[..., Sequence[dict[str, Any]]],
) -> Result:
    """Return a deduplicated bounded observable set from trusted result rows."""
    bounded_limit = max(0, int(limit))
    retained = (
        copy.deepcopy(existing[:bounded_limit])
        if isinstance(existing, list)
        else []
    )
    sources = _sources(round_results)
    candidates = validate(sources, limit=max(0, bounded_limit - len(retained)))
    known = {
        (str(item.get("kind")), str(item.get("value")))
        for item in retained if isinstance(item, dict)
    }
    promoted = 0
    for item in candidates:
        key = (str(item.get("kind")), str(item.get("value")))
        if key in known or len(retained) >= bounded_limit:
            continue
        retained.append(copy.deepcopy(item))
        known.add(key)
        promoted += 1
    return Result(
        observables=tuple(retained),
        source_count=len(sources),
        promoted_count=promoted,
    )
