"""Bounded evidence catalogs for blind independent review."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Pattern


COMMON_SECTIONS = (
    "alert", "grouped_alert_context", "correlated_alert_context",
    "pcap_evidence", "detection_validation", "incident_response_evidence",
    "investigation_query_results", "live_osquery_evidence",
)
OBSERVABLE_SECTIONS = (
    "alert", "grouped_alert_context", "correlated_alert_context",
    "public_enrichment", "pcap_evidence", "detection_validation",
    "asset_context", "analyst_state", "incident_response_evidence",
    "investigation_query_capability", "investigation_query_results",
    "live_osquery_evidence",
)
RULE_SECTIONS = (
    "alert", "grouped_alert_context", "correlated_alert_context",
    "detection_validation", "incident_response_evidence",
    "investigation_query_results",
)
IP_FIELDS = frozenset({
    "source_ip", "destination_ip", "src_ip", "dest_ip", "client_ip",
    "server_ip", "ip", "address",
})
DOMAIN_FIELDS = frozenset({
    "domain", "domain_name", "dns_query", "sni", "server_name",
})
HOST_FIELDS = frozenset({"host", "hostname", "host_name", "observer_name"})
USER_FIELDS = frozenset({"user", "username", "user_name"})


@dataclass(frozen=True)
class Policy:
    observable_max: int
    observable_kinds: frozenset[str]
    ipv4_pattern: Pattern[str]
    domain_pattern: Pattern[str]
    taxonomy_field_paths: frozenset[str]
    artifact_field_paths: frozenset[str]
    artifact_suffixes: frozenset[str]
    rule_label_field_paths: frozenset[str]
    list_limit: int = 1000
    rule_token_limit: int = 32


@dataclass(frozen=True)
class Dependencies:
    bounded_reference: Callable[[Any], str]
    reviewer_safe_copy: Callable[[dict[str, Any]], Any]


def _field_segment(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _is_typed(path: tuple[str, ...], fields: frozenset[str]) -> bool:
    return bool(path) and (path[-1] in fields or "_".join(path[-2:]) in fields)


def _walk_typed(
    value: Any,
    path: tuple[str, ...],
    fields: frozenset[str],
    scalar_types: tuple[type, ...],
    add: Callable[[Any], None],
    list_limit: int,
) -> None:
    if isinstance(value, dict):
        for raw_key, child in value.items():
            segment = _field_segment(raw_key)
            child_path = path + ((segment,) if segment else ())
            if isinstance(child, scalar_types) and _is_typed(child_path, fields):
                add(child)
            else:
                _walk_typed(child, child_path, fields, scalar_types, add, list_limit)
    elif isinstance(value, list):
        for child in value[:list_limit]:
            _walk_typed(child, path, fields, scalar_types, add, list_limit)


def _collect_typed(
    prompt_package: dict[str, Any],
    sections: tuple[str, ...],
    fields: frozenset[str],
    scalar_types: tuple[type, ...],
    add: Callable[[Any], None],
    list_limit: int,
) -> None:
    for section in sections:
        _walk_typed(prompt_package.get(section), (), fields, scalar_types, add, list_limit)


class _ObservableCollector:
    def __init__(self, policy: Policy, dependencies: Dependencies) -> None:
        self.policy = policy
        self.dependencies = dependencies
        self.found: set[tuple[str, str]] = set()

    def add(self, kind: str, value: Any) -> None:
        text = self.dependencies.bounded_reference(value)
        if kind not in self.policy.observable_kinds or not text:
            return
        if len(self.found) >= self.policy.observable_max:
            return
        canonical = text.lower() if kind in {"domain", "host", "user"} else text
        self.found.add((kind, canonical))

    def add_local_context(self, prompt_package: dict[str, Any]) -> None:
        local = prompt_package.get("_local_investigation_query_context")
        if not isinstance(local, dict):
            return
        self._add_permitted(local.get("permitted_observables"))
        tuples = local.get("permitted_event_tuples")
        for item in tuples if isinstance(tuples, list) else []:
            event = item.get("event_tuple") if isinstance(item, dict) else None
            if isinstance(event, dict):
                self._add_event_tuple(event)

    def _add_permitted(self, permitted: Any) -> None:
        if not isinstance(permitted, dict):
            return
        for plural, kind in (("ips", "ip"), ("domains", "domain"),
                             ("hosts", "host"), ("users", "user")):
            values = permitted.get(plural)
            for value in values if isinstance(values, list) else []:
                self.add(kind, value)

    def _add_event_tuple(self, event: dict[str, Any]) -> None:
        for key, kind in (("source_ip", "ip"), ("destination_ip", "ip"),
                          ("community_id", "community_id")):
            self.add(kind, event.get(key))

    def visit(self, value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                self.visit(child, str(child_key).lower().replace("-", "_"))
        elif isinstance(value, list):
            for child in value[:self.policy.list_limit]:
                self.visit(child, key)
        elif isinstance(value, (str, int)):
            self._add_scalar(key, str(value).strip())

    def _add_scalar(self, key: str, text: str) -> None:
        if key in IP_FIELDS:
            for match in self.policy.ipv4_pattern.findall(text):
                self.add("ip", match)
        elif key in DOMAIN_FIELDS:
            self.add("domain", text)
        elif key in HOST_FIELDS:
            self.add("host", text)
        elif key in USER_FIELDS:
            self.add("user", text)
        elif key == "community_id":
            self.add("community_id", text)


def observables(
    prompt_package: dict[str, Any], policy: Policy, dependencies: Dependencies,
) -> list[dict[str, str]]:
    """Return exact, bounded observables the reviewer may mention."""
    collector = _ObservableCollector(policy, dependencies)
    collector.add_local_context(prompt_package)
    for section in OBSERVABLE_SECTIONS:
        collector.visit(prompt_package.get(section))
    serialized = json.dumps(
        dependencies.reviewer_safe_copy(prompt_package), sort_keys=True, default=str,
    )
    for match in policy.ipv4_pattern.findall(serialized):
        collector.add("ip", match)
    return [
        {"kind": kind, "value": value}
        for kind, value in sorted(collector.found)
    ]


def taxonomy(
    prompt_package: dict[str, Any], policy: Policy, dependencies: Dependencies,
) -> list[str]:
    """Return dotted taxonomy labels only from collector-owned typed fields."""
    found: set[str] = set()

    def add(value: Any) -> None:
        text = dependencies.bounded_reference(value).lower()
        if text and policy.domain_pattern.fullmatch(text):
            found.add(text)

    _collect_typed(prompt_package, COMMON_SECTIONS, policy.taxonomy_field_paths,
                   (str, int), add, policy.list_limit)
    return sorted(found)


def artifacts(
    prompt_package: dict[str, Any], policy: Policy, dependencies: Dependencies,
) -> list[str]:
    """Return script-like names only from collector-owned command/path fields."""
    del dependencies
    found: set[str] = set()

    def add(value: Any) -> None:
        for candidate in policy.domain_pattern.findall(str(value or "")):
            text = candidate.lower()
            if text.rsplit(".", 1)[-1] in policy.artifact_suffixes:
                found.add(text)

    _collect_typed(prompt_package, COMMON_SECTIONS, policy.artifact_field_paths,
                   (str,), add, policy.list_limit)
    return sorted(found)


def rule_shorthands(
    prompt_package: dict[str, Any], policy: Policy, dependencies: Dependencies,
) -> list[str]:
    """Return detector shorthands derived from typed rule labels."""
    found: set[str] = set()

    def add(value: Any) -> None:
        raw = dependencies.bounded_reference(value)
        tokens = re.findall(r"[A-Za-z0-9][A-Za-z0-9_-]{1,62}", raw)
        if len(tokens) < 2 or not re.fullmatch(r"[A-Z0-9]{2,8}", tokens[0]):
            return
        namespace, raw_lower = tokens[0].lower(), raw.lower()
        for token in tokens[1:policy.rule_token_limit]:
            candidate = f"{namespace}.{token.lower()}"
            if candidate not in raw_lower and policy.domain_pattern.fullmatch(candidate):
                found.add(candidate)

    _collect_typed(prompt_package, RULE_SECTIONS, policy.rule_label_field_paths,
                   (str,), add, policy.list_limit)
    return sorted(found)
