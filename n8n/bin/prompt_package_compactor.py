#!/usr/bin/env python3
"""Deterministically compact a prompt package to its admission budget."""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Callable


@dataclass(frozen=True)
class PackageCompactionSources:
    mandatory_grounding_digest: Callable[[dict], str]
    project_hits: Callable[..., int]
    project_osquery_rows: Callable[..., int]
    validate_incident_evidence: Callable[[dict], dict]


class _Serializer:
    def __init__(self, package: dict):
        self.package = package

    def serialize(self) -> str:
        budget = self.package["package_budget"]
        if budget["serialization"] == "compact":
            return json.dumps(
                self.package,
                separators=(",", ":"),
                sort_keys=True,
            )
        return json.dumps(self.package, indent=2, sort_keys=True)

    def stabilized(self) -> str:
        for _ in range(8):
            output = self.serialize()
            actual = len(output.encode("utf-8"))
            if self.package["package_budget"].get("serialized_bytes") == actual:
                return output
            self.package["package_budget"]["serialized_bytes"] = actual
        raise ValueError("prompt package byte-size metadata did not stabilize")


def _fits(output: str, max_bytes: int) -> bool:
    return len(output.encode("utf-8")) <= max_bytes


def _compact_supporting_context(package: dict, steps: list[str]) -> None:
    rollup = package.get("latest_daily_rollup")
    if isinstance(rollup, dict) and len(str(rollup.get("content") or "")) > 2000:
        rollup["content"] = str(rollup["content"])[:2000]
        rollup["truncated_for_package_budget"] = True
        steps.append("daily_rollup")
    _compact_history_lists(package, steps)
    _compact_grouped_timeline(package, steps)
    _compact_correlation_candidates(package, steps)


def _compact_history_lists(package: dict, steps: list[str]) -> None:
    for key, retain in (
        ("prior_analyses", 1),
        ("related_alerts", 5),
        ("recent_notifications", 5),
    ):
        value = package.get(key)
        if isinstance(value, list) and len(value) > retain:
            package[key] = value[:retain]
            steps.append(key)


def _compact_grouped_timeline(package: dict, steps: list[str]) -> None:
    grouped = package.get("grouped_alert_context")
    if isinstance(grouped, dict) and isinstance(grouped.get("timeline_sample"), list):
        grouped["timeline_sample"] = grouped["timeline_sample"][:8]
        grouped["timeline_sample_truncated_for_package_budget"] = True
        steps.append("grouped_alert_timeline")


def _compact_correlation_candidates(package: dict, steps: list[str]) -> None:
    correlation = package.get("correlated_alert_context")
    if isinstance(correlation, dict) and isinstance(correlation.get("candidates"), list):
        correlation["candidates"] = correlation["candidates"][:4]
        steps.append("correlation_candidates")


def _truncate_list(container: dict, key: str, retain: int) -> bool:
    value = container.get(key)
    if not isinstance(value, list) or len(value) <= retain:
        return False
    container[key] = value[:retain]
    container[f"{key}_truncated_for_package_budget"] = True
    return True


def _compact_asset_context(package: dict, steps: list[str]) -> None:
    context = package.get("asset_context")
    if not isinstance(context, dict):
        return
    for key, retain in (
        ("matched_assets", 64),
        ("registered_expectation_matches", 64),
        ("conflicts", 32),
        ("unmatched_observables", 128),
    ):
        _truncate_list(context, key, retain)
    for asset in context.get("matched_assets", []):
        if not isinstance(asset, dict):
            continue
        for key, retain in (
            ("expected_services", 16),
            ("expected_behaviors", 16),
            ("matched_observables", 32),
        ):
            _truncate_list(asset, key, retain)
    steps.append("asset_context")


def _compact_enrichment(package: dict, steps: list[str]) -> None:
    enrichment = package.get("public_enrichment")
    if not isinstance(enrichment, dict):
        return
    for key, retain in (("records", 10), ("skipped", 5), ("errors", 5)):
        if isinstance(enrichment.get(key), list):
            enrichment[key] = enrichment[key][:retain]
    steps.append("public_enrichment")


def _compact_ac_hunter(package: dict, steps: list[str]) -> None:
    context = package.get("ac_hunter_evidence")
    if not isinstance(context, dict):
        return
    changed = False
    for key, retain in (
        ("findings", 12),
        ("correlated_hosts", 8),
        ("analyst_notes", 6),
    ):
        changed = _truncate_list(context, key, retain) or changed
    if changed:
        context["status"] = "partial"
        context["complete"] = False
        context["truncated"] = True
        context["negative_evidence_allowed"] = False
        steps.append("ac_hunter_evidence")


def _pcap_relationship_counts(pcap: dict) -> None:
    evidence_rows = pcap["parsed_evidence"]
    pcap["exact_alert_evidence_count"] = sum(
        1
        for item in evidence_rows
        if isinstance(item, dict)
        and item.get("evidence_relationship") == "exact_alert"
    )
    pcap["stable_group_related_evidence_count"] = sum(
        1
        for item in evidence_rows
        if isinstance(item, dict)
        and item.get("evidence_relationship") == "stable_group_related"
    )


def _compact_tshark(evidence: dict) -> None:
    tshark = evidence.get("tshark")
    if isinstance(tshark, dict) and isinstance(tshark.get("samples"), list):
        tshark["samples"] = tshark["samples"][:1]
        for sample in tshark["samples"]:
            if not isinstance(sample, dict):
                continue
            for key in ("protocol_hierarchy", "conversations", "field_sample_tsv"):
                sample[key] = str(sample.get(key) or "")[:1200]
    if isinstance(tshark, dict) and isinstance(tshark.get("packet_samples"), list):
        tshark["packet_samples"] = tshark["packet_samples"][:8]


def _compact_local_query_index(evidence: dict) -> None:
    local_index = evidence.get("_local_query_index")
    if not isinstance(local_index, dict):
        return
    for operation, values in local_index.items():
        if isinstance(values, list):
            local_index[operation] = values[:8]


def _compact_pcap(package: dict, steps: list[str]) -> None:
    pcap = package.get("pcap_evidence")
    if not isinstance(pcap, dict):
        return
    if isinstance(pcap.get("pcap_requests"), list):
        pcap["pcap_requests"] = pcap["pcap_requests"][:3]
    evidence_rows = pcap.get("parsed_evidence")
    if isinstance(evidence_rows, list):
        evidence_rows.sort(
            key=lambda item: (
                0
                if isinstance(item, dict)
                and item.get("evidence_relationship") == "exact_alert"
                else 1
            )
        )
        original_count = len(evidence_rows)
        pcap["parsed_evidence"] = evidence_rows[:1]
        if original_count > len(pcap["parsed_evidence"]):
            pcap["parsed_evidence_truncated_for_package_budget"] = True
        _pcap_relationship_counts(pcap)
        for evidence in pcap["parsed_evidence"]:
            if isinstance(evidence, dict):
                _compact_tshark(evidence)
                _compact_local_query_index(evidence)
    steps.append("pcap_evidence")


def _compact_memory(package: dict, steps: list[str]) -> None:
    memory = package.get("agent_memory")
    if not isinstance(memory, dict):
        return
    for key in ("role_memory", "shared_memory"):
        value = memory.get(key)
        if isinstance(value, str) and len(value) > 2500:
            memory[key] = value[:2500] + "\n[truncated for prompt package budget]"
    steps.append("agent_memory")


def _initial_lossy_compaction(package, incident, steps, sources) -> None:
    _compact_supporting_context(package, steps)
    _compact_asset_context(package, steps)
    _compact_enrichment(package, steps)
    _compact_ac_hunter(package, steps)
    _compact_pcap(package, steps)
    if isinstance(incident, dict) and sources.project_hits(
        incident,
        limit=5,
        reason="package_budget_compaction",
    ):
        sources.validate_incident_evidence(incident)
        steps.append("incident_response_hit_samples")
    _compact_memory(package, steps)


def _apply_incident_projection(
    incident: dict,
    steps: list[str],
    sources: PackageCompactionSources,
    *,
    rows: bool,
    limit: int,
    reason: str,
) -> bool:
    if rows:
        changed = sources.project_osquery_rows(
            incident,
            limit=limit,
            max_retained_bytes=16 * 1024 if limit else 2,
            max_row_bytes=4 * 1024 if limit else 0,
            reason=reason,
        )
    else:
        changed = sources.project_hits(incident, limit=limit, reason=reason)
    if changed:
        sources.validate_incident_evidence(incident)
        steps.append(reason)
    return bool(changed)


def _progressive_incident_compaction(
    serializer: _Serializer,
    incident: dict,
    steps: list[str],
    sources: PackageCompactionSources,
    max_bytes: int,
) -> str:
    stages = (
        (True, 10, "package_budget_compaction", "incident_response_osquery_row_samples"),
        (False, 1, "package_budget_minimal_hit_sample", "incident_response_minimal_hit_samples"),
        (True, 0, "package_budget_row_omission", "incident_response_osquery_rows"),
        (False, 0, "package_budget_hit_omission", "incident_response_hits"),
    )
    output = serializer.stabilized()
    for rows, limit, reason, step_name in stages:
        if _fits(output, max_bytes):
            break
        previous_count = len(steps)
        _apply_incident_projection(
            incident,
            steps,
            sources,
            rows=rows,
            limit=limit,
            reason=reason,
        )
        if len(steps) > previous_count:
            steps[-1] = step_name
            output = serializer.stabilized()
    return output


def compact_package_to_budget(
    sources: PackageCompactionSources,
    package: dict,
    max_bytes: int,
) -> tuple[dict, str]:
    """Apply ordered lossless and lossy reductions, preserving grounding."""
    package["package_budget"] = {
        "max_bytes": max_bytes,
        "compacted": False,
        "compaction_steps": [],
        "serialization": "pretty",
    }
    serializer = _Serializer(package)
    output = serializer.stabilized()
    if _fits(output, max_bytes):
        return package, output
    budget = package["package_budget"]
    budget["compacted"] = True
    budget["serialization"] = "compact"
    steps = budget["compaction_steps"]
    steps.append("json_whitespace")
    output = serializer.stabilized()
    if _fits(output, max_bytes):
        return package, output
    incident = package.get("incident_response_evidence")
    grounding = None
    if isinstance(incident, dict):
        grounding = sources.mandatory_grounding_digest(package)
        budget["mandatory_grounding_sha256"] = grounding
        budget["mandatory_grounding_preserved"] = True
    _initial_lossy_compaction(package, incident, steps, sources)
    output = serializer.stabilized()
    if not _fits(output, max_bytes) and isinstance(incident, dict):
        output = _progressive_incident_compaction(
            serializer, incident, steps, sources, max_bytes
        )
    if grounding is not None and sources.mandatory_grounding_digest(package) != grounding:
        raise ValueError("mandatory incident prompt grounding changed during compaction")
    if not _fits(output, max_bytes):
        raise ValueError(
            f"prompt package remains above {max_bytes} bytes after deterministic compaction"
        )
    return package, output
