#!/usr/bin/env python3
"""Terminal cohort projection and digest-sealed private export workflow."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class CohortExportSources:
    cohort_error: type[RuntimeError]
    export_schema: str
    monitor_cohort_once: Callable[[Path, Path], tuple[dict[str, Any], bool]]
    harness_execution_proof: Callable[..., dict[str, Any]]
    member_stable_group_key: Callable[[Mapping[str, Any]], str]
    utc_now: Callable[[], str]
    sha256_value: Callable[[Any], str]
    ordered_identity_projection: Callable[[list[dict[str, Any]]], Any]
    write_private_json: Callable[..., dict[str, Any]]


def _require_completed_manifest(
    sources: CohortExportSources,
    manifest: Mapping[str, Any],
    terminal: bool,
) -> None:
    if not terminal:
        raise sources.cohort_error(
            "cohort is not terminal; refusing a partial export"
        )
    noncompleted = [
        int(member.get("rank") or 0)
        for member in manifest["members"]
        if str((member.get("monitor") or {}).get("state") or "")
        != "completed"
    ]
    if noncompleted:
        raise sources.cohort_error(
            "cohort contains non-completed results; refusing a gradeable "
            f"export (ranks={noncompleted})"
        )


def _execution_proof(
    sources: CohortExportSources,
    harness_database_path: Path | None,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    monitor: Mapping[str, Any],
) -> dict[str, Any]:
    if harness_database_path is None:
        return {
            "status": "not_attested",
            "reason": "harness database was not supplied",
        }
    return sources.harness_execution_proof(
        harness_database_path=harness_database_path,
        manifest=manifest,
        member=member,
        monitor=monitor,
    )


def _member_projection(
    sources: CohortExportSources,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    harness_database_path: Path | None,
) -> dict[str, Any]:
    monitor = member.get("monitor") or {}
    return {
        "rank": member["rank"],
        "dashboard_group_id": member["dashboard_group_id"],
        "stable_group_id": member["stable_group_id"],
        "stable_group_key": sources.member_stable_group_key(member),
        "representative_alert_id": member["representative_alert_id"],
        "detection": member["detection"],
        "pre_state": member["pre_state"],
        "dispatch": member["dispatch"],
        "result": monitor,
        "execution_proof": _execution_proof(
            sources,
            harness_database_path,
            manifest,
            member,
            monitor,
        ),
    }


def _gate(
    sources: CohortExportSources,
    manifest: Mapping[str, Any],
    members: list[dict[str, Any]],
    harness_database_path: Path | None,
) -> dict[str, Any]:
    passed_count = sum(
        (member.get("execution_proof") or {}).get("status") == "passed"
        for member in members
    )
    gate_passed = (
        harness_database_path is not None
        and len(members) == int(manifest["count"])
        and passed_count == len(members)
    )
    return {
        "status": "passed" if gate_passed else "not_attested",
        "expected_count": int(manifest["count"]),
        "passed_count": passed_count,
        "ordered_identity_sha256": sources.sha256_value(
            sources.ordered_identity_projection(members)
        ),
        "contract_sha256": sources.sha256_value(
            manifest["execution_contract"]
        ),
    }


def _export_document(
    sources: CohortExportSources,
    manifest: Mapping[str, Any],
    members: list[dict[str, Any]],
    harness_database_path: Path | None,
) -> dict[str, Any]:
    selection = manifest.get("selection")
    selection = dict(selection) if isinstance(selection, dict) else {}
    return {
        "schema": sources.export_schema,
        "cohort_id": manifest["cohort_id"],
        "reason": manifest["reason"],
        "agent_role": manifest.get("agent_role") or "incident-responder",
        "count": manifest["count"],
        "frozen_at": manifest["created_at"],
        "exported_at": sources.utc_now(),
        "source_manifest_sha256": manifest["manifest_sha256"],
        "frozen_plan_sha256": manifest["frozen_plan_sha256"],
        "selection": selection,
        "execution_contract": manifest["execution_contract"],
        "execution_gate": _gate(
            sources, manifest, members, harness_database_path
        ),
        "security_onion_access": "none",
        "content_policy": {
            "contains_raw_alerts": False,
            "contains_prompts": False,
            "contains_raw_model_responses": False,
            "contains_query_text": False,
            "contains_query_results": False,
            "contains_credentials": False,
        },
        "members": members,
    }


def export_cohort(
    sources: CohortExportSources,
    database_path: Path,
    manifest_path: Path,
    output_path: Path,
    *,
    harness_database_path: Path | None = None,
) -> dict[str, Any]:
    manifest, terminal = sources.monitor_cohort_once(
        database_path, manifest_path
    )
    _require_completed_manifest(sources, manifest, terminal)
    members = [
        _member_projection(sources, manifest, member, harness_database_path)
        for member in manifest["members"]
    ]
    document = _export_document(
        sources, manifest, members, harness_database_path
    )
    return sources.write_private_json(
        output_path,
        document,
        digest_field="export_sha256",
        replace=False,
    )
