#!/usr/bin/env python3
"""Fail-closed cohort selection and frozen-manifest workflows."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Pattern


@dataclass(frozen=True)
class CohortFreezePolicy:
    schema: str
    maximum_cohort_size: int
    dashboard_group_id_pattern: Pattern[str]
    stable_group_id_pattern: Pattern[str]
    representative_alert_id_pattern: Pattern[str]


@dataclass(frozen=True)
class CohortFreezeSources:
    error_type: type[RuntimeError]
    validate_cohort_identity: Callable[[str, str], tuple[str, str]]
    validate_release_id: Callable[[str], str]
    validate_agent_role: Callable[[str], str]
    connect_read_only: Callable[[Path], Any]
    load_aliases: Callable[[Any], Mapping[str, str]]
    incident_cases: Callable[[Any, Mapping[str, str]], Mapping[str, list[dict]]]
    summary_rows: Callable[[Any], list[dict[str, Any]]]
    resolve_alias: Callable[[str, Mapping[str, str]], str]
    bind_representative_stable_group_key: Callable[[Any, str, dict], dict]
    validate_stable_group_key: Callable[[Any, str], str]
    validate_representative_binding: Callable[[Any, Mapping[str, Any], str], None]
    incident_pre_state: Callable[[Any, str, Mapping[str, str], Mapping[str, list[dict]]], dict]
    soc_pre_state: Callable[[Any, str, Mapping[str, str]], dict]
    source_identity: Callable[[Mapping[str, Any]], tuple[str, str, str]]
    source_detection_projection: Callable[[Mapping[str, Any]], dict[str, Any]]
    validate_source_detection: Callable[[Mapping[str, Any], Mapping[str, Any], str], dict[str, Any]]
    validate_source_pre_state: Callable[[Mapping[str, Any], Mapping[str, Any], str], None]
    ordered_identity_projection: Callable[[list[dict]], list[dict]]
    utc_now: Callable[[], str]
    sha256_value: Callable[[Any], str]
    execution_contract: Callable[..., dict[str, Any]]
    schema_fingerprint: Callable[[Any], str]
    frozen_plan_digest: Callable[[Mapping[str, Any]], str]
    digest_bound: Callable[[Mapping[str, Any], str], dict[str, Any]]
    write_private_json: Callable[..., dict[str, Any]]
    load_private_source_rows: Callable[[Path], tuple[list[dict], str]]


def _validate_freeze_request(
    policy: CohortFreezePolicy,
    sources: CohortFreezeSources,
    manifest_path: Path,
    cohort_id: str,
    reason: str,
    count: int,
    release_id: str,
    dry_run: bool,
) -> tuple[str, str, str]:
    cohort_id, reason = sources.validate_cohort_identity(cohort_id, reason)
    release_id = sources.validate_release_id(release_id)
    if count < 1 or count > policy.maximum_cohort_size:
        raise sources.error_type(
            f"cohort size must be between 1 and {policy.maximum_cohort_size}"
        )
    if manifest_path.expanduser().exists() and not dry_run:
        raise sources.error_type(f"manifest already exists: {manifest_path.expanduser()}")
    return cohort_id, reason, release_id


def _stable_summary_identity(
    summary: Mapping[str, Any],
    aliases: Mapping[str, str],
    policy: CohortFreezePolicy,
    sources: CohortFreezeSources,
) -> tuple[str, str, str]:
    dashboard_id = str(summary.get("group_id") or "").strip().lower()
    if not policy.dashboard_group_id_pattern.fullmatch(dashboard_id):
        raise sources.error_type(
            f"invalid dashboard group identity in summary: {dashboard_id!r}"
        )
    if dashboard_id not in aliases:
        raise sources.error_type(f"dashboard group {dashboard_id} has no stable alias")
    stable_id = sources.resolve_alias(dashboard_id, aliases)
    if not policy.stable_group_id_pattern.fullmatch(stable_id):
        raise sources.error_type(
            f"dashboard group {dashboard_id} resolves to invalid stable identity "
            f"{stable_id!r}"
        )
    alert_id = str(summary.get("representative_alert_id") or "").strip()
    if not policy.representative_alert_id_pattern.fullmatch(alert_id):
        raise sources.error_type(
            f"dashboard group {dashboard_id} has an invalid representative alert ID"
        )
    return dashboard_id, stable_id, alert_id


def _bind_frozen_detection(
    connection: Any,
    dashboard_id: str,
    stable_id: str,
    alert_id: str,
    detection: dict[str, Any],
    sources: CohortFreezeSources,
) -> tuple[dict[str, Any], str]:
    detection = sources.bind_representative_stable_group_key(
        connection, alert_id, detection
    )
    stable_key = sources.validate_stable_group_key(
        detection.get("stable_group_key"),
        f"representative alert stable_group_key for dashboard group {dashboard_id}",
    )
    sources.validate_representative_binding(
        connection,
        {
            "dashboard_group_id": dashboard_id,
            "stable_group_id": stable_id,
            "stable_group_key": stable_key,
            "representative_alert_id": alert_id,
            "detection": detection,
        },
        alert_id,
    )
    return detection, stable_key


def _new_member(
    rank: int,
    agent_role: str,
    dashboard_id: str,
    stable_id: str,
    stable_key: str,
    alert_id: str,
    detection: dict[str, Any],
    pre_state: dict[str, Any],
) -> dict[str, Any]:
    kind = "analyze" if agent_role == "soc-analyst" else (
        "reanalyze" if pre_state["incident_case"] else "escalate"
    )
    return {
        "rank": rank,
        "dashboard_group_id": dashboard_id,
        "stable_group_id": stable_id,
        "stable_group_key": stable_key,
        "representative_alert_id": alert_id,
        "detection": detection,
        "pre_state": pre_state,
        "dispatch": {"kind": kind, "state": "unattempted", "attempt_count": 0},
        "monitor": {"state": "not_started"},
    }


def _select_database_members(
    connection: Any,
    count: int,
    policy: CohortFreezePolicy,
    sources: CohortFreezeSources,
    aliases: Mapping[str, str],
    cases_by_stable: Mapping[str, list[dict]],
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    selected_stable: set[str] = set()
    for summary in sources.summary_rows(connection):
        dashboard_id, stable_id, alert_id = _stable_summary_identity(
            summary, aliases, policy, sources
        )
        if stable_id in selected_stable:
            continue
        detection = {key: value for key, value in summary.items() if key != "group_id"}
        detection, stable_key = _bind_frozen_detection(
            connection, dashboard_id, stable_id, alert_id, detection, sources
        )
        pre_state = sources.incident_pre_state(
            connection, stable_id, aliases, cases_by_stable
        )
        selected_stable.add(stable_id)
        selected.append(
            _new_member(
                len(selected) + 1, "incident-responder", dashboard_id,
                stable_id, stable_key, alert_id, detection, pre_state,
            )
        )
        if len(selected) == count:
            break
    if len(selected) != count:
        raise sources.error_type(
            f"requested {count} distinct stable groups but only {len(selected)} were available"
        )
    return selected


def _manifest_document(
    connection: Any,
    policy: CohortFreezePolicy,
    sources: CohortFreezeSources,
    *,
    cohort_id: str,
    reason: str,
    agent_role: str,
    members: list[dict[str, Any]],
    selection_mode: str,
    source_sha256: str,
    database_path: Path,
    expected_release_id: str,
    expected_assigned_route: str,
    expected_reviewer_route: str,
    evaluation_profile: str,
) -> dict[str, Any]:
    identities = sources.ordered_identity_projection(members)
    manifest = {
        "schema": policy.schema,
        "cohort_id": cohort_id,
        "reason": reason,
        "agent_role": agent_role,
        "count": len(members),
        "created_at": sources.utc_now(),
        "selection": {
            "mode": selection_mode,
            "source_sha256": source_sha256,
            "source_count": len(members),
            "order_preserved": True,
            "ordered_identity_sha256": sources.sha256_value(identities),
        },
        "execution_contract": sources.execution_contract(
            expected_release_id=expected_release_id,
            expected_assigned_route=expected_assigned_route,
            expected_reviewer_route=expected_reviewer_route,
            evaluation_profile=evaluation_profile,
        ),
        "database": {
            "path": str(database_path.expanduser().resolve()),
            "schema_sha256": sources.schema_fingerprint(connection),
            "user_version": int(connection.execute("PRAGMA user_version").fetchone()[0]),
            "read_only": True,
        },
        "security_onion_access": "none",
        "state": "frozen",
        "members": members,
    }
    manifest["frozen_plan_sha256"] = sources.frozen_plan_digest(manifest)
    return manifest


def _finish_manifest(
    manifest_path: Path,
    manifest: dict[str, Any],
    dry_run: bool,
    sources: CohortFreezeSources,
) -> dict[str, Any]:
    if dry_run:
        return sources.digest_bound(manifest, "manifest_sha256")
    return sources.write_private_json(
        manifest_path, manifest, digest_field="manifest_sha256", replace=False
    )


def freeze_cohort(
    policy: CohortFreezePolicy,
    sources: CohortFreezeSources,
    database_path: Path,
    manifest_path: Path,
    *,
    cohort_id: str,
    reason: str,
    count: int,
    expected_release_id: str,
    expected_assigned_route: str,
    expected_reviewer_route: str,
    evaluation_profile: str,
    dry_run: bool,
) -> dict[str, Any]:
    cohort_id, reason, expected_release_id = _validate_freeze_request(
        policy, sources, manifest_path, cohort_id, reason, count,
        expected_release_id, dry_run,
    )
    connection = sources.connect_read_only(database_path)
    try:
        connection.execute("BEGIN")
        aliases = sources.load_aliases(connection)
        cases = sources.incident_cases(connection, aliases)
        members = _select_database_members(
            connection, count, policy, sources, aliases, cases
        )
        identities = sources.ordered_identity_projection(members)
        manifest = _manifest_document(
            connection, policy, sources, cohort_id=cohort_id, reason=reason,
            agent_role="incident-responder", members=members,
            selection_mode="database_newest",
            source_sha256=sources.sha256_value(identities),
            database_path=database_path, expected_release_id=expected_release_id,
            expected_assigned_route=expected_assigned_route,
            expected_reviewer_route=expected_reviewer_route,
            evaluation_profile=evaluation_profile,
        )
    finally:
        connection.close()
    return _finish_manifest(manifest_path, manifest, dry_run, sources)


def _imported_detection(
    connection: Any,
    source: Mapping[str, Any],
    current: Mapping[str, Any],
    dashboard_id: str,
    alert_id: str,
    sources: CohortFreezeSources,
) -> dict[str, Any]:
    current_alert_id = str(current.get("representative_alert_id") or "")
    if current_alert_id != alert_id:
        try:
            return sources.source_detection_projection(source)
        except RuntimeError as exc:
            raise sources.error_type(
                f"source row {dashboard_id} detection must be an object"
            ) from exc
    projected = sources.validate_source_detection(source, current, dashboard_id)
    detection = {key: value for key, value in current.items() if key != "group_id"}
    if "stable_group_key" in projected:
        detection["stable_group_key"] = projected["stable_group_key"]
    return detection


def _imported_member(
    connection: Any,
    source: Mapping[str, Any],
    rank: int,
    agent_role: str,
    aliases: Mapping[str, str],
    cases: Mapping[str, list[dict]],
    summaries: Mapping[str, Mapping[str, Any]],
    sources: CohortFreezeSources,
) -> dict[str, Any]:
    dashboard_id, stable_id, alert_id = sources.source_identity(source)
    current = summaries.get(dashboard_id)
    if not current:
        raise sources.error_type(
            f"source dashboard group no longer exists: {dashboard_id}"
        )
    if sources.resolve_alias(dashboard_id, aliases) != stable_id:
        raise sources.error_type(f"source stable identity changed for {dashboard_id}")
    detection = _imported_detection(
        connection, source, current, dashboard_id, alert_id, sources
    )
    detection = sources.bind_representative_stable_group_key(
        connection, alert_id, detection
    )
    stable_key = sources.validate_stable_group_key(
        detection.get("stable_group_key"),
        f"representative alert stable_group_key for dashboard group {dashboard_id}",
    )
    sources.validate_representative_binding(
        connection,
        {
            "dashboard_group_id": dashboard_id,
            "stable_group_id": stable_id,
            "stable_group_key": stable_key,
            "representative_alert_id": alert_id,
            "detection": detection,
        },
        str(current.get("representative_alert_id") or ""),
    )
    if agent_role == "soc-analyst":
        pre_state = sources.soc_pre_state(connection, stable_id, aliases)
    else:
        pre_state = sources.incident_pre_state(connection, stable_id, aliases, cases)
        sources.validate_source_pre_state(source, pre_state, dashboard_id)
    return _new_member(
        rank, agent_role, dashboard_id, stable_id, stable_key,
        alert_id, detection, pre_state,
    )


def _import_members(
    connection: Any,
    rows: list[dict[str, Any]],
    agent_role: str,
    sources: CohortFreezeSources,
) -> list[dict[str, Any]]:
    aliases = sources.load_aliases(connection)
    cases = sources.incident_cases(connection, aliases)
    summaries = {
        str(item.get("group_id") or ""): item for item in sources.summary_rows(connection)
    }
    members: list[dict[str, Any]] = []
    seen_dashboard: set[str] = set()
    seen_stable: set[str] = set()
    for rank, source in enumerate(rows, start=1):
        dashboard_id, stable_id, _ = sources.source_identity(source)
        if dashboard_id in seen_dashboard:
            raise sources.error_type(f"source repeats dashboard group {dashboard_id}")
        if stable_id in seen_stable:
            raise sources.error_type(f"source repeats stable group {stable_id}")
        members.append(
            _imported_member(
                connection, source, rank, agent_role, aliases, cases, summaries, sources
            )
        )
        seen_dashboard.add(dashboard_id)
        seen_stable.add(stable_id)
    return members


def freeze_cohort_from_rows(
    policy: CohortFreezePolicy,
    sources: CohortFreezeSources,
    database_path: Path,
    source_rows_path: Path,
    manifest_path: Path,
    *,
    cohort_id: str,
    reason: str,
    expected_count: int,
    expected_release_id: str,
    agent_role: str,
    expected_assigned_route: str,
    expected_reviewer_route: str,
    evaluation_profile: str,
    dry_run: bool,
) -> dict[str, Any]:
    cohort_id, reason, expected_release_id = _validate_freeze_request(
        policy, sources, manifest_path, cohort_id, reason, expected_count,
        expected_release_id, dry_run,
    )
    agent_role = sources.validate_agent_role(agent_role)
    rows, source_sha256 = sources.load_private_source_rows(source_rows_path)
    if len(rows) != expected_count:
        raise sources.error_type(
            f"source contains {len(rows)} rows; expected {expected_count}"
        )
    connection = sources.connect_read_only(database_path)
    try:
        connection.execute("BEGIN")
        members = _import_members(connection, rows, agent_role, sources)
        manifest = _manifest_document(
            connection, policy, sources, cohort_id=cohort_id, reason=reason,
            agent_role=agent_role, members=members, selection_mode="imported_rows",
            source_sha256=source_sha256, database_path=database_path,
            expected_release_id=expected_release_id,
            expected_assigned_route=expected_assigned_route,
            expected_reviewer_route=expected_reviewer_route,
            evaluation_profile=evaluation_profile,
        )
    finally:
        connection.close()
    return _finish_manifest(manifest_path, manifest, dry_run, sources)
