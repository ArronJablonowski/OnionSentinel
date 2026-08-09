"""Compose read-only cohort state, representative binding, and preflight."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Iterable, Mapping

from cohort_manifest_adapters import (
    member_stable_group_key,
    validate_stable_group_key,
)
from cohort_preflight import (
    MemberPreflightSources,
    RepresentativeBindingPolicy,
    validate_member_preflight as run_member_preflight,
    validate_representative_binding as prove_representative_binding,
)
from cohort_representative_state import (
    CohortRepresentativeStatePolicy,
    alert_representative_identity as read_alert_representative_identity,
    bind_representative_stable_group_key as bind_stable_group_key,
    case_for_stable as read_case_for_stable,
    current_summary_identity as read_current_summary_identity,
)
from cohort_runner_contracts import (
    ACTIVE_AGENT_STATES,
    FROZEN_REPRESENTATIVE_IMMUTABLE_FIELDS,
    REPRESENTATIVE_ALERT_ID_RE,
    REPRESENTATIVE_BINDING_SCHEMA,
    AmbiguousDispatchError,
    CohortError,
    sha256_value,
)
from cohort_storage_core import (
    CohortStoragePolicy,
    connect_read_only as open_cohort_database_read_only,
    load_aliases as read_group_aliases,
    require_columns as require_storage_columns,
    resolve_alias as resolve_group_alias,
    schema_fingerprint as calculate_schema_fingerprint,
    table_columns as storage_table_columns,
    table_exists as storage_table_exists,
)
from cohort_storage_state import (
    CohortStatePolicy,
    active_jobs as query_active_jobs,
    active_reanalysis as query_active_reanalysis,
    analysis_ids_for_group as query_analysis_ids_for_group,
    durable_dispatch_job as read_durable_dispatch_job,
    durable_job_snapshot as read_durable_job_snapshot,
    frozen_analysis_ids as read_frozen_analysis_ids,
    incident_cases as query_incident_cases,
    incident_pre_state as build_incident_pre_state,
    latest_analysis_metadata as read_latest_analysis_metadata,
    soc_pre_state as build_soc_pre_state,
    summary_rows as query_summary_rows,
    verify_zero_fresh_analyses as prove_zero_fresh_analyses,
)


SUMMARY_EXPORT_COLUMNS = (
    "group_id",
    "representative_alert_id",
    "first_seen",
    "last_seen",
    "timestamp",
    "rule_name",
    "event_dataset",
    "severity",
    "severity_label",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "network_protocol",
    "transport_protocol",
    "traffic_direction",
    "triage_score",
    "triage_level",
    "raw_alert_count",
    "total_seen_count",
)


def storage_policy() -> CohortStoragePolicy:
    return CohortStoragePolicy(error=CohortError, sha256_value=sha256_value)


def connect_read_only(database_path: Path) -> sqlite3.Connection:
    return open_cohort_database_read_only(database_path, storage_policy())


def table_exists(connection: sqlite3.Connection, table: str) -> bool:
    return storage_table_exists(connection, table)


def table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return storage_table_columns(connection, table)


def require_columns(
    connection: sqlite3.Connection,
    table: str,
    required: Iterable[str],
) -> set[str]:
    return require_storage_columns(connection, table, required, storage_policy())


def schema_fingerprint(connection: sqlite3.Connection) -> str:
    return calculate_schema_fingerprint(connection, storage_policy())


def load_aliases(connection: sqlite3.Connection) -> dict[str, str]:
    return read_group_aliases(connection, storage_policy())


def resolve_alias(identity: str, aliases: Mapping[str, str]) -> str:
    return resolve_group_alias(identity, aliases, storage_policy())


def state_policy() -> CohortStatePolicy:
    return CohortStatePolicy(
        error=CohortError,
        ambiguous_error=AmbiguousDispatchError,
        storage=storage_policy(),
        active_agent_states=frozenset(ACTIVE_AGENT_STATES),
    )


def summary_rows(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    return query_summary_rows(connection, state_policy())


def incident_cases(
    connection: sqlite3.Connection,
    aliases: Mapping[str, str],
) -> dict[str, list[dict[str, Any]]]:
    return query_incident_cases(connection, aliases, state_policy())


def active_jobs(
    connection: sqlite3.Connection,
    stable_group_id: str,
    aliases: Mapping[str, str],
    *,
    job_type: str = "incident_response_analysis",
) -> list[dict[str, Any]]:
    return query_active_jobs(
        connection,
        stable_group_id,
        aliases,
        state_policy(),
        job_type=job_type,
    )


def durable_dispatch_job(
    connection: sqlite3.Connection,
    *,
    job_type: str,
    stable_group_id: str,
) -> dict[str, Any]:
    return read_durable_dispatch_job(
        connection,
        job_type=job_type,
        stable_group_id=stable_group_id,
        policy=state_policy(),
    )


def durable_job_snapshot(
    connection: sqlite3.Connection,
    *,
    job_type: str,
    stable_group_id: str,
) -> dict[str, Any] | None:
    return read_durable_job_snapshot(
        connection,
        job_type=job_type,
        stable_group_id=stable_group_id,
        policy=state_policy(),
    )


def active_reanalysis(
    connection: sqlite3.Connection,
    stable_group_id: str,
    case_id: str,
    aliases: Mapping[str, str],
) -> list[dict[str, Any]]:
    return query_active_reanalysis(
        connection,
        stable_group_id,
        case_id,
        aliases,
        state_policy(),
    )


def analysis_ids_for_group(
    connection: sqlite3.Connection,
    stable_group_id: str,
    *,
    agent_role: str,
) -> list[str]:
    return query_analysis_ids_for_group(
        connection,
        stable_group_id,
        agent_role=agent_role,
        policy=state_policy(),
    )


def frozen_analysis_ids(
    member: Mapping[str, Any],
    *,
    agent_role: str,
    pre_state_field: str,
) -> set[str]:
    return read_frozen_analysis_ids(
        member,
        agent_role=agent_role,
        pre_state_field=pre_state_field,
        policy=state_policy(),
    )


def verify_zero_fresh_analyses(
    connection: sqlite3.Connection,
    member: Mapping[str, Any],
    stable_group_id: str,
    *,
    agent_role: str,
    pre_state_field: str,
) -> list[str]:
    return prove_zero_fresh_analyses(
        connection,
        member,
        stable_group_id,
        agent_role=agent_role,
        pre_state_field=pre_state_field,
        policy=state_policy(),
    )


def soc_pre_state(
    connection: sqlite3.Connection,
    stable_group_id: str,
    aliases: Mapping[str, str],
) -> dict[str, Any]:
    return build_soc_pre_state(connection, stable_group_id, aliases, state_policy())


def latest_analysis_metadata(
    connection: sqlite3.Connection,
    analysis_id: str,
) -> dict[str, Any] | None:
    return read_latest_analysis_metadata(connection, analysis_id)


def incident_pre_state(
    connection: sqlite3.Connection,
    stable_group_id: str,
    aliases: Mapping[str, str],
    cases_by_stable: Mapping[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    return build_incident_pre_state(
        connection,
        stable_group_id,
        aliases,
        cases_by_stable,
        state_policy(),
    )


def representative_state_policy() -> CohortRepresentativeStatePolicy:
    return CohortRepresentativeStatePolicy(
        error=CohortError,
        storage=storage_policy(),
        resolve_alias=resolve_alias,
        incident_cases=incident_cases,
        immutable_fields=FROZEN_REPRESENTATIVE_IMMUTABLE_FIELDS,
    )


def current_summary_identity(
    connection: sqlite3.Connection,
    dashboard_group_id: str,
    aliases: Mapping[str, str],
) -> tuple[str, str] | None:
    return read_current_summary_identity(
        connection,
        dashboard_group_id,
        aliases,
        representative_state_policy(),
    )


def alert_representative_identity(
    connection: sqlite3.Connection,
    alert_id: str,
) -> dict[str, Any] | None:
    return read_alert_representative_identity(
        connection,
        alert_id,
        representative_state_policy(),
    )


def bind_representative_stable_group_key(
    connection: sqlite3.Connection,
    representative_alert_id: str,
    detection: Mapping[str, Any],
) -> dict[str, Any]:
    return bind_stable_group_key(
        connection,
        representative_alert_id,
        detection,
        representative_state_policy(),
        alert_identity=alert_representative_identity,
    )


def validate_representative_binding(
    connection: sqlite3.Connection,
    member: Mapping[str, Any],
    current_representative_alert_id: str,
) -> dict[str, Any]:
    return prove_representative_binding(
        connection,
        member,
        current_representative_alert_id,
        alert_identity=alert_representative_identity,
        member_stable_group_key=member_stable_group_key,
        policy=RepresentativeBindingPolicy(
            error=CohortError,
            representative_alert_id_pattern=REPRESENTATIVE_ALERT_ID_RE,
            immutable_fields=FROZEN_REPRESENTATIVE_IMMUTABLE_FIELDS,
            binding_schema=REPRESENTATIVE_BINDING_SCHEMA,
            validate_stable_group_key=validate_stable_group_key,
            sha256_value=sha256_value,
        ),
    )


def case_for_stable(
    connection: sqlite3.Connection,
    stable_group_id: str,
    aliases: Mapping[str, str],
) -> dict[str, Any] | None:
    return read_case_for_stable(
        connection,
        stable_group_id,
        aliases,
        representative_state_policy(),
    )


def validate_member_preflight(
    connection: sqlite3.Connection,
    member: Mapping[str, Any],
) -> dict[str, Any]:
    return run_member_preflight(
        connection,
        member,
        MemberPreflightSources(
            error=CohortError,
            active_agent_states=frozenset(ACTIVE_AGENT_STATES),
            load_aliases=load_aliases,
            current_summary_identity=current_summary_identity,
            validate_representative_binding=validate_representative_binding,
            soc_pre_state=soc_pre_state,
            frozen_analysis_ids=frozen_analysis_ids,
            analysis_ids_for_group=analysis_ids_for_group,
            case_for_stable=case_for_stable,
            active_jobs=active_jobs,
            active_reanalysis=active_reanalysis,
        ),
    )


def validate_frozen_cohort(
    database_path: Path,
    manifest: Mapping[str, Any],
) -> None:
    connection = connect_read_only(database_path)
    try:
        connection.execute("BEGIN")
        if schema_fingerprint(connection) != (
            manifest.get("database") or {}
        ).get("schema_sha256"):
            raise CohortError("alert database schema changed after cohort freeze")
        for member in manifest["members"]:
            validate_member_preflight(connection, member)
    finally:
        connection.close()
