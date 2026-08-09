#!/usr/bin/env python3
"""Legacy prompt-builder adapters over modular evidence and I/O services."""
from __future__ import annotations

import datetime as dt
import sqlite3
from pathlib import Path
from typing import Iterable

from incident_evidence_contract import validate_incident_evidence_artifact
from prompt_alert_store import (
    build_test_alert_filter,
    derive_alert_group_key,
    query_row,
    query_rows,
    sqlite_row_value,
    stable_alert_group_id,
)
from prompt_builder_io import (
    load_bounded_json_mapping,
    load_prompt_text,
    normalized_int,
    output_filename_timestamp,
    parse_json_mapping,
    read_bounded_bytes,
    safe_output_filename,
)
from prompt_builder_policy import (
    DEFAULT_SYSTEM_PROMPT,
    MAX_ARTIFACT_JSON_BYTES,
    MAX_SYSTEM_PROMPT_BYTES,
    TEST_PREFIXES,
)
from prompt_incident_evidence_projection import (
    project_incident_evidence_hits as project_evidence_hits,
    project_incident_evidence_osquery_rows as project_evidence_osquery_rows,
    reject_preprojected_incident_evidence_source as reject_preprojected_source,
)
from prompt_incident_grounding import (
    IncidentGroundingSources,
    immutable_query_provenance,
    mandatory_grounding_digest,
)
from prompt_package_compactor import (
    PackageCompactionSources,
    compact_package_to_budget as compact_prompt_package,
)


def project_incident_evidence_hits(
    incident_evidence: dict,
    *,
    limit: int,
    reason: str,
) -> int:
    return project_evidence_hits(incident_evidence, limit=limit, reason=reason)


def project_incident_evidence_osquery_rows(
    incident_evidence: dict,
    *,
    limit: int,
    max_retained_bytes: int,
    max_row_bytes: int,
    reason: str,
) -> int:
    return project_evidence_osquery_rows(
        incident_evidence,
        limit=limit,
        max_retained_bytes=max_retained_bytes,
        max_row_bytes=max_row_bytes,
        reason=reason,
    )


def reject_preprojected_incident_evidence_source(incident_evidence: dict) -> None:
    reject_preprojected_source(incident_evidence)


def project_now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  ")


def filename_timestamp(value: str) -> str:
    return output_filename_timestamp(value)


def safe_filename(value: str) -> str:
    return safe_output_filename(value)


def rows(
    conn: sqlite3.Connection,
    sql: str,
    params: Iterable[object] = (),
) -> list[sqlite3.Row]:
    return query_rows(conn, sql, params)


def row(
    conn: sqlite3.Connection,
    sql: str,
    params: Iterable[object] = (),
) -> sqlite3.Row | None:
    return query_row(conn, sql, params)


def test_filter_sql(prefix: str = "alert_id") -> tuple[str, list[object]]:
    return build_test_alert_filter(TEST_PREFIXES, prefix)


def parse_alert_json(value: str | None) -> dict:
    return parse_json_mapping(value)


def parse_json_object(value: str | None) -> dict:
    return parse_json_mapping(value)


def safe_int(value: object, default: int = 0) -> int:
    return normalized_int(value, default)


def read_bytes_bounded(path: Path, max_bytes: int) -> bytes:
    return read_bounded_bytes(path, max_bytes)


def load_json_bounded(path: Path, max_bytes: int = MAX_ARTIFACT_JSON_BYTES) -> dict:
    return load_bounded_json_mapping(path, max_bytes)


def load_system_prompt(path: Path) -> str:
    return load_prompt_text(path, MAX_SYSTEM_PROMPT_BYTES, DEFAULT_SYSTEM_PROMPT)


def sqlite_value(row_value: sqlite3.Row, key: str, default: object = None) -> object:
    return sqlite_row_value(row_value, key, default)


def alert_group_key(row_value: sqlite3.Row) -> str:
    return derive_alert_group_key(row_value)


def alert_group_id(group_key: str) -> str:
    return stable_alert_group_id(group_key)


def incident_prompt_immutable_query_provenance(incident: dict) -> dict:
    return immutable_query_provenance(incident)


def incident_prompt_mandatory_grounding_digest(package: dict) -> str:
    return mandatory_grounding_digest(
        IncidentGroundingSources(
            validate_incident_evidence=validate_incident_evidence_artifact,
        ),
        package,
    )


def compact_package_to_budget(package: dict, max_bytes: int) -> tuple[dict, str]:
    return compact_prompt_package(
        PackageCompactionSources(
            mandatory_grounding_digest=incident_prompt_mandatory_grounding_digest,
            project_hits=project_incident_evidence_hits,
            project_osquery_rows=project_incident_evidence_osquery_rows,
            validate_incident_evidence=validate_incident_evidence_artifact,
        ),
        package,
        max_bytes,
    )
