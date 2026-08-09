#!/usr/bin/env python3
"""Configured alert-store evidence projections for prompt construction."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
import sqlite3
from typing import Any, Iterable

from detection_validation import extract_rule_context
from prompt_alert_group import (
    AlertGroupRowsRequest,
    AlertGroupSources,
    build_analyst_state_context,
    build_execution_lineage,
    build_grouped_alert_context,
    fetch_alert_group_rows,
)
from prompt_alert_projection import AlertProjectionSources, project_compact_alert
from prompt_alert_queries import (
    AlertQuerySources,
    AlertSelectionRequest,
    related_alert_context,
    select_prompt_alert,
)
from prompt_alert_store import (
    build_test_alert_filter,
    derive_alert_group_key,
    query_row,
    query_rows,
    read_table_columns,
    sqlite_row_value,
    stable_alert_group_id,
)
from prompt_authorization_context import (
    AuthorizationContextSources,
    authorized_activity_context as project_authorized_activity_context,
    canonical_authorized_activity_entry as canonical_authorization_entry,
)
from prompt_builder_io import (
    load_bounded_json_mapping,
    normalized_int,
    parse_json_mapping,
)
from prompt_builder_policy import (
    LEGACY_ARTIFACT_SCAN_LIMIT,
    MAX_ARTIFACT_JSON_BYTES,
    MAX_DETECTION_GROUP_ROWS,
    TEST_PREFIXES,
)
from prompt_correlation_context import (
    CorrelationContextSources,
    build_correlated_alert_context,
)
from prompt_correlation_facts import (
    CORRELATION_MAX_RAW_JSON_BYTES,
    CorrelationFactSources,
    correlation_observable_weight,
    correlation_relationships,
    correlation_row_facts,
    correlation_time_bonus,
    parse_project_datetime,
)
from prompt_pcap_evidence import (
    PcapEvidenceRequest,
    PcapEvidenceSources,
    build_pcap_evidence_context,
    compact_pcap_analysis as project_pcap_analysis,
    pcap_request_context as project_pcap_request_context,
)
from prompt_prior_analysis import (
    PriorAnalysisRequest,
    PriorAnalysisSources,
    build_prior_analysis_context,
)
from prompt_public_enrichment import (
    PublicEnrichmentRequest,
    PublicEnrichmentSources,
    build_public_enrichment_context,
    compact_public_enrichment_record as project_public_enrichment_record,
)


def rows(connection, sql, params: Iterable[object] = ()):
    return query_rows(connection, sql, params)


def row(connection, sql, params: Iterable[object] = ()):
    return query_row(connection, sql, params)


def test_filter_sql(prefix: str = "alert_id") -> tuple[str, list[object]]:
    return build_test_alert_filter(TEST_PREFIXES, prefix)


def parse_alert_json(value: str | None) -> dict:
    return parse_json_mapping(value)


def parse_json_object(value: str | None) -> dict:
    return parse_json_mapping(value)


def safe_int(value: object, default: int = 0) -> int:
    return normalized_int(value, default)


def load_json_bounded(
    path: Path,
    max_bytes: int = MAX_ARTIFACT_JSON_BYTES,
) -> dict:
    return load_bounded_json_mapping(path, max_bytes)


def sqlite_value(row_value: Any, key: str, default: object = None) -> object:
    return sqlite_row_value(row_value, key, default)


def alert_group_key(row_value: Any) -> str:
    return derive_alert_group_key(row_value)


def alert_group_id(group_key: str) -> str:
    return stable_alert_group_id(group_key)


def table_columns(connection, table: str) -> set[str]:
    return read_table_columns(connection, table)


def _alert_group_sources() -> AlertGroupSources:
    return AlertGroupSources(
        table_columns=table_columns,
        row_value=sqlite_value,
        query_row=row,
        query_rows=rows,
        test_filter_sql=test_filter_sql,
        safe_int=safe_int,
        alert_group_key=alert_group_key,
        alert_group_id=alert_group_id,
    )


def execution_lineage(selected: Any, *, blind_reanalysis: bool) -> dict[str, Any]:
    return build_execution_lineage(
        _alert_group_sources(),
        selected,
        blind_reanalysis=blind_reanalysis,
    )


def alert_group_rows(
    connection,
    selected,
    *,
    include_tests: bool,
    extra_columns: Iterable[str] = (),
    row_limit: int | None = None,
):
    return fetch_alert_group_rows(
        _alert_group_sources(),
        AlertGroupRowsRequest(
            connection=connection,
            selected=selected,
            include_tests=include_tests,
            maximum_group_rows=MAX_DETECTION_GROUP_ROWS,
            extra_columns=tuple(extra_columns),
            row_limit=row_limit,
        ),
    )


def analyst_state_context(connection, selected) -> dict:
    return build_analyst_state_context(
        _alert_group_sources(),
        connection,
        selected,
    )


def prior_analysis_context(
    connection,
    analysis_dir: Path,
    selected,
    limit: int = 3,
) -> list[dict]:
    return build_prior_analysis_context(
        PriorAnalysisSources(
            row_value=sqlite_value,
            query_rows=rows,
            load_json_bounded=load_json_bounded,
        ),
        PriorAnalysisRequest(
            connection=connection,
            analysis_dir=analysis_dir,
            selected=selected,
            result_limit=limit,
            legacy_scan_limit=LEGACY_ARTIFACT_SCAN_LIMIT,
        ),
    )


def compact_pcap_analysis(record: dict) -> dict:
    return project_pcap_analysis(record)


def compact_public_enrichment_record(record: dict) -> dict:
    return project_public_enrichment_record(record)


def _public_enrichment_sources() -> PublicEnrichmentSources:
    return PublicEnrichmentSources(
        row_value=sqlite_value,
        alert_group_rows=alert_group_rows,
        parse_json_object=parse_json_object,
    )


def public_enrichment_context(
    connection,
    selected,
    limit: int,
    include_tests: bool,
) -> dict:
    return build_public_enrichment_context(
        _public_enrichment_sources(),
        PublicEnrichmentRequest(
            connection=connection,
            selected=selected,
            record_limit=limit,
            include_tests=include_tests,
        ),
    )


def _pcap_evidence_sources() -> PcapEvidenceSources:
    return PcapEvidenceSources(
        row_value=sqlite_value,
        query_rows=rows,
        load_json_bounded=load_json_bounded,
    )


def pcap_request_context(connection, selected) -> list[dict]:
    return project_pcap_request_context(
        _pcap_evidence_sources(),
        connection,
        selected,
    )


def pcap_evidence_context(
    connection,
    selected,
    analysis_dir: Path,
    limit: int,
) -> dict:
    return build_pcap_evidence_context(
        _pcap_evidence_sources(),
        PcapEvidenceRequest(
            connection=connection,
            selected=selected,
            analysis_dir=analysis_dir,
            evidence_limit=limit,
            legacy_scan_limit=LEGACY_ARTIFACT_SCAN_LIMIT,
        ),
    )


def _alert_query_sources() -> AlertQuerySources:
    return AlertQuerySources(
        query_row=row,
        query_rows=rows,
        test_filter_sql=test_filter_sql,
        row_value=sqlite_value,
        now_local=lambda: dt.datetime.now().astimezone(),
    )


def select_alert(connection, args):
    return select_prompt_alert(
        _alert_query_sources(),
        AlertSelectionRequest(
            connection=connection,
            alert_id=str(args.alert_id or ""),
            levels_csv=str(args.levels or ""),
            hours=int(args.hours),
            include_tests=bool(args.include_tests),
        ),
    )


def related_alerts(connection, selected, limit: int, include_tests: bool) -> list[dict]:
    return related_alert_context(
        _alert_query_sources(),
        connection,
        selected,
        limit,
        include_tests,
    )


def _authorization_context_sources() -> AuthorizationContextSources:
    return AuthorizationContextSources(
        row_value=sqlite_value,
        parse_alert_json=parse_alert_json,
        parse_datetime=parse_project_datetime,
        query_row=row,
        query_rows=rows,
    )


def authorized_activity_context(
    connection,
    selected,
    limit: int = 500,
) -> dict[str, Any] | None:
    return project_authorized_activity_context(
        _authorization_context_sources(),
        connection,
        selected,
        limit,
    )


def canonical_authorized_activity_entry(
    selected: Any,
    authorization: Any,
    *,
    policy_id: Any,
) -> dict[str, Any] | None:
    return canonical_authorization_entry(
        _authorization_context_sources(),
        selected,
        authorization,
        policy_id=policy_id,
    )


def _correlation_row_facts(row_value: Any) -> dict[str, Any]:
    return correlation_row_facts(
        CorrelationFactSources(
            row_value=sqlite_value,
            parse_json_object=parse_json_object,
        ),
        row_value,
    )


def _correlation_relationships(
    selected_facts: dict[str, Any],
    related_facts: dict[str, Any],
) -> list[dict[str, Any]]:
    return correlation_relationships(selected_facts, related_facts)


def correlated_alert_context(
    connection,
    selected,
    limit: int,
    min_score: int,
) -> dict:
    return build_correlated_alert_context(
        CorrelationContextSources(
            rows=rows,
            table_columns=table_columns,
            row_value=sqlite_value,
            observable_weight=correlation_observable_weight,
            time_bonus=correlation_time_bonus,
            row_facts=_correlation_row_facts,
            relationships=_correlation_relationships,
            safe_int=safe_int,
            max_raw_json_bytes=CORRELATION_MAX_RAW_JSON_BYTES,
        ),
        connection,
        selected,
        limit,
        min_score,
    )


def grouped_alert_context(
    connection,
    selected,
    limit: int,
    include_tests: bool,
) -> dict:
    return build_grouped_alert_context(
        _alert_group_sources(),
        AlertGroupRowsRequest(
            connection=connection,
            selected=selected,
            include_tests=include_tests,
            maximum_group_rows=MAX_DETECTION_GROUP_ROWS,
        ),
        limit,
    )


def compact_alert(row_value) -> dict:
    return project_compact_alert(
        AlertProjectionSources(
            row_value=sqlite_value,
            parse_alert_json=parse_alert_json,
            parse_json_object=parse_json_object,
            extract_rule_context=extract_rule_context,
        ),
        row_value,
    )
