#!/usr/bin/env python3
"""Freeze and orchestrate a bounded Onion Sentinel agent evaluation cohort.

This utility deliberately does not grade investigation semantics.  It provides
the reproducible control plane around an evaluation:

* choose the newest distinct stable detection groups from SQLite in read-only
  mode;
* freeze dashboard/stable identities and pre-run state in an owner-only,
  digest-bound manifest;
* enqueue each member once through the loopback dashboard API, using a
  single-group SOC analysis, incident escalation, or single-case reanalysis
  endpoint;
* monitor the exact case/run identities returned by the API; and
* export bounded result metadata and cryptographic digests without exporting
  prompts, raw responses, queries, evidence rows, credentials, or job payloads.

It never connects to Security Onion and it never writes the alert database.
All database connections use SQLite ``mode=ro`` plus ``PRAGMA query_only``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import sqlite3
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping


SCHEMA = "onion-sentinel-incident-harness-cohort-v2"
EXPORT_SCHEMA = "onion-sentinel-incident-harness-cohort-export-v2"
MAX_COHORT_SIZE = 100
MAX_HTTP_BODY_BYTES = 1_000_000
MAX_SOURCE_ROWS_BYTES = 2_000_000
MAX_MANIFEST_BYTES = 10_000_000
TERMINAL_MONITOR_STATES = {"completed", "failed", "skipped"}
ACTIVE_JOB_STATES = {"pending", "processing"}
ACTIVE_AGENT_STATES = {"queued", "analyzing"}
ACTIVE_REANALYSIS_STATES = {"queued", "running"}
AGENT_ROLES = {"incident-responder", "soc-analyst"}
COHORT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}")
DASHBOARD_GROUP_ID_RE = re.compile(r"[a-f0-9]{12}")
STABLE_GROUP_ID_RE = re.compile(r"[a-f0-9]{20}")
CASE_ID_RE = re.compile(r"ir-[a-z0-9-]{1,80}")
RUN_ID_RE = re.compile(r"irr-[a-z0-9-]{1,80}")
SHA256_RE = re.compile(r"[a-f0-9]{64}")
SAFE_ROUTE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{2,255}")
TRACE_EVALUATOR_PATH = Path(__file__).with_name("evaluate-harness-traces.py")


class CohortError(RuntimeError):
    """A fail-closed cohort validation or orchestration error."""


class AmbiguousDispatchError(CohortError):
    """The caller cannot prove whether the dashboard accepted a request."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_value(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _digest_bound(document: Mapping[str, Any], field: str) -> dict[str, Any]:
    output = dict(document)
    output.pop(field, None)
    output[field] = sha256_value(output)
    return output


def _validate_digest(document: Mapping[str, Any], field: str) -> None:
    expected = str(document.get(field) or "")
    unsigned = dict(document)
    unsigned.pop(field, None)
    if not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise CohortError(f"{field} is missing or malformed")
    if not _constant_time_equal(expected, sha256_value(unsigned)):
        raise CohortError(f"{field} does not match the document")


def _constant_time_equal(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


def _ensure_private_parent(path: Path) -> None:
    parent = path.expanduser().resolve().parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink() or not parent.is_dir():
        raise CohortError(f"output parent is not a real directory: {parent}")
    os.chmod(parent, 0o700)


def write_private_json(
    path: Path,
    document: Mapping[str, Any],
    *,
    digest_field: str,
    replace: bool = True,
) -> dict[str, Any]:
    """Atomically write a digest-bound JSON document with mode 0600."""

    target = path.expanduser()
    _ensure_private_parent(target)
    if target.is_symlink():
        raise CohortError(f"refusing to replace symlink: {target}")
    if target.exists() and not replace:
        raise CohortError(f"refusing to overwrite existing file: {target}")
    bound = _digest_bound(document, digest_field)
    parent = target.resolve().parent
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(file_descriptor, 0o600)
        with os.fdopen(file_descriptor, "wb") as handle:
            handle.write(json.dumps(bound, indent=2, sort_keys=True).encode("utf-8"))
            handle.write(b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        os.chmod(target, 0o600)
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()
    return bound


def load_private_manifest(path: Path) -> dict[str, Any]:
    target = path.expanduser()
    if target.is_symlink() or not target.is_file():
        raise CohortError(f"manifest is not a regular file: {target}")
    metadata = target.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o077:
        raise CohortError(
            f"manifest must be owner-only (0600); current mode is {mode:04o}"
        )
    if metadata.st_uid != os.geteuid():
        raise CohortError("manifest is not owned by the current user")
    if metadata.st_size > MAX_MANIFEST_BYTES:
        raise CohortError("manifest exceeds the bounded input size")
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CohortError(f"could not read manifest: {type(exc).__name__}") from exc
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise CohortError("unsupported cohort manifest schema")
    _validate_digest(document, "manifest_sha256")
    validate_cohort_identity(
        str(document.get("cohort_id") or ""),
        str(document.get("reason") or ""),
    )
    validate_agent_role(str(document.get("agent_role") or "incident-responder"))
    members = document.get("members")
    if not isinstance(members, list) or not members:
        raise CohortError("cohort manifest has no members")
    contract = document.get("execution_contract")
    if not isinstance(contract, dict) or contract != execution_contract(
        expected_assigned_route=str(
            (contract or {}).get("expected_assigned_route") or ""
        ),
        expected_reviewer_route=str(
            (contract or {}).get("expected_reviewer_route") or ""
        ),
    ):
        raise CohortError("cohort execution contract is missing or malformed")
    frozen_plan_sha256 = str(document.get("frozen_plan_sha256") or "")
    if (
        not SHA256_RE.fullmatch(frozen_plan_sha256)
        or not _constant_time_equal(
            frozen_plan_sha256,
            _frozen_plan_digest(document),
        )
    ):
        raise CohortError("frozen plan digest does not match the manifest")
    return document


def load_private_source_rows(path: Path) -> tuple[list[dict[str, Any]], str]:
    """Load an already-frozen owner-only JSON array without changing its order."""

    target = path.expanduser()
    if target.is_symlink() or not target.is_file():
        raise CohortError(f"source rows file is not a regular file: {target}")
    metadata = target.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o077:
        raise CohortError(
            f"source rows must be owner-only (0600); current mode is {mode:04o}"
        )
    if metadata.st_uid != os.geteuid():
        raise CohortError("source rows file is not owned by the current user")
    if metadata.st_size > MAX_SOURCE_ROWS_BYTES:
        raise CohortError("source rows file exceeds the bounded input size")
    try:
        raw = target.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CohortError(
            f"could not read source rows: {type(exc).__name__}"
        ) from exc
    if (
        not isinstance(document, list)
        or not document
        or len(document) > MAX_COHORT_SIZE
        or not all(isinstance(item, dict) for item in document)
    ):
        raise CohortError(
            f"source rows must be a JSON array of 1-{MAX_COHORT_SIZE} objects"
        )
    return [dict(item) for item in document], hashlib.sha256(raw).hexdigest()


def validate_cohort_identity(cohort_id: str, reason: str) -> tuple[str, str]:
    normalized_id = str(cohort_id or "").strip()
    normalized_reason = " ".join(str(reason or "").split())
    if not COHORT_ID_RE.fullmatch(normalized_id):
        raise CohortError(
            "cohort ID must be 3-64 characters using letters, digits, '.', '_', or '-'"
        )
    if len(normalized_reason) < 10 or len(normalized_reason) > 1000:
        raise CohortError("cohort reason must contain 10-1000 characters")
    return normalized_id, normalized_reason


def validate_agent_role(value: str) -> str:
    role = str(value or "incident-responder").strip().lower()
    if role not in AGENT_ROLES:
        raise CohortError(
            "agent role must be incident-responder or soc-analyst"
        )
    return role


def validate_model_route(value: str, label: str, *, allow_empty: bool = False) -> str:
    route = str(value or "").strip()
    if not route and allow_empty:
        return ""
    if not SAFE_ROUTE_RE.fullmatch(route):
        raise CohortError(f"{label} is missing or malformed")
    return route


def execution_contract(
    *,
    expected_assigned_route: str,
    expected_reviewer_route: str = "",
) -> dict[str, Any]:
    """Return the immutable controls required for a gradeable harness run."""

    return {
        "harness_required": True,
        "harness_mode": "shadow",
        "memory_frozen": True,
        "expected_assigned_route": validate_model_route(
            expected_assigned_route,
            "expected assigned route",
        ),
        "expected_reviewer_route": validate_model_route(
            expected_reviewer_route,
            "expected reviewer route",
            allow_empty=True,
        ),
    }


def ordered_identity_projection(
    members: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "rank": int(member["rank"]),
            "dashboard_group_id": str(member["dashboard_group_id"]),
            "stable_group_id": str(member["stable_group_id"]),
            "representative_alert_id": str(
                member["representative_alert_id"]
            ),
        }
        for member in members
    ]


def _frozen_plan_digest(manifest: Mapping[str, Any]) -> str:
    selection = manifest.get("selection")
    members = (
        manifest.get("members")
        if isinstance(manifest.get("members"), list)
        else []
    )
    identities = ordered_identity_projection(members)
    if len(identities) != len(members):
        raise CohortError("frozen plan member projection is incomplete")
    return sha256_value(
        {
            "schema": manifest.get("schema"),
            "cohort_id": manifest.get("cohort_id"),
            "agent_role": manifest.get("agent_role"),
            "count": manifest.get("count"),
            "created_at": manifest.get("created_at"),
            "selection": selection if isinstance(selection, dict) else {},
            "execution_contract": manifest.get("execution_contract"),
            "members": [
                {
                    **identity,
                    "pre_state_sha256": sha256_value(
                        member.get("pre_state")
                        if isinstance(member.get("pre_state"), dict)
                        else {}
                    ),
                    "dispatch_kind": str(
                        (member.get("dispatch") or {}).get("kind") or ""
                    ),
                }
                for identity, member in zip(
                    identities,
                    members,
                )
            ],
        }
    )


def _parse_timestamp(value: Any, label: str) -> dt.datetime:
    text = str(value or "").strip()
    if not text:
        raise CohortError(f"{label} is missing")
    text = re.sub(
        r"^(\d{4}-\d{2}-\d{2})\s+",
        r"\1T",
        text,
        count=1,
    )
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CohortError(f"{label} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise CohortError(f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def connect_read_only(database_path: Path) -> sqlite3.Connection:
    """Open the live SQLite database without creating or mutating any file."""

    path = database_path.expanduser()
    if not path.exists() or not path.is_file():
        raise CohortError(f"alert database not found: {path}")
    resolved = path.resolve()
    uri_path = urllib.parse.quote(str(resolved), safe="/")
    try:
        connection = sqlite3.connect(
            f"file:{uri_path}?mode=ro",
            uri=True,
            timeout=5.0,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        if int(connection.execute("PRAGMA query_only").fetchone()[0]) != 1:
            connection.close()
            raise CohortError("SQLite query_only could not be enabled")
        return connection
    except sqlite3.Error as exc:
        raise CohortError(f"could not open alert database read-only: {exc}") from exc


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return row is not None


def _table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    if not _table_exists(connection, table):
        return set()
    return {
        str(row["name"])
        for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
    }


def _require_columns(
    connection: sqlite3.Connection,
    table: str,
    required: Iterable[str],
) -> set[str]:
    columns = _table_columns(connection, table)
    missing = set(required) - columns
    if missing:
        raise CohortError(
            f"alert database schema is missing {table} columns: "
            + ", ".join(sorted(missing))
        )
    return columns


def schema_fingerprint(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        """
        SELECT type, name, tbl_name, COALESCE(sql, '') AS sql
        FROM sqlite_master
        WHERE type IN ('table', 'index')
          AND name IN (
            'alert_group_summary', 'alert_group_alias',
            'incident_response_cases', 'incident_reanalysis_runs',
            'incident_reanalysis_run_cases', 'durable_jobs',
            'ai_analysis_runs', 'ai_second_opinion_runs'
          )
        ORDER BY type, name
        """
    ).fetchall()
    return sha256_value([dict(row) for row in rows])


def load_aliases(connection: sqlite3.Connection) -> dict[str, str]:
    _require_columns(
        connection,
        "alert_group_alias",
        {"legacy_group_id", "stable_group_id"},
    )
    aliases: dict[str, str] = {}
    for row in connection.execute(
        """
        SELECT legacy_group_id, stable_group_id
        FROM alert_group_alias
        ORDER BY legacy_group_id
        """
    ):
        legacy = str(row["legacy_group_id"] or "").strip().lower()
        stable = str(row["stable_group_id"] or "").strip().lower()
        if not legacy or not stable:
            raise CohortError("alert_group_alias contains a blank identity")
        aliases[legacy] = stable
    return aliases


def resolve_alias(identity: str, aliases: Mapping[str, str]) -> str:
    current = str(identity or "").strip().lower()
    visited: set[str] = set()
    while current in aliases:
        if current in visited:
            raise CohortError(f"cycle detected in alert group aliases at {current}")
        visited.add(current)
        current = str(aliases[current] or "").strip().lower()
    return current


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


def _summary_rows(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    columns = _require_columns(
        connection,
        "alert_group_summary",
        {"group_id", "representative_alert_id", "last_seen"},
    )
    selected = [item for item in SUMMARY_EXPORT_COLUMNS if item in columns]
    time_candidates = [
        item for item in ("last_seen", "timestamp", "first_seen", "updated_at")
        if item in columns
    ]
    time_expression = "COALESCE(" + ", ".join(
        f"NULLIF({item}, '')" for item in time_candidates
    ) + ")"
    sql = (
        "SELECT "
        + ", ".join(selected)
        + f", {time_expression} AS cohort_seen_at "
        + "FROM alert_group_summary "
        + f"ORDER BY replace(replace({time_expression}, 'T', ' '), 'Z', '') DESC, "
        + "group_id DESC"
    )
    return [dict(row) for row in connection.execute(sql).fetchall()]


CASE_COLUMNS = (
    "case_id",
    "group_id",
    "dashboard_group_id",
    "representative_alert_id",
    "status",
    "agent_status",
    "escalated_at",
    "updated_at",
    "latest_analysis_id",
    "latest_model",
    "latest_generated_at",
)


def _incident_cases(
    connection: sqlite3.Connection,
    aliases: Mapping[str, str],
) -> dict[str, list[dict[str, Any]]]:
    columns = _require_columns(
        connection,
        "incident_response_cases",
        {
            "case_id",
            "group_id",
            "dashboard_group_id",
            "representative_alert_id",
            "status",
            "agent_status",
            "latest_analysis_id",
        },
    )
    selected = [item for item in CASE_COLUMNS if item in columns]
    by_stable: dict[str, list[dict[str, Any]]] = {}
    for row in connection.execute(
        "SELECT " + ", ".join(selected) + " FROM incident_response_cases"
    ):
        item = dict(row)
        stable = resolve_alias(str(item.get("group_id") or ""), aliases)
        by_stable.setdefault(stable, []).append(item)
    return by_stable


def _active_jobs(
    connection: sqlite3.Connection,
    stable_group_id: str,
    aliases: Mapping[str, str],
    *,
    job_type: str = "incident_response_analysis",
) -> list[dict[str, Any]]:
    if job_type not in {"incident_response_analysis", "ai_analysis"}:
        raise CohortError(f"unsupported durable job type: {job_type}")
    _require_columns(
        connection,
        "durable_jobs",
        {
            "id",
            "job_type",
            "dedupe_key",
            "status",
            "attempt_count",
            "requested_at",
            "updated_at",
        },
    )
    rows = connection.execute(
        """
        SELECT id, job_type, dedupe_key, status, attempt_count,
               requested_at, updated_at
        FROM durable_jobs
        WHERE job_type = ?
          AND status IN ('pending', 'processing')
        ORDER BY id
        """,
        (job_type,),
    ).fetchall()
    return [
        dict(row)
        for row in rows
        if resolve_alias(str(row["dedupe_key"] or ""), aliases) == stable_group_id
    ]


def _durable_job_snapshot(
    connection: sqlite3.Connection,
    *,
    job_type: str,
    stable_group_id: str,
) -> dict[str, Any] | None:
    if job_type not in {"incident_response_analysis", "ai_analysis"}:
        raise CohortError(f"unsupported durable job type: {job_type}")
    _require_columns(
        connection,
        "durable_jobs",
        {
            "id",
            "job_type",
            "dedupe_key",
            "status",
            "attempt_count",
            "requested_at",
            "updated_at",
        },
    )
    row = connection.execute(
        """
        SELECT id, job_type, dedupe_key, status, attempt_count,
               requested_at, updated_at, completed_at, last_completed_at
        FROM durable_jobs
        WHERE job_type = ? AND dedupe_key = ?
        """,
        (job_type, stable_group_id),
    ).fetchone()
    return dict(row) if row else None


def _active_reanalysis(
    connection: sqlite3.Connection,
    stable_group_id: str,
    case_id: str,
    aliases: Mapping[str, str],
) -> list[dict[str, Any]]:
    _require_columns(
        connection,
        "incident_reanalysis_run_cases",
        {
            "run_id",
            "case_id",
            "group_id",
            "dashboard_group_id",
            "representative_alert_id",
            "status",
            "updated_at",
        },
    )
    rows = connection.execute(
        """
        SELECT run_id, case_id, group_id, dashboard_group_id,
               representative_alert_id, status, updated_at
        FROM incident_reanalysis_run_cases
        WHERE status IN ('queued', 'running')
        ORDER BY updated_at, run_id
        """
    ).fetchall()
    output = []
    for row in rows:
        if case_id and str(row["case_id"] or "") == case_id:
            output.append(dict(row))
        elif (
            resolve_alias(str(row["group_id"] or ""), aliases)
            == stable_group_id
        ):
            output.append(dict(row))
    return output


def _analysis_ids_for_group(
    connection: sqlite3.Connection,
    stable_group_id: str,
    *,
    agent_role: str,
) -> list[str]:
    _require_columns(
        connection,
        "ai_analysis_runs",
        {"analysis_id", "group_id", "agent_role", "generated_at"},
    )
    rows = connection.execute(
        """
        SELECT analysis_id
        FROM ai_analysis_runs
        WHERE group_id = ? AND agent_role = ?
        ORDER BY generated_at, analysis_id
        LIMIT 10001
        """,
        (stable_group_id, agent_role),
    ).fetchall()
    if len(rows) > 10000:
        raise CohortError(
            f"stable group {stable_group_id} has too many prior analyses "
            "for an exact bounded cohort"
        )
    identities = [str(row["analysis_id"] or "") for row in rows]
    if any(not item for item in identities) or len(identities) != len(
        set(identities)
    ):
        raise CohortError(
            f"stable group {stable_group_id} has invalid analysis identities"
        )
    return identities


def _soc_pre_state(
    connection: sqlite3.Connection,
    stable_group_id: str,
    aliases: Mapping[str, str],
) -> dict[str, Any]:
    active_jobs = _active_jobs(
        connection,
        stable_group_id,
        aliases,
        job_type="ai_analysis",
    )
    if active_jobs:
        raise CohortError(
            f"stable group {stable_group_id} already has a pending/processing "
            "SOC Analyst job"
        )
    analysis_ids = _analysis_ids_for_group(
        connection,
        stable_group_id,
        agent_role="soc-analyst",
    )
    latest = (
        _latest_analysis_metadata(connection, analysis_ids[-1])
        if analysis_ids
        else None
    )
    return {
        "soc_analysis_ids": analysis_ids,
        "latest_analysis": latest,
        "active_ai_jobs": [],
    }


def _latest_analysis_metadata(
    connection: sqlite3.Connection,
    analysis_id: str,
) -> dict[str, Any] | None:
    if not analysis_id or not _table_exists(connection, "ai_analysis_runs"):
        return None
    columns = _table_columns(connection, "ai_analysis_runs")
    allowed = [
        item
        for item in (
            "analysis_id",
            "group_id",
            "alert_id",
            "agent_role",
            "generated_at",
            "model",
            "model_path",
            "detection_outcome",
            "confidence",
            "evidence_hash",
            "created_at",
        )
        if item in columns
    ]
    if "analysis_id" not in allowed:
        return None
    row = connection.execute(
        "SELECT " + ", ".join(allowed)
        + " FROM ai_analysis_runs WHERE analysis_id = ?",
        (analysis_id,),
    ).fetchone()
    return dict(row) if row else None


def _pre_state(
    connection: sqlite3.Connection,
    stable_group_id: str,
    aliases: Mapping[str, str],
    cases_by_stable: Mapping[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    cases = list(cases_by_stable.get(stable_group_id, []))
    if len(cases) > 1:
        raise CohortError(
            f"multiple incident cases resolve to stable group {stable_group_id}"
        )
    case = cases[0] if cases else None
    if case and str(case.get("agent_status") or "") in ACTIVE_AGENT_STATES:
        raise CohortError(
            f"incident case {case.get('case_id')} is already "
            f"{case.get('agent_status')}"
        )
    active_jobs = _active_jobs(connection, stable_group_id, aliases)
    if active_jobs:
        raise CohortError(
            f"stable group {stable_group_id} already has a pending/processing "
            "Incident Responder job"
        )
    active_runs = _active_reanalysis(
        connection,
        stable_group_id,
        str((case or {}).get("case_id") or ""),
        aliases,
    )
    if active_runs:
        raise CohortError(
            f"stable group {stable_group_id} already has a queued/running "
            "reanalysis"
        )
    latest_analysis_id = str((case or {}).get("latest_analysis_id") or "")
    return {
        "incident_case": case,
        "latest_analysis": _latest_analysis_metadata(
            connection,
            latest_analysis_id,
        ),
        "active_incident_jobs": [],
        "active_reanalysis_cases": [],
    }


def freeze_cohort(
    database_path: Path,
    manifest_path: Path,
    *,
    cohort_id: str,
    reason: str,
    count: int,
    expected_assigned_route: str = "codex-cli:gpt-5.6-sol:high",
    expected_reviewer_route: str = "",
    dry_run: bool = False,
) -> dict[str, Any]:
    cohort_id, reason = validate_cohort_identity(cohort_id, reason)
    if count < 1 or count > MAX_COHORT_SIZE:
        raise CohortError(f"cohort size must be between 1 and {MAX_COHORT_SIZE}")
    if manifest_path.expanduser().exists() and not dry_run:
        raise CohortError(f"manifest already exists: {manifest_path.expanduser()}")

    connection = connect_read_only(database_path)
    try:
        connection.execute("BEGIN")
        aliases = load_aliases(connection)
        cases_by_stable = _incident_cases(connection, aliases)
        selected: list[dict[str, Any]] = []
        selected_stable: set[str] = set()
        for summary in _summary_rows(connection):
            dashboard_id = str(summary.get("group_id") or "").strip().lower()
            if not DASHBOARD_GROUP_ID_RE.fullmatch(dashboard_id):
                raise CohortError(
                    f"invalid dashboard group identity in summary: {dashboard_id!r}"
                )
            if dashboard_id not in aliases:
                raise CohortError(
                    f"dashboard group {dashboard_id} has no stable alias"
                )
            stable_id = resolve_alias(dashboard_id, aliases)
            if not STABLE_GROUP_ID_RE.fullmatch(stable_id):
                raise CohortError(
                    f"dashboard group {dashboard_id} resolves to invalid "
                    f"stable identity {stable_id!r}"
                )
            if stable_id in selected_stable:
                continue
            representative_alert_id = str(
                summary.get("representative_alert_id") or ""
            ).strip()
            if not representative_alert_id:
                raise CohortError(
                    f"dashboard group {dashboard_id} has no representative alert"
                )
            pre_state = _pre_state(
                connection,
                stable_id,
                aliases,
                cases_by_stable,
            )
            selected_stable.add(stable_id)
            selected.append(
                {
                    "rank": len(selected) + 1,
                    "dashboard_group_id": dashboard_id,
                    "stable_group_id": stable_id,
                    "representative_alert_id": representative_alert_id,
                    "detection": {
                        key: value
                        for key, value in summary.items()
                        if key != "group_id"
                    },
                    "pre_state": pre_state,
                    "dispatch": {
                        "kind": (
                            "reanalyze"
                            if pre_state["incident_case"]
                            else "escalate"
                        ),
                        "state": "unattempted",
                        "attempt_count": 0,
                    },
                    "monitor": {"state": "not_started"},
                }
            )
            if len(selected) == count:
                break
        if len(selected) != count:
            raise CohortError(
                f"requested {count} distinct stable groups but only "
                f"{len(selected)} were available"
            )
        identities = ordered_identity_projection(selected)
        manifest: dict[str, Any] = {
            "schema": SCHEMA,
            "cohort_id": cohort_id,
            "reason": reason,
            "agent_role": "incident-responder",
            "count": count,
            "created_at": utc_now(),
            "selection": {
                "mode": "database_newest",
                "source_sha256": sha256_value(identities),
                "source_count": len(identities),
                "order_preserved": True,
                "ordered_identity_sha256": sha256_value(identities),
            },
            "execution_contract": execution_contract(
                expected_assigned_route=expected_assigned_route,
                expected_reviewer_route=expected_reviewer_route,
            ),
            "database": {
                "path": str(database_path.expanduser().resolve()),
                "schema_sha256": schema_fingerprint(connection),
                "user_version": int(
                    connection.execute("PRAGMA user_version").fetchone()[0]
                ),
                "read_only": True,
            },
            "security_onion_access": "none",
            "state": "frozen",
            "members": selected,
        }
        manifest["frozen_plan_sha256"] = _frozen_plan_digest(manifest)
    finally:
        connection.close()
    if dry_run:
        return _digest_bound(manifest, "manifest_sha256")
    return write_private_json(
        manifest_path,
        manifest,
        digest_field="manifest_sha256",
        replace=False,
    )


def _source_identity(row: Mapping[str, Any]) -> tuple[str, str, str]:
    dashboard_id = str(
        row.get("dashboard_group_id")
        or row.get("legacy_group_id")
        or row.get("group_id")
        or ""
    ).strip().lower()
    stable_id = str(row.get("stable_group_id") or "").strip().lower()
    representative_alert_id = str(
        row.get("representative_alert_id") or ""
    ).strip()
    if not DASHBOARD_GROUP_ID_RE.fullmatch(dashboard_id):
        raise CohortError(
            f"source row has invalid dashboard group ID: {dashboard_id!r}"
        )
    if not STABLE_GROUP_ID_RE.fullmatch(stable_id):
        raise CohortError(
            f"source row has invalid stable group ID: {stable_id!r}"
        )
    if not representative_alert_id:
        raise CohortError(
            f"source row {dashboard_id} has no representative alert ID"
        )
    return dashboard_id, stable_id, representative_alert_id


def _validate_source_detection(
    source: Mapping[str, Any],
    current: Mapping[str, Any],
    dashboard_id: str,
) -> None:
    supplied_detection = source.get("detection")
    if supplied_detection is not None and not isinstance(
        supplied_detection,
        dict,
    ):
        raise CohortError(
            f"source row {dashboard_id} detection must be an object"
        )
    comparisons: dict[str, Any] = {}
    for key in SUMMARY_EXPORT_COLUMNS:
        if key == "group_id":
            continue
        if key in source:
            comparisons[key] = source[key]
        if isinstance(supplied_detection, dict) and key in supplied_detection:
            comparisons[key] = supplied_detection[key]
    if "cohort_seen_at" in source:
        comparisons["cohort_seen_at"] = source["cohort_seen_at"]
    if (
        isinstance(supplied_detection, dict)
        and "cohort_seen_at" in supplied_detection
    ):
        comparisons["cohort_seen_at"] = supplied_detection["cohort_seen_at"]
    for key, value in comparisons.items():
        if current.get(key) != value:
            raise CohortError(
                f"source row {dashboard_id} no longer matches frozen "
                f"detection field {key}"
            )


def _validate_source_pre_state(
    source: Mapping[str, Any],
    current: Mapping[str, Any],
    dashboard_id: str,
) -> None:
    if "pre_state" in source and source["pre_state"] != current:
        raise CohortError(
            f"source row {dashboard_id} pre-state changed after selection"
        )
    case = current.get("incident_case") or {}
    aliases = {
        "case_id": "case_id",
        "case_status": "status",
        "case_agent_status": "agent_status",
        "latest_analysis_id": "latest_analysis_id",
    }
    for source_key, case_key in aliases.items():
        if source_key in source and source[source_key] != case.get(case_key):
            raise CohortError(
                f"source row {dashboard_id} no longer matches {source_key}"
            )


def freeze_cohort_from_rows(
    database_path: Path,
    source_rows_path: Path,
    manifest_path: Path,
    *,
    cohort_id: str,
    reason: str,
    expected_count: int,
    agent_role: str = "incident-responder",
    expected_assigned_route: str = "codex-cli:gpt-5.6-sol:high",
    expected_reviewer_route: str = "",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Import exact preselected identities; never recompute cohort membership."""

    cohort_id, reason = validate_cohort_identity(cohort_id, reason)
    agent_role = validate_agent_role(agent_role)
    if expected_count < 1 or expected_count > MAX_COHORT_SIZE:
        raise CohortError(
            f"expected count must be between 1 and {MAX_COHORT_SIZE}"
        )
    rows, source_sha256 = load_private_source_rows(source_rows_path)
    if len(rows) != expected_count:
        raise CohortError(
            f"source contains {len(rows)} rows; expected {expected_count}"
        )
    if manifest_path.expanduser().exists() and not dry_run:
        raise CohortError(f"manifest already exists: {manifest_path.expanduser()}")

    connection = connect_read_only(database_path)
    try:
        connection.execute("BEGIN")
        aliases = load_aliases(connection)
        cases_by_stable = _incident_cases(connection, aliases)
        summaries = {
            str(item.get("group_id") or ""): item
            for item in _summary_rows(connection)
        }
        members: list[dict[str, Any]] = []
        seen_dashboard: set[str] = set()
        seen_stable: set[str] = set()
        for index, source in enumerate(rows):
            dashboard_id, stable_id, representative_alert_id = (
                _source_identity(source)
            )
            if dashboard_id in seen_dashboard:
                raise CohortError(
                    f"source repeats dashboard group {dashboard_id}"
                )
            if stable_id in seen_stable:
                raise CohortError(
                    f"source repeats stable group {stable_id}"
                )
            current = summaries.get(dashboard_id)
            if not current:
                raise CohortError(
                    f"source dashboard group no longer exists: {dashboard_id}"
                )
            resolved = resolve_alias(dashboard_id, aliases)
            if resolved != stable_id:
                raise CohortError(
                    f"source stable identity changed for {dashboard_id}"
                )
            if (
                str(current.get("representative_alert_id") or "")
                != representative_alert_id
            ):
                raise CohortError(
                    f"source representative alert changed for {dashboard_id}"
                )
            _validate_source_detection(source, current, dashboard_id)
            if agent_role == "soc-analyst":
                pre_state = _soc_pre_state(
                    connection,
                    stable_id,
                    aliases,
                )
            else:
                pre_state = _pre_state(
                    connection,
                    stable_id,
                    aliases,
                    cases_by_stable,
                )
                _validate_source_pre_state(source, pre_state, dashboard_id)
            seen_dashboard.add(dashboard_id)
            seen_stable.add(stable_id)
            members.append(
                {
                    "rank": index + 1,
                    "dashboard_group_id": dashboard_id,
                    "stable_group_id": stable_id,
                    "representative_alert_id": representative_alert_id,
                    "detection": {
                        key: value
                        for key, value in current.items()
                        if key != "group_id"
                    },
                    "pre_state": pre_state,
                    "dispatch": {
                        "kind": (
                            "analyze"
                            if agent_role == "soc-analyst"
                            else (
                                "reanalyze"
                                if pre_state["incident_case"]
                                else "escalate"
                            )
                        ),
                        "state": "unattempted",
                        "attempt_count": 0,
                    },
                    "monitor": {"state": "not_started"},
                }
            )
        identities = ordered_identity_projection(members)
        manifest: dict[str, Any] = {
            "schema": SCHEMA,
            "cohort_id": cohort_id,
            "reason": reason,
            "agent_role": agent_role,
            "count": expected_count,
            "created_at": utc_now(),
            "selection": {
                "mode": "imported_rows",
                "source_sha256": source_sha256,
                "source_count": len(rows),
                "order_preserved": True,
                "ordered_identity_sha256": sha256_value(identities),
            },
            "execution_contract": execution_contract(
                expected_assigned_route=expected_assigned_route,
                expected_reviewer_route=expected_reviewer_route,
            ),
            "database": {
                "path": str(database_path.expanduser().resolve()),
                "schema_sha256": schema_fingerprint(connection),
                "user_version": int(
                    connection.execute("PRAGMA user_version").fetchone()[0]
                ),
                "read_only": True,
            },
            "security_onion_access": "none",
            "state": "frozen",
            "members": members,
        }
        manifest["frozen_plan_sha256"] = _frozen_plan_digest(manifest)
    finally:
        connection.close()
    if dry_run:
        return _digest_bound(manifest, "manifest_sha256")
    return write_private_json(
        manifest_path,
        manifest,
        digest_field="manifest_sha256",
        replace=False,
    )


def _current_summary_identity(
    connection: sqlite3.Connection,
    dashboard_group_id: str,
    aliases: Mapping[str, str],
) -> tuple[str, str] | None:
    row = connection.execute(
        """
        SELECT group_id, representative_alert_id
        FROM alert_group_summary
        WHERE group_id = ?
        """,
        (dashboard_group_id,),
    ).fetchone()
    if not row:
        return None
    return (
        resolve_alias(str(row["group_id"] or ""), aliases),
        str(row["representative_alert_id"] or ""),
    )


def _case_for_stable(
    connection: sqlite3.Connection,
    stable_group_id: str,
    aliases: Mapping[str, str],
) -> dict[str, Any] | None:
    cases = _incident_cases(connection, aliases).get(stable_group_id, [])
    if len(cases) > 1:
        raise CohortError(
            f"multiple incident cases resolve to {stable_group_id}"
        )
    return cases[0] if cases else None


def validate_member_preflight(
    connection: sqlite3.Connection,
    member: Mapping[str, Any],
) -> None:
    aliases = load_aliases(connection)
    dashboard_id = str(member["dashboard_group_id"])
    stable_id = str(member["stable_group_id"])
    identity = _current_summary_identity(connection, dashboard_id, aliases)
    if identity is None:
        raise CohortError(f"frozen dashboard group disappeared: {dashboard_id}")
    if identity != (
        stable_id,
        str(member["representative_alert_id"]),
    ):
        raise CohortError(
            f"frozen identity drift for dashboard group {dashboard_id}"
        )
    if str((member.get("dispatch") or {}).get("kind") or "") == "analyze":
        current_soc_state = _soc_pre_state(
            connection,
            stable_id,
            aliases,
        )
        if current_soc_state != (member.get("pre_state") or {}):
            raise CohortError(
                f"SOC Analyst pre-state changed for stable group {stable_id}"
            )
        return
    pre_case = (member.get("pre_state") or {}).get("incident_case")
    current_case = _case_for_stable(connection, stable_id, aliases)
    if current_case != pre_case:
        raise CohortError(
            f"incident case pre-state changed for stable group {stable_id}"
        )
    if current_case and str(current_case.get("agent_status") or "") in ACTIVE_AGENT_STATES:
        raise CohortError(
            f"incident case {current_case.get('case_id')} became active"
        )
    if _active_jobs(connection, stable_id, aliases):
        raise CohortError(
            f"stable group {stable_id} has a pending/processing job"
        )
    if _active_reanalysis(
        connection,
        stable_id,
        str((current_case or {}).get("case_id") or ""),
        aliases,
    ):
        raise CohortError(
            f"stable group {stable_id} has a queued/running reanalysis"
        )


def validate_frozen_cohort(
    database_path: Path,
    manifest: Mapping[str, Any],
) -> None:
    connection = connect_read_only(database_path)
    try:
        connection.execute("BEGIN")
        if (
            schema_fingerprint(connection)
            != (manifest.get("database") or {}).get("schema_sha256")
        ):
            raise CohortError("alert database schema changed after cohort freeze")
        for member in manifest["members"]:
            validate_member_preflight(connection, member)
    finally:
        connection.close()


def validate_loopback_base_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(str(value or "").strip())
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise CohortError(
            "dashboard base URL must be a plain loopback HTTP origin"
        )
    try:
        port = parsed.port
    except ValueError as exc:
        raise CohortError("dashboard base URL has an invalid port") from exc
    if port is None:
        raise CohortError("dashboard base URL must include an explicit port")
    rendered_host = (
        f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    )
    return f"http://{rendered_host}:{port}"


class HttpResult:
    def __init__(self, status: int, payload: Any, body_sha256: str):
        self.status = status
        self.payload = payload
        self.body_sha256 = body_sha256


def dashboard_post_json(
    url: str,
    payload: Mapping[str, Any],
    *,
    timeout: float,
) -> HttpResult:
    body = canonical_bytes(payload)
    origin = urllib.parse.urlunsplit(
        (*urllib.parse.urlsplit(url)[:2], "", "", "")
    )
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": origin,
            "Sec-Fetch-Site": "same-origin",
            "X-Onion-Sentinel-Request": "dashboard",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = int(response.status)
            raw = response.read(MAX_HTTP_BODY_BYTES + 1)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        try:
            raw = exc.read(MAX_HTTP_BODY_BYTES + 1)
        except OSError as read_error:
            raise AmbiguousDispatchError(
                "dashboard error response could not be read"
            ) from read_error
        finally:
            exc.close()
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        raise AmbiguousDispatchError(
            f"dashboard request outcome is ambiguous: {type(exc).__name__}"
        ) from exc
    if len(raw) > MAX_HTTP_BODY_BYTES:
        raise AmbiguousDispatchError(
            "dashboard response exceeded the bounded response size"
        )
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        parsed = None
    return HttpResult(status, parsed, hashlib.sha256(raw).hexdigest())


def _request_for_member(
    base_url: str,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> tuple[str, dict[str, Any]]:
    cohort_id = str(manifest["cohort_id"])
    reason = f"[cohort:{cohort_id}] {manifest['reason']}"[:1000]
    requested_by = f"harness-cohort:{cohort_id}"[:100]
    dispatch_kind = str((member.get("dispatch") or {}).get("kind") or "")
    if dispatch_kind == "escalate":
        path = (
            "/api/soc-alerts/"
            + urllib.parse.quote(str(member["dashboard_group_id"]), safe="")
            + "/escalate"
        )
        payload = {
            "reason": reason,
            "requested_by": requested_by,
            "related_limit": 500,
            "pcap_analysis_limit": 25,
        }
    elif dispatch_kind == "analyze":
        path = (
            "/api/soc-alerts/"
            + urllib.parse.quote(str(member["dashboard_group_id"]), safe="")
            + "/analyze"
        )
        payload = {
            "reason": reason,
            "requested_by": requested_by,
            "related_limit": 500,
            "pcap_analysis_limit": 25,
        }
    elif dispatch_kind == "reanalyze":
        case_id = str(
            ((member.get("pre_state") or {}).get("incident_case") or {}).get(
                "case_id"
            )
            or ""
        )
        if not CASE_ID_RE.fullmatch(case_id):
            raise CohortError(f"invalid frozen incident case ID: {case_id!r}")
        path = (
            "/api/soc-incidents/"
            + urllib.parse.quote(case_id, safe="")
            + "/reanalyze"
        )
        payload = {"reason": reason, "requested_by": requested_by}
    else:
        raise CohortError(f"unsupported dispatch kind: {dispatch_kind!r}")
    return base_url + path, payload


def _validate_success_response(
    member: Mapping[str, Any],
    result: HttpResult,
) -> dict[str, Any]:
    if result.status != 202:
        if 400 <= result.status < 500 and result.status not in {408, 425}:
            raise CohortError(
                f"dashboard rejected request with HTTP {result.status}"
            )
        raise AmbiguousDispatchError(
            f"dashboard returned ambiguous HTTP {result.status}"
        )
    payload = result.payload
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise AmbiguousDispatchError(
            "dashboard returned an invalid success response"
        )
    kind = str((member.get("dispatch") or {}).get("kind") or "")
    accepted: dict[str, Any] = {
        "http_status": result.status,
        "response_sha256": result.body_sha256,
    }
    if kind == "escalate":
        expected = {
            "group_id": member["dashboard_group_id"],
            "queue_group_id": member["stable_group_id"],
            "representative_alert_id": member["representative_alert_id"],
        }
        if any(str(payload.get(key) or "") != str(value) for key, value in expected.items()):
            raise AmbiguousDispatchError(
                "escalation response identity did not match the frozen member"
            )
        case_id = str(payload.get("case_id") or "")
        if not CASE_ID_RE.fullmatch(case_id):
            raise AmbiguousDispatchError(
                "escalation response did not contain a valid case ID"
            )
        accepted.update(
            {
                **expected,
                "case_id": case_id,
                "requested_at": str(payload.get("requested_at") or ""),
            }
        )
    elif kind == "analyze":
        expected = {
            "group_id": member["dashboard_group_id"],
            "queue_group_id": member["stable_group_id"],
            "representative_alert_id": member["representative_alert_id"],
        }
        if any(
            str(payload.get(key) or "") != str(value)
            for key, value in expected.items()
        ):
            raise AmbiguousDispatchError(
                "SOC analysis response identity did not match the frozen member"
            )
        requested_at = str(payload.get("requested_at") or "")
        if not requested_at:
            raise AmbiguousDispatchError(
                "SOC analysis response did not include requested_at"
            )
        accepted.update({**expected, "requested_at": requested_at})
    elif kind == "reanalyze":
        run_id = str(payload.get("run_id") or "")
        try:
            total_count = int(payload.get("total_count") or 0)
        except (TypeError, ValueError) as exc:
            raise AmbiguousDispatchError(
                "reanalysis response has an invalid case count"
            ) from exc
        if (
            not RUN_ID_RE.fullmatch(run_id)
            or str(payload.get("scope") or "") != "single_case"
            or total_count != 1
        ):
            raise AmbiguousDispatchError(
                "reanalysis response did not identify one exact single-case run"
            )
        case_id = str(
            ((member.get("pre_state") or {}).get("incident_case") or {}).get(
                "case_id"
            )
            or ""
        )
        accepted.update(
            {
                "run_id": run_id,
                "case_id": case_id,
                "release_id": str(payload.get("release_id") or ""),
                "run_status": str(payload.get("status") or ""),
                "created_at": str(payload.get("created_at") or ""),
            }
        )
    else:
        raise CohortError(f"unsupported dispatch kind: {kind!r}")
    return accepted


def _verify_dispatch_readback(
    database_path: Path,
    member: Mapping[str, Any],
    accepted: Mapping[str, Any],
) -> dict[str, Any]:
    connection = connect_read_only(database_path)
    try:
        aliases = load_aliases(connection)
        stable_id = str(member["stable_group_id"])
        kind = str((member.get("dispatch") or {}).get("kind") or "")
        if kind == "analyze":
            prior_ids = set(
                (member.get("pre_state") or {}).get("soc_analysis_ids") or []
            )
            current_ids = set(
                _analysis_ids_for_group(
                    connection,
                    stable_id,
                    agent_role="soc-analyst",
                )
            )
            new_ids = sorted(current_ids - prior_ids)
            active_jobs = _active_jobs(
                connection,
                stable_id,
                aliases,
                job_type="ai_analysis",
            )
            if current_ids & prior_ids != prior_ids:
                raise AmbiguousDispatchError(
                    "prior SOC analysis identities changed during dispatch"
                )
            if len(new_ids) > 1 or (not new_ids and not active_jobs):
                raise AmbiguousDispatchError(
                    "SOC analysis acceptance could not be bound to one exact job"
                )
            return {
                "stable_group_id": stable_id,
                "dashboard_group_id": str(member["dashboard_group_id"]),
                "representative_alert_id": str(
                    member["representative_alert_id"]
                ),
                "job_status": (
                    str(active_jobs[0]["status"]) if active_jobs else "completed"
                ),
                "analysis_id": new_ids[0] if new_ids else "",
            }
        case_id = str(accepted["case_id"])
        case = _case_for_stable(connection, stable_id, aliases)
        if (
            not case
            or str(case.get("case_id") or "") != case_id
            or str(case.get("dashboard_group_id") or "")
            != str(member["dashboard_group_id"])
            or str(case.get("representative_alert_id") or "")
            != str(member["representative_alert_id"])
            or str(case.get("agent_status") or "")
            not in {"queued", "analyzing", "analyzed", "failed"}
        ):
            raise AmbiguousDispatchError(
                "dashboard accepted the request but exact case readback failed"
            )
        output = {
            "case_id": case_id,
            "stable_group_id": stable_id,
            "dashboard_group_id": str(member["dashboard_group_id"]),
            "representative_alert_id": str(member["representative_alert_id"]),
            "agent_status": str(case.get("agent_status") or ""),
        }
        if kind == "reanalyze":
            run_id = str(accepted.get("run_id") or "")
            row = connection.execute(
                """
                SELECT run_id, case_id, group_id, dashboard_group_id,
                       representative_alert_id, status, queued_at, updated_at
                FROM incident_reanalysis_run_cases
                WHERE run_id = ? AND case_id = ?
                """,
                (run_id, case_id),
            ).fetchone()
            if (
                not row
                or resolve_alias(str(row["group_id"] or ""), aliases) != stable_id
                or str(row["dashboard_group_id"] or "")
                != str(member["dashboard_group_id"])
                or str(row["representative_alert_id"] or "")
                != str(member["representative_alert_id"])
                or str(row["status"] or "")
                not in {"queued", "running", "completed", "failed", "skipped"}
            ):
                raise AmbiguousDispatchError(
                    "dashboard accepted reanalysis but exact run readback failed"
                )
            output.update(
                {
                    "run_id": run_id,
                    "run_case_status": str(row["status"]),
                    "queued_at": str(row["queued_at"] or ""),
                }
            )
        return output
    finally:
        connection.close()


Poster = Callable[[str, Mapping[str, Any]], HttpResult]


def queue_cohort(
    database_path: Path,
    manifest_path: Path,
    *,
    base_url: str,
    timeout: float = 15.0,
    dry_run: bool = False,
    poster: Poster | None = None,
) -> dict[str, Any]:
    manifest = load_private_manifest(manifest_path)
    base_url = validate_loopback_base_url(base_url)
    states = {
        str((member.get("dispatch") or {}).get("state") or "")
        for member in manifest["members"]
    }
    if states == {"accepted"}:
        return manifest
    if states != {"unattempted"}:
        raise CohortError(
            "cohort contains a prior, partial, rejected, dispatching, or "
            "ambiguous dispatch; refusing to send another request"
        )
    validate_frozen_cohort(database_path, manifest)
    if dry_run:
        return manifest

    def do_post(url: str, payload: Mapping[str, Any]) -> HttpResult:
        if poster is not None:
            return poster(url, payload)
        return dashboard_post_json(url, payload, timeout=timeout)

    manifest["state"] = "queueing"
    manifest["queue_started_at"] = utc_now()
    manifest = write_private_json(
        manifest_path,
        manifest,
        digest_field="manifest_sha256",
    )
    for index, member in enumerate(manifest["members"]):
        connection = connect_read_only(database_path)
        try:
            validate_member_preflight(connection, member)
        finally:
            connection.close()
        url, payload = _request_for_member(base_url, manifest, member)
        dispatch = member["dispatch"]
        dispatch.update(
            {
                "state": "dispatching",
                "attempt_count": 1,
                "started_at": utc_now(),
                "request_path": urllib.parse.urlsplit(url).path,
                "request_sha256": sha256_value(payload),
            }
        )
        manifest["members"][index] = member
        manifest = write_private_json(
            manifest_path,
            manifest,
            digest_field="manifest_sha256",
        )
        try:
            result = do_post(url, payload)
            accepted = _validate_success_response(member, result)
            readback = _verify_dispatch_readback(
                database_path,
                member,
                accepted,
            )
        except AmbiguousDispatchError as exc:
            dispatch.update(
                {
                    "state": "ambiguous",
                    "finished_at": utc_now(),
                    "error_type": type(exc).__name__,
                    "error_digest": sha256_value(str(exc)),
                }
            )
            manifest["state"] = "dispatch_ambiguous"
            manifest["members"][index] = member
            write_private_json(
                manifest_path,
                manifest,
                digest_field="manifest_sha256",
            )
            raise
        except CohortError as exc:
            dispatch.update(
                {
                    "state": "rejected",
                    "finished_at": utc_now(),
                    "error_type": type(exc).__name__,
                    "error_digest": sha256_value(str(exc)),
                }
            )
            manifest["state"] = "dispatch_rejected"
            manifest["members"][index] = member
            write_private_json(
                manifest_path,
                manifest,
                digest_field="manifest_sha256",
            )
            raise
        dispatch.update(
            {
                "state": "accepted",
                "finished_at": utc_now(),
                "accepted": accepted,
                "readback": readback,
            }
        )
        manifest["members"][index] = member
        manifest = write_private_json(
            manifest_path,
            manifest,
            digest_field="manifest_sha256",
        )
    manifest["state"] = "queued"
    manifest["queue_completed_at"] = utc_now()
    return write_private_json(
        manifest_path,
        manifest,
        digest_field="manifest_sha256",
    )


def _analysis_metadata(
    connection: sqlite3.Connection,
    analysis_id: str,
    stable_group_id: str,
    *,
    expected_agent_role: str = "incident-responder",
) -> dict[str, Any]:
    columns = _require_columns(
        connection,
        "ai_analysis_runs",
        {"analysis_id", "group_id", "agent_role", "response_json"},
    )
    allowed = [
        item
        for item in (
            "analysis_id",
            "group_id",
            "alert_id",
            "agent_role",
            "generated_at",
            "model",
            "model_path",
            "detection_outcome",
            "confidence",
            "evidence_hash",
            "created_at",
            "response_json",
        )
        if item in columns
    ]
    row = connection.execute(
        "SELECT " + ", ".join(allowed)
        + " FROM ai_analysis_runs WHERE analysis_id = ?",
        (analysis_id,),
    ).fetchone()
    if not row:
        raise CohortError(f"analysis result is missing: {analysis_id}")
    item = dict(row)
    if (
        str(item.get("group_id") or "") != stable_group_id
        or str(item.get("agent_role") or "") != expected_agent_role
    ):
        raise CohortError(
            f"analysis {analysis_id} is not bound to the frozen "
            f"{expected_agent_role} identity"
        )
    raw_response = str(item.pop("response_json", "") or "")
    item["response_bytes"] = len(raw_response.encode("utf-8"))
    item["response_sha256"] = hashlib.sha256(
        raw_response.encode("utf-8")
    ).hexdigest()
    try:
        response = json.loads(raw_response)
    except json.JSONDecodeError as exc:
        raise CohortError(
            f"analysis {analysis_id} response JSON is malformed"
        ) from exc
    if not isinstance(response, dict):
        raise CohortError(f"analysis {analysis_id} response is not an object")
    item["response_canonical_sha256"] = hashlib.sha256(
        json.dumps(
            response,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()
    item["result"] = {
        key: response.get(key)
        for key in (
            "event_status",
            "detection_validity",
            "activity_disposition",
            "handling",
            "duplicate_of",
            "final_disposition_status",
            "_analysis_model",
            "_analysis_model_path",
            "_analysis_provider",
            "_analysis_harness",
            "_analysis_model_route",
            "_analysis_input_mode",
            "_analysis_evaluation_memory_frozen",
        )
        if key in response
        and isinstance(response.get(key), (str, int, float, bool, type(None)))
    }
    item["query_audit"] = _bounded_query_audit_metadata(response)
    return item


def _bounded_query_audit_metadata(response: Mapping[str, Any]) -> dict[str, Any]:
    """Return evidence coverage metadata, never query text or result rows."""

    output: dict[str, Any] = {}
    for key in (
        "_incident_query_audit",
        "_incident_osquery_audit",
        "_incident_live_osquery_audit",
        "_incident_pcap_audit",
        "_incident_zeek_audit",
        "_investigation_query_audit",
    ):
        audit = response.get(key)
        if not isinstance(audit, dict):
            continue
        queries = audit.get("queries")
        safe_queries = []
        if isinstance(queries, list):
            for query in queries[:500]:
                if not isinstance(query, dict):
                    continue
                safe_queries.append(
                    {
                        field: query.get(field)
                        for field in (
                            "pack",
                            "query_id",
                            "backend",
                            "dialect",
                            "target_alias",
                            "status",
                            "query_digest",
                            "request_digest",
                            "result_digest",
                            "evidence_ref",
                            "total_hits",
                            "returned_hits",
                            "total_rows",
                            "returned_rows",
                            "truncated",
                            "partial",
                        )
                        if isinstance(
                            query.get(field),
                            (str, int, float, bool, type(None)),
                        )
                    }
                )
        safe_round_results: list[dict[str, Any]] = []
        safe_tool_call_bindings: list[dict[str, Any]] = []
        if key == "_investigation_query_audit":
            round_tool_call_bindings: list[dict[str, Any]] = []
            rounds = (
                audit.get("rounds")
                if isinstance(audit.get("rounds"), list)
                else []
            )
            for round_item in rounds[:10]:
                if not isinstance(round_item, dict):
                    continue
                for trusted in (
                    round_item.get("trusted_queries")
                    if isinstance(
                        round_item.get("trusted_queries"),
                        list,
                    )
                    else []
                ):
                    if not isinstance(trusted, dict):
                        continue
                    safe_queries.append(
                        {
                            field: trusted.get(field)
                            for field in (
                                "query_id",
                                "backend",
                                "dialect",
                                "pack",
                                "status",
                                "query_digest",
                                "request_digest",
                                "result_digest",
                                "evidence_ref",
                                "total_hits",
                                "returned_hits",
                                "total_rows",
                                "returned_rows",
                                "truncated",
                                "partial",
                            )
                            if isinstance(
                                trusted.get(field),
                                (
                                    str,
                                    int,
                                    float,
                                    bool,
                                    type(None),
                                ),
                            )
                        }
                    )
                for result in (
                    round_item.get("results")
                    if isinstance(round_item.get("results"), list)
                    else []
                ):
                    if not isinstance(result, dict):
                        continue
                    safe_round_results.append(
                        {
                            field: result.get(field)
                            for field in (
                                "query_id",
                                "backend",
                                "status",
                                "query_digest",
                            )
                            if isinstance(
                                result.get(field),
                                (
                                    str,
                                    int,
                                    float,
                                    bool,
                                    type(None),
                                ),
                            )
                        }
                    )
                round_tool_call_bindings.extend(
                    binding
                    for binding in (
                        round_item.get("tool_call_bindings")
                        if isinstance(
                            round_item.get("tool_call_bindings"),
                            list,
                        )
                        else []
                    )
                    if isinstance(binding, dict)
                )
            raw_tool_call_bindings = (
                audit.get("tool_call_bindings")
                if isinstance(audit.get("tool_call_bindings"), list)
                else round_tool_call_bindings
            )
            for binding in raw_tool_call_bindings:
                if not isinstance(binding, dict):
                    continue
                safe_tool_call_bindings.append(
                    {
                        field: binding.get(field)
                        for field in (
                            "call_id",
                            "round_number",
                            "query_id",
                            "backend",
                            "status",
                            "request_digest",
                            "result_digest",
                            "read_only",
                        )
                        if isinstance(
                            binding.get(field),
                            (
                                str,
                                int,
                                float,
                                bool,
                                type(None),
                            ),
                        )
                    }
                )
        output[key] = {
            field: audit.get(field)
            for field in (
                "trusted_source",
                "read_only",
                "complete",
                "partial",
                "query_contract",
                "provider_neutral",
                "rounds_completed",
                "queries_admitted",
                "successful_read_only_queries",
                "planning_retry_attempted",
                "planning_retry_produced_requests",
                "all_tool_call_bindings_read_only",
                "evaluation_requirement_satisfied",
            )
            if isinstance(
                audit.get(field),
                (str, int, float, bool, type(None)),
            )
        }
        output[key]["queries"] = safe_queries[:500]
        if key == "_investigation_query_audit":
            output[key]["round_results"] = safe_round_results[:500]
            output[key]["tool_call_bindings"] = (
                safe_tool_call_bindings[:500]
            )
    return output


def _query_audit_execution_binding(
    analysis: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind collector-owned query provenance without exporting query text."""

    query_audit = (
        analysis.get("query_audit")
        if isinstance(analysis.get("query_audit"), dict)
        else {}
    )
    section_count = 0
    queried_section_count = 0
    query_count = 0
    read_only_queried_section_count = 0
    for section in query_audit.values():
        if not isinstance(section, dict):
            continue
        section_count += 1
        queries = (
            section.get("queries")
            if isinstance(section.get("queries"), list)
            else []
        )
        query_count += len(queries)
        if queries:
            queried_section_count += 1
            if section.get("read_only") is True:
                read_only_queried_section_count += 1
    security_onion = query_audit.get("_incident_query_audit")
    security_onion = (
        security_onion if isinstance(security_onion, dict) else {}
    )
    security_onion_queries = (
        security_onion.get("queries")
        if isinstance(security_onion.get("queries"), list)
        else []
    )
    dynamic = query_audit.get("_investigation_query_audit")
    dynamic = dynamic if isinstance(dynamic, dict) else {}
    dynamic_queries = (
        dynamic.get("queries")
        if isinstance(dynamic.get("queries"), list)
        else []
    )
    successful_statuses = {
        "ok",
        "complete",
        "completed",
        "success",
        "succeeded",
    }
    dynamic_tool_bindings: list[dict[str, Any]] = []
    raw_dynamic_tool_bindings = (
        dynamic.get("tool_call_bindings")
        if isinstance(dynamic.get("tool_call_bindings"), list)
        else []
    )
    invalid_dynamic_tool_bindings = 0
    duplicate_dynamic_tool_bindings = 0
    seen_call_ids: set[str] = set()
    for binding in raw_dynamic_tool_bindings:
        if not isinstance(binding, dict):
            invalid_dynamic_tool_bindings += 1
            continue
        status = str(binding.get("status") or "").strip().lower()
        status = status.replace("_", "-")
        try:
            round_number = int(binding.get("round_number"))
        except (TypeError, ValueError, OverflowError):
            round_number = -1
        call_id = str(binding.get("call_id") or "")
        query_id = str(binding.get("query_id") or "")
        backend = str(binding.get("backend") or "")
        request_digest = str(binding.get("request_digest") or "")
        result_digest = str(binding.get("result_digest") or "")
        binding_is_valid = (
            round_number >= 1
            and bool(query_id)
            and bool(backend)
            and bool(status)
            and call_id == f"round-{round_number}-{query_id}"[:128]
            and SHA256_RE.fullmatch(request_digest) is not None
            and SHA256_RE.fullmatch(result_digest) is not None
            and isinstance(binding.get("read_only"), bool)
        )
        if not binding_is_valid:
            invalid_dynamic_tool_bindings += 1
            continue
        if call_id in seen_call_ids:
            duplicate_dynamic_tool_bindings += 1
            continue
        seen_call_ids.add(call_id)
        if (
            status not in successful_statuses
            or binding.get("read_only") is not True
        ):
            continue
        dynamic_tool_bindings.append(
            {
                "call_id": call_id,
                "round_number": round_number,
                "query_id": query_id,
                "backend": backend,
                "status": status,
                "request_digest": request_digest,
                "result_digest": result_digest,
                "read_only": True,
            }
        )
    dynamic_tool_bindings.sort(
        key=lambda item: (
            int(item["round_number"]),
            str(item["call_id"]),
        )
    )
    try:
        successful_read_only_queries = int(
            dynamic.get("successful_read_only_queries")
        )
    except (TypeError, ValueError, OverflowError):
        successful_read_only_queries = -1
    return {
        "query_audit_sha256": sha256_value(query_audit),
        "section_count": section_count,
        "queried_section_count": queried_section_count,
        "query_count": query_count,
        "read_only_queried_section_count": (
            read_only_queried_section_count
        ),
        "read_only_verified": (
            queried_section_count > 0
            and read_only_queried_section_count == queried_section_count
        ),
        "security_onion_query_count": len(security_onion_queries),
        "security_onion_read_only": (
            security_onion.get("read_only") is True
        ),
        "dynamic_query_count": len(dynamic_queries),
        "dynamic_tool_call_binding_count": len(
            raw_dynamic_tool_bindings
        ),
        "dynamic_invalid_tool_call_binding_count": (
            invalid_dynamic_tool_bindings
        ),
        "dynamic_duplicate_tool_call_binding_count": (
            duplicate_dynamic_tool_bindings
        ),
        "dynamic_read_only": dynamic.get("read_only") is True,
        "dynamic_complete": dynamic.get("complete") is True,
        "dynamic_all_tool_call_bindings_read_only": (
            dynamic.get("all_tool_call_bindings_read_only") is True
        ),
        "dynamic_evaluation_requirement_satisfied": (
            dynamic.get("evaluation_requirement_satisfied") is True
        ),
        "dynamic_successful_read_only_queries": (
            successful_read_only_queries
        ),
        "dynamic_successful_read_only_tool_bindings": (
            dynamic_tool_bindings
        ),
        "dynamic_successful_read_only_tool_bindings_sha256": (
            sha256_value(dynamic_tool_bindings)
        ),
    }


def _second_opinion_metadata(
    connection: sqlite3.Connection,
    analysis_id: str,
) -> dict[str, Any] | None:
    if not _table_exists(connection, "ai_second_opinion_runs"):
        return None
    columns = _table_columns(connection, "ai_second_opinion_runs")
    allowed = [
        item
        for item in (
            "analysis_id",
            "group_id",
            "alert_id",
            "agent_role",
            "trigger",
            "status",
            "primary_model",
            "primary_model_path",
            "primary_outcome",
            "primary_confidence",
            "reviewer_model",
            "reviewer_model_path",
            "reviewer_outcome",
            "reviewer_confidence",
            "agreement",
            "material_disagreement",
            "reviewer_runtime_seconds",
            "generated_at",
            "created_at",
            "updated_at",
        )
        if item in columns
    ]
    if "analysis_id" not in allowed:
        return None
    row = connection.execute(
        "SELECT " + ", ".join(allowed)
        + " FROM ai_second_opinion_runs WHERE analysis_id = ?",
        (analysis_id,),
    ).fetchone()
    return dict(row) if row else None


def monitor_member(
    connection: sqlite3.Connection,
    member: Mapping[str, Any],
) -> dict[str, Any]:
    dispatch = member.get("dispatch") or {}
    if dispatch.get("state") != "accepted":
        raise CohortError(
            f"member {member.get('rank')} was not unambiguously accepted"
        )
    accepted = dispatch.get("accepted") or {}
    stable_id = str(member["stable_group_id"])
    kind = str(dispatch.get("kind") or "")
    if kind == "analyze":
        prior_ids = set(
            (member.get("pre_state") or {}).get("soc_analysis_ids") or []
        )
        current_ids = set(
            _analysis_ids_for_group(
                connection,
                stable_id,
                agent_role="soc-analyst",
            )
        )
        if not prior_ids.issubset(current_ids):
            raise CohortError(
                f"prior SOC analysis identity disappeared for {stable_id}"
            )
        new_ids = sorted(current_ids - prior_ids)
        if len(new_ids) > 1:
            raise CohortError(
                f"more than one new SOC analysis exists for {stable_id}; "
                "the cohort result is ambiguous"
            )
        job = _durable_job_snapshot(
            connection,
            job_type="ai_analysis",
            stable_group_id=stable_id,
        )
        if new_ids:
            analysis_id = new_ids[0]
            state = "completed"
            analysis = _analysis_metadata(
                connection,
                analysis_id,
                stable_id,
                expected_agent_role="soc-analyst",
            )
        else:
            analysis_id = ""
            job_status = str((job or {}).get("status") or "")
            state = {
                "pending": "queued",
                "processing": "running",
                "failed": "failed",
            }.get(job_status, job_status or "unknown")
            if state not in {"queued", "running", "failed"}:
                raise CohortError(
                    f"SOC job for {stable_id} is {job_status or 'missing'} "
                    "without one exact new analysis"
                )
            analysis = None
        return {
            "state": state,
            "checked_at": utc_now(),
            "case_id": "",
            "run_id": "",
            "analysis_id": analysis_id,
            "job": job,
            "analysis": analysis,
            "second_opinion": (
                _second_opinion_metadata(connection, analysis_id)
                if analysis_id
                else None
            ),
        }
    case_id = str(accepted.get("case_id") or "")
    aliases = load_aliases(connection)
    case = _case_for_stable(connection, stable_id, aliases)
    if not case or str(case.get("case_id") or "") != case_id:
        raise CohortError(f"exact incident case identity was lost: {case_id}")
    if (
        str(case.get("dashboard_group_id") or "")
        != str(member["dashboard_group_id"])
        or str(case.get("representative_alert_id") or "")
        != str(member["representative_alert_id"])
    ):
        raise CohortError(f"incident case identity drifted: {case_id}")
    status = str(case.get("agent_status") or "")
    analysis_id = ""
    run_case: dict[str, Any] | None = None
    if kind == "reanalyze":
        run_id = str(accepted.get("run_id") or "")
        row = connection.execute(
            """
            SELECT run_id, case_id, group_id, dashboard_group_id,
                   representative_alert_id, status, skip_reason, latest_error,
                   queued_at, started_at, completed_at, latest_attempt_id,
                   analysis_id, executed_model, executed_provider,
                   executed_model_path, result_generated_at, updated_at
            FROM incident_reanalysis_run_cases
            WHERE run_id = ? AND case_id = ?
            """,
            (run_id, case_id),
        ).fetchone()
        if not row:
            raise CohortError(
                f"exact reanalysis run case is missing: {run_id}/{case_id}"
            )
        run_case = dict(row)
        if (
            resolve_alias(str(row["group_id"] or ""), aliases) != stable_id
            or str(row["dashboard_group_id"] or "")
            != str(member["dashboard_group_id"])
            or str(row["representative_alert_id"] or "")
            != str(member["representative_alert_id"])
        ):
            raise CohortError(
                f"exact reanalysis identity drifted: {run_id}/{case_id}"
            )
        status = str(row["status"] or "")
        analysis_id = str(row["analysis_id"] or "")
    elif kind == "escalate":
        status = {
            "queued": "queued",
            "analyzing": "running",
            "analyzed": "completed",
            "failed": "failed",
        }.get(status, status or "unknown")
        analysis_id = str(case.get("latest_analysis_id") or "")
    else:
        raise CohortError(f"unsupported dispatch kind: {kind!r}")
    if status == "completed" and not analysis_id:
        raise CohortError(
            f"completed member {member.get('rank')} has no analysis ID"
        )
    analysis = (
        _analysis_metadata(connection, analysis_id, stable_id)
        if analysis_id
        else None
    )
    return {
        "state": status,
        "checked_at": utc_now(),
        "case_id": case_id,
        "run_id": str(accepted.get("run_id") or ""),
        "analysis_id": analysis_id,
        "case_agent_status": str(case.get("agent_status") or ""),
        "run_case": {
            key: value
            for key, value in (run_case or {}).items()
            if key not in {"latest_error", "skip_reason"}
        }
        if run_case
        else None,
        "analysis": analysis,
        "second_opinion": (
            _second_opinion_metadata(connection, analysis_id)
            if analysis_id
            else None
        ),
    }


def monitor_cohort_once(
    database_path: Path,
    manifest_path: Path,
) -> tuple[dict[str, Any], bool]:
    manifest = load_private_manifest(manifest_path)
    connection = connect_read_only(database_path)
    try:
        connection.execute("BEGIN")
        terminal = True
        for index, member in enumerate(manifest["members"]):
            monitor = monitor_member(connection, member)
            member["monitor"] = monitor
            manifest["members"][index] = member
            terminal = terminal and monitor["state"] in TERMINAL_MONITOR_STATES
    finally:
        connection.close()
    manifest["last_monitored_at"] = utc_now()
    manifest["state"] = "terminal" if terminal else "monitoring"
    manifest = write_private_json(
        manifest_path,
        manifest,
        digest_field="manifest_sha256",
    )
    return manifest, terminal


def monitor_cohort(
    database_path: Path,
    manifest_path: Path,
    *,
    timeout: float,
    poll_interval: float,
) -> tuple[dict[str, Any], bool]:
    if timeout < 0:
        raise CohortError("monitor timeout must not be negative")
    if poll_interval < 0.2 or poll_interval > 60:
        raise CohortError("poll interval must be between 0.2 and 60 seconds")
    deadline = time.monotonic() + timeout
    while True:
        manifest, terminal = monitor_cohort_once(database_path, manifest_path)
        if terminal or timeout == 0 or time.monotonic() >= deadline:
            return manifest, terminal
        time.sleep(min(poll_interval, max(0.0, deadline - time.monotonic())))


def _load_trace_evaluator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "onion_sentinel_cohort_trace_evaluator",
        TRACE_EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise CohortError("could not load the harness trace evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _prior_analysis_ids(member: Mapping[str, Any]) -> set[str]:
    pre_state = (
        member.get("pre_state")
        if isinstance(member.get("pre_state"), dict)
        else {}
    )
    identities = {
        str(item)
        for item in pre_state.get("soc_analysis_ids", [])
        if str(item)
    } if isinstance(pre_state.get("soc_analysis_ids"), list) else set()
    for source in (
        pre_state.get("latest_analysis"),
        pre_state.get("incident_case"),
    ):
        if isinstance(source, dict):
            identity = str(
                source.get("analysis_id")
                or source.get("latest_analysis_id")
                or ""
            )
            if identity:
                identities.add(identity)
    return identities


def _expected_task_kind(role: str, dispatch_kind: str) -> str:
    if role == "soc-analyst" and dispatch_kind == "analyze":
        # The explicit dashboard /analyze endpoint marks the queued job as a
        # manual reanalysis. The harness must preserve that lineage instead of
        # presenting this controlled rerun as first-pass alert intake.
        return "reanalysis"
    if role == "incident-responder" and dispatch_kind == "reanalyze":
        return "reanalysis"
    if role == "incident-responder" and dispatch_kind == "escalate":
        return "incident-response"
    raise CohortError(
        f"dispatch {dispatch_kind!r} is invalid for agent role {role!r}"
    )


def _harness_execution_proof(
    *,
    harness_database_path: Path,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    monitor: Mapping[str, Any],
) -> dict[str, Any]:
    """Fail closed unless one fresh result has one valid successful trace."""

    role = str(manifest.get("agent_role") or "")
    contract = manifest.get("execution_contract")
    if not isinstance(contract, dict):
        raise CohortError("manifest has no execution contract")
    dispatch = (
        member.get("dispatch")
        if isinstance(member.get("dispatch"), dict)
        else {}
    )
    analysis = (
        monitor.get("analysis")
        if isinstance(monitor.get("analysis"), dict)
        else {}
    )
    analysis_result = (
        analysis.get("result")
        if isinstance(analysis.get("result"), dict)
        else {}
    )
    analysis_id = str(monitor.get("analysis_id") or "")
    failures: list[str] = []
    if str(monitor.get("state") or "") != "completed":
        failures.append("result-not-completed")
    if not analysis_id or str(analysis.get("analysis_id") or "") != analysis_id:
        failures.append("analysis-id-binding-failed")
    if analysis_id in _prior_analysis_ids(member):
        failures.append("analysis-id-is-not-fresh")
    if str(analysis.get("agent_role") or "") != role:
        failures.append("analysis-role-mismatch")
    if dispatch.get("state") != "accepted" or int(
        dispatch.get("attempt_count") or 0
    ) != 1:
        failures.append("dispatch-not-exactly-once")
    try:
        dispatch_started = _parse_timestamp(
            dispatch.get("started_at"),
            "dispatch started_at",
        )
        analysis_generated = _parse_timestamp(
            analysis.get("generated_at"),
            "analysis generated_at",
        )
        if analysis_generated < dispatch_started:
            failures.append("analysis-predates-dispatch")
    except CohortError:
        failures.append("freshness-timestamp-invalid")
        dispatch_started = None
        analysis_generated = None

    expected_route = str(contract.get("expected_assigned_route") or "")
    expected_reviewer_route = str(
        contract.get("expected_reviewer_route") or ""
    )
    if analysis_result.get("_analysis_evaluation_memory_frozen") is not True:
        failures.append("analysis-memory-freeze-not-attested")
    if str(analysis_result.get("_analysis_model_route") or "") != expected_route:
        failures.append("analysis-route-mismatch")

    trace_evaluator = _load_trace_evaluator()
    try:
        trace_report = trace_evaluator.evaluate_database(
            harness_database_path,
            analysis_id,
        )
    except Exception as exc:
        raise CohortError(
            f"harness trace evaluation failed for {analysis_id}: "
            f"{type(exc).__name__}"
        ) from exc
    trace_runs = trace_report.get("runs")
    if not isinstance(trace_runs, list) or len(trace_runs) != 1:
        raise CohortError(
            f"harness trace for {analysis_id} is not exactly one run"
        )
    trace = trace_runs[0]
    integrity = (
        trace.get("integrity")
        if isinstance(trace.get("integrity"), dict)
        else {}
    )
    routes = (
        (trace.get("models") or {}).get("route_consistency")
        if isinstance(trace.get("models"), dict)
        else {}
    )
    routes = routes if isinstance(routes, dict) else {}
    tools = trace.get("tools") if isinstance(trace.get("tools"), dict) else {}
    models = (
        trace.get("models")
        if isinstance(trace.get("models"), dict)
        else {}
    )
    terminal = (
        trace.get("terminal_execution_summary")
        if isinstance(trace.get("terminal_execution_summary"), dict)
        else {}
    )
    if str(trace.get("run_id") or "") != analysis_id:
        failures.append("harness-run-analysis-binding-failed")
    if str(trace.get("status") or "") != "succeeded":
        failures.append("harness-run-not-succeeded")
    if str(trace.get("stage") or "") != "complete":
        failures.append("harness-run-not-complete")
    if str(trace.get("role") or "") != role:
        failures.append("harness-role-mismatch")
    dispatch_kind = str(dispatch.get("kind") or "")
    if str(trace.get("task_kind") or "") != _expected_task_kind(
        role,
        dispatch_kind,
    ):
        failures.append("harness-task-kind-mismatch")
    if str(trace.get("correlation_id") or "") != str(
        member.get("stable_group_id") or ""
    ):
        failures.append("harness-stable-group-binding-failed")
    if str(trace.get("alert_id") or "") != str(
        member.get("representative_alert_id") or ""
    ):
        failures.append("harness-alert-binding-failed")
    if str(trace.get("policy_mode") or "") != str(
        contract.get("harness_mode") or ""
    ):
        failures.append("harness-mode-mismatch")
    if str(trace.get("assigned_route") or "") != expected_route:
        failures.append("harness-assigned-route-mismatch")
    if (
        str(trace.get("assigned_reviewer_route") or "")
        != expected_reviewer_route
    ):
        failures.append("harness-reviewer-route-mismatch")
    if not integrity.get("valid"):
        failures.append("harness-chain-invalid")
    if not integrity.get("ledger_manifest_bound"):
        failures.append("harness-terminal-ledger-unbound")
    if int(models.get("successful_primary_call_count") or 0) < 1:
        failures.append("harness-primary-model-call-missing")
    if int(models.get("successful_call_count") or 0) != int(
        (trace.get("counts") or {}).get("model_calls") or 0
    ):
        failures.append("harness-model-call-incomplete")
    for field in (
        "authorization_failure_count",
        "authorization_denied_event_count",
        "authorization_malformed_event_count",
        "authorization_orphan_event_count",
        "authorization_unverified_call_count",
        "observation_denied_event_count",
        "observation_malformed_event_count",
        "observation_orphan_event_count",
        "identity_mismatch_count",
        "identity_unverified_call_count",
    ):
        if int(routes.get(field) or 0):
            failures.append(f"harness-route-{field}")
    if routes.get("contract_available") is not True:
        failures.append("harness-route-contract-unavailable")
    tool_call_count = int(
        (trace.get("counts") or {}).get("tool_calls") or 0
    )
    successful_tool_call_count = int(
        tools.get("successful_call_count") or 0
    )
    read_only_tool_call_count = int(
        tools.get("read_only_call_count") or 0
    )
    if tool_call_count < 1:
        failures.append("harness-tool-call-ledger-missing")
    if successful_tool_call_count < 1:
        failures.append("harness-successful-tool-call-missing")
    if read_only_tool_call_count != tool_call_count:
        failures.append("harness-read-only-tool-ledger-incomplete")
    if int(tools.get("read_only_violation_count") or 0):
        failures.append("harness-non-read-only-tool-call")
    query_audit_binding = _query_audit_execution_binding(analysis)
    if (
        int(query_audit_binding["queried_section_count"]) > 0
        and query_audit_binding["read_only_verified"] is not True
    ):
        failures.append("collector-query-audit-not-read-only")
    if role == "incident-responder" and (
        int(query_audit_binding["security_onion_query_count"]) < 1
        or query_audit_binding["security_onion_read_only"] is not True
    ):
        failures.append(
            "incident-security-onion-query-audit-missing-or-unverified"
        )
    dynamic_bindings = query_audit_binding[
        "dynamic_successful_read_only_tool_bindings"
    ]
    trace_bindings = tools.get("successful_read_only_call_bindings")
    if (
        query_audit_binding["dynamic_read_only"] is not True
        or query_audit_binding[
            "dynamic_all_tool_call_bindings_read_only"
        ]
        is not True
        or query_audit_binding[
            "dynamic_evaluation_requirement_satisfied"
        ]
        is not True
        or int(
            query_audit_binding[
                "dynamic_successful_read_only_queries"
            ]
        )
        < 1
        or int(query_audit_binding["dynamic_query_count"]) < 1
        or int(
            query_audit_binding[
                "dynamic_tool_call_binding_count"
            ]
        )
        < 1
        or int(
            query_audit_binding[
                "dynamic_invalid_tool_call_binding_count"
            ]
        )
        != 0
        or int(
            query_audit_binding[
                "dynamic_duplicate_tool_call_binding_count"
            ]
        )
        != 0
        or not dynamic_bindings
        or int(
            query_audit_binding[
                "dynamic_successful_read_only_queries"
            ]
        )
        != len(dynamic_bindings)
    ):
        failures.append(
            "dynamic-query-audit-missing-or-incomplete"
        )
    trace_binding_digest = str(
        tools.get("successful_read_only_call_bindings_sha256") or ""
    )
    if (
        not isinstance(trace_bindings, list)
        or trace_bindings != dynamic_bindings
        or len(dynamic_bindings) != successful_tool_call_count
        or trace_binding_digest != sha256_value(dynamic_bindings)
    ):
        failures.append("dynamic-query-tool-ledger-binding-mismatch")
    if trace_report.get("data_quality", {}).get("malformed_json_counts"):
        failures.append("harness-trace-malformed-json")
    if terminal.get("evaluation_memory_frozen") is not True:
        failures.append("harness-memory-freeze-not-attested")
    if str(terminal.get("analysis_id") or "") != analysis_id:
        failures.append("harness-terminal-analysis-binding-failed")
    canonical_response_sha256 = str(
        analysis.get("response_canonical_sha256") or ""
    )
    submitted_response_sha256 = str(
        terminal.get("submitted_response_sha256") or ""
    )
    stored_response_sha256 = str(
        terminal.get("stored_response_sha256") or ""
    )
    # The alert store deliberately normalizes timestamp strings before
    # persistence. Consequently the pre-normalization submitted response may
    # have a different canonical digest. Its digest is still hash-chain bound
    # in the terminal event; only the commit receipt's stored digest can be
    # compared to the canonical response read back from ai_analysis_runs.
    if not SHA256_RE.fullmatch(submitted_response_sha256):
        failures.append("harness-terminal-submitted-response-digest-invalid")
    if (
        not SHA256_RE.fullmatch(stored_response_sha256)
        or stored_response_sha256 != canonical_response_sha256
    ):
        failures.append("harness-terminal-stored-response-digest-mismatch")
    try:
        harness_started = _parse_timestamp(
            trace.get("started_at"),
            "harness started_at",
        )
        harness_completed = _parse_timestamp(
            trace.get("completed_at"),
            "harness completed_at",
        )
        if dispatch_started and harness_started < dispatch_started:
            failures.append("harness-run-predates-dispatch")
        if analysis_generated and harness_completed < analysis_generated:
            failures.append("harness-completed-before-analysis")
    except CohortError:
        failures.append("harness-timestamp-invalid")

    if failures:
        raise CohortError(
            f"execution gate failed for {analysis_id}: "
            + ", ".join(sorted(set(failures)))
        )
    proof = {
        "status": "passed",
        "fresh_analysis": True,
        "dispatch_accepted_once": True,
        "analysis_id": analysis_id,
        "analysis_generated_at": str(analysis.get("generated_at") or ""),
        "harness": {
            "run_id": analysis_id,
            "trace_id": str(trace.get("trace_id") or ""),
            "stable_group_id": str(trace.get("correlation_id") or ""),
            "representative_alert_id": str(trace.get("alert_id") or ""),
            "status": "succeeded",
            "stage": "complete",
            "role": role,
            "task_kind": str(trace.get("task_kind") or ""),
            "policy_mode": str(trace.get("policy_mode") or ""),
            "assigned_route": str(trace.get("assigned_route") or ""),
            "assigned_reviewer_route": str(
                trace.get("assigned_reviewer_route") or ""
            ),
            "started_at": str(trace.get("started_at") or ""),
            "completed_at": str(trace.get("completed_at") or ""),
            "chain_valid": True,
            "chain_head_sha256": str(integrity.get("head_sha256") or ""),
            "ledger_manifest_bound": True,
            "ledger_manifest_schema": str(
                integrity.get("ledger_manifest_schema") or ""
            ),
            "model_call_count": int(
                (trace.get("counts") or {}).get("model_calls") or 0
            ),
            "successful_model_call_count": int(
                models.get("successful_call_count") or 0
            ),
            "successful_primary_model_call_count": int(
                models.get("successful_primary_call_count") or 0
            ),
            "route_authorization_failure_count": 0,
            "route_identity_mismatch_count": 0,
            "tool_call_count": tool_call_count,
            "successful_tool_call_count": successful_tool_call_count,
            "read_only_tool_call_count": read_only_tool_call_count,
            "read_only_violation_count": 0,
            "successful_read_only_tool_call_bindings": (
                trace_bindings
            ),
            "successful_read_only_tool_call_bindings_sha256": (
                trace_binding_digest
            ),
            "query_audit": query_audit_binding,
            "memory_frozen": True,
            "submitted_response_sha256": submitted_response_sha256,
            "response_canonical_sha256": canonical_response_sha256,
        },
    }
    proof["proof_sha256"] = sha256_value(proof)
    return proof


def export_cohort(
    database_path: Path,
    manifest_path: Path,
    output_path: Path,
    *,
    harness_database_path: Path | None = None,
) -> dict[str, Any]:
    manifest, terminal = monitor_cohort_once(database_path, manifest_path)
    if not terminal:
        raise CohortError("cohort is not terminal; refusing a partial export")
    noncompleted = [
        int(member.get("rank") or 0)
        for member in manifest["members"]
        if str((member.get("monitor") or {}).get("state") or "")
        != "completed"
    ]
    if noncompleted:
        raise CohortError(
            "cohort contains non-completed results; refusing a gradeable "
            f"export (ranks={noncompleted})"
        )
    members = []
    for member in manifest["members"]:
        monitor = member.get("monitor") or {}
        proof = (
            _harness_execution_proof(
                harness_database_path=harness_database_path,
                manifest=manifest,
                member=member,
                monitor=monitor,
            )
            if harness_database_path is not None
            else {
                "status": "not_attested",
                "reason": "harness database was not supplied",
            }
        )
        members.append(
            {
                "rank": member["rank"],
                "dashboard_group_id": member["dashboard_group_id"],
                "stable_group_id": member["stable_group_id"],
                "representative_alert_id": member["representative_alert_id"],
                "detection": member["detection"],
                "pre_state": member["pre_state"],
                "dispatch": member["dispatch"],
                "result": monitor,
                "execution_proof": proof,
            }
        )
    selection = (
        dict(manifest.get("selection"))
        if isinstance(manifest.get("selection"), dict)
        else {}
    )
    gate_passed = (
        harness_database_path is not None
        and len(members) == int(manifest["count"])
        and all(
            (member.get("execution_proof") or {}).get("status") == "passed"
            for member in members
        )
    )
    export = {
        "schema": EXPORT_SCHEMA,
        "cohort_id": manifest["cohort_id"],
        "reason": manifest["reason"],
        "agent_role": manifest.get("agent_role") or "incident-responder",
        "count": manifest["count"],
        "frozen_at": manifest["created_at"],
        "exported_at": utc_now(),
        "source_manifest_sha256": manifest["manifest_sha256"],
        "frozen_plan_sha256": manifest["frozen_plan_sha256"],
        "selection": selection,
        "execution_contract": manifest["execution_contract"],
        "execution_gate": {
            "status": "passed" if gate_passed else "not_attested",
            "expected_count": int(manifest["count"]),
            "passed_count": sum(
                (member.get("execution_proof") or {}).get("status") == "passed"
                for member in members
            ),
            "ordered_identity_sha256": sha256_value(
                ordered_identity_projection(members)
            ),
            "contract_sha256": sha256_value(
                manifest["execution_contract"]
            ),
        },
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
    return write_private_json(
        output_path,
        export,
        digest_field="export_sha256",
        replace=False,
    )


def _print_summary(document: Mapping[str, Any]) -> None:
    print(
        json.dumps(
            {
                "schema": document.get("schema"),
                "cohort_id": document.get("cohort_id"),
                "agent_role": document.get("agent_role"),
                "state": document.get("state"),
                "count": document.get("count"),
                "manifest_sha256": document.get("manifest_sha256"),
                "export_sha256": document.get("export_sha256"),
            },
            indent=2,
            sort_keys=True,
        )
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    freeze = commands.add_parser("freeze", help="freeze the newest stable cohort")
    freeze.add_argument("--db", required=True, type=Path)
    freeze.add_argument("--manifest", required=True, type=Path)
    freeze.add_argument("--cohort-id", required=True)
    freeze.add_argument("--reason", required=True)
    freeze.add_argument("--count", required=True, type=int)
    freeze.add_argument("--expected-assigned-route", required=True)
    freeze.add_argument("--expected-reviewer-route", default="")
    freeze.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and print the frozen plan without writing a manifest",
    )

    imported = commands.add_parser(
        "freeze-from-rows",
        help="freeze an already-selected owner-only JSON array without reselection",
    )
    imported.add_argument("--db", required=True, type=Path)
    imported.add_argument("--source-rows", required=True, type=Path)
    imported.add_argument("--manifest", required=True, type=Path)
    imported.add_argument("--cohort-id", required=True)
    imported.add_argument("--reason", required=True)
    imported.add_argument("--expected-count", required=True, type=int)
    imported.add_argument("--expected-assigned-route", required=True)
    imported.add_argument("--expected-reviewer-route", default="")
    imported.add_argument(
        "--agent-role",
        choices=sorted(AGENT_ROLES),
        default="incident-responder",
        help="agent queue to exercise; defaults to incident-responder",
    )
    imported.add_argument(
        "--dry-run",
        action="store_true",
        help="validate exact source rows without writing a manifest",
    )

    queue = commands.add_parser("queue", help="queue each frozen member once")
    queue.add_argument("--db", required=True, type=Path)
    queue.add_argument("--manifest", required=True, type=Path)
    queue.add_argument(
        "--base-url",
        default="http://127.0.0.1:8766",
        help="loopback dashboard origin",
    )
    queue.add_argument("--http-timeout", type=float, default=15.0)
    queue.add_argument(
        "--dry-run",
        action="store_true",
        help="validate all identities without sending any HTTP request",
    )

    monitor = commands.add_parser("monitor", help="monitor exact accepted identities")
    monitor.add_argument("--db", required=True, type=Path)
    monitor.add_argument("--manifest", required=True, type=Path)
    monitor.add_argument(
        "--timeout",
        type=float,
        default=0.0,
        help="seconds to wait; zero performs one snapshot",
    )
    monitor.add_argument("--poll-interval", type=float, default=5.0)

    export = commands.add_parser("export", help="export terminal result metadata")
    export.add_argument("--db", required=True, type=Path)
    export.add_argument("--manifest", required=True, type=Path)
    export.add_argument("--output", required=True, type=Path)
    export.add_argument(
        "--harness-db",
        required=True,
        type=Path,
        help="read-only harness ledger used to attest every exact analysis",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "freeze":
            result = freeze_cohort(
                args.db,
                args.manifest,
                cohort_id=args.cohort_id,
                reason=args.reason,
                count=args.count,
                expected_assigned_route=args.expected_assigned_route,
                expected_reviewer_route=args.expected_reviewer_route,
                dry_run=args.dry_run,
            )
            _print_summary(result)
            return 0
        if args.command == "freeze-from-rows":
            result = freeze_cohort_from_rows(
                args.db,
                args.source_rows,
                args.manifest,
                cohort_id=args.cohort_id,
                reason=args.reason,
                expected_count=args.expected_count,
                agent_role=args.agent_role,
                expected_assigned_route=args.expected_assigned_route,
                expected_reviewer_route=args.expected_reviewer_route,
                dry_run=args.dry_run,
            )
            _print_summary(result)
            return 0
        if args.command == "queue":
            result = queue_cohort(
                args.db,
                args.manifest,
                base_url=args.base_url,
                timeout=args.http_timeout,
                dry_run=args.dry_run,
            )
            _print_summary(result)
            return 0
        if args.command == "monitor":
            result, terminal = monitor_cohort(
                args.db,
                args.manifest,
                timeout=args.timeout,
                poll_interval=args.poll_interval,
            )
            _print_summary(result)
            return 0 if terminal else 3
        if args.command == "export":
            result = export_cohort(
                args.db,
                args.manifest,
                args.output,
                harness_database_path=args.harness_db,
            )
            _print_summary(result)
            return 0
    except (CohortError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
