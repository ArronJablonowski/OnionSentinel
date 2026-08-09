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
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping


OPERATIONS_DIR = Path(__file__).resolve().parent
if str(OPERATIONS_DIR) not in sys.path:
    sys.path.insert(0, str(OPERATIONS_DIR))
from cohort_freezing import (
    CohortFreezePolicy,
    CohortFreezeSources,
    freeze_cohort as run_freeze_cohort,
    freeze_cohort_from_rows as run_freeze_cohort_from_rows,
)


SCHEMA = "onion-sentinel-incident-harness-cohort-v4"
EXPORT_SCHEMA = "onion-sentinel-incident-harness-cohort-export-v4"
MAX_COHORT_SIZE = 100
MAX_HTTP_BODY_BYTES = 1_000_000
MAX_SOURCE_ROWS_BYTES = 2_000_000
MAX_MANIFEST_BYTES = 10_000_000
MAX_STORED_RESPONSE_BYTES = 8_000_000
MAX_STABLE_GROUP_KEY_BYTES = 2048
MAX_EVALUATION_TOKEN_BYTES = 64
TERMINAL_MONITOR_STATES = {"completed", "failed", "skipped"}
ACTIVE_JOB_STATES = {"pending", "processing"}
ACTIVE_AGENT_STATES = {"queued", "analyzing"}
ACTIVE_REANALYSIS_STATES = {"queued", "running"}
AGENT_ROLES = {"incident-responder", "soc-analyst"}
COHORT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}")
DASHBOARD_GROUP_ID_RE = re.compile(r"[a-f0-9]{12}")
STABLE_GROUP_ID_RE = re.compile(r"[a-f0-9]{20}")
REPRESENTATIVE_ALERT_ID_RE = re.compile(r"[A-Za-z0-9._:@=-]{1,256}")
CASE_ID_RE = re.compile(r"ir-[a-z0-9_-]{1,64}")
RUN_ID_RE = re.compile(r"irr-[a-z0-9-]{1,64}")
SHA256_RE = re.compile(r"[a-f0-9]{64}")
SKILL_ID_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._:@+=/-]{0,255}")
MAX_ATTESTED_INVESTIGATION_SKILLS = 4
RELEASE_ID_RE = re.compile(r"[a-f0-9]{40}")
SAFE_ROUTE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{2,255}")
CONTROLLED_ROUTE_RE = re.compile(
    r"codex-cli:(?:gpt-5\.5|gpt-5\.6-(?:sol|terra|luna)):"
    r"(?:low|medium|high|xhigh)"
)
CONTROLLED_EVALUATION_PROFILE = (
    "onion-sentinel-gpt55-high-gpt56-sol-xhigh-v1"
)
PROFILE_ASSIGNED_ROUTE = "codex-cli:gpt-5.5:high"
PROFILE_REVIEWER_ROUTE = "codex-cli:gpt-5.6-sol:xhigh"
TRACE_EVALUATOR_PATH = Path(__file__).with_name("evaluate-harness-traces.py")
ALERT_STORE_CANONICAL_SHA256_JS = r"""
const crypto = require("node:crypto");
const fs = require("node:fs");
const canonicalize = (item) => {
  if (Array.isArray(item)) return item.map((entry) => canonicalize(entry));
  if (item && typeof item === "object") {
    return Object.fromEntries(
      Object.keys(item).sort().map((key) => [key, canonicalize(item[key])]),
    );
  }
  return item;
};
const value = JSON.parse(fs.readFileSync(0, "utf8"));
process.stdout.write(
  crypto.createHash("sha256")
    .update(JSON.stringify(canonicalize(value)))
    .digest("hex"),
);
"""
MODEL_CALL_CONTRACT_SCHEMA = "onion-sentinel-model-call-contract-v1"
MAX_RUNTIME_MODEL_CALLS = 6
DISPATCH_ID_SCHEMA = "onion-sentinel-cohort-member-dispatch-v1"
REPRESENTATIVE_BINDING_SCHEMA = (
    "onion-sentinel-frozen-representative-binding-v1"
)
FROZEN_REPRESENTATIVE_IMMUTABLE_FIELDS = (
    "stable_group_key",
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
)


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


def alert_store_response_sha256(raw_response: str) -> str:
    """Reproduce alert-store's JavaScript canonical response digest exactly.

    Python's JSON serializer cannot be used for this receipt comparison:
    ECMAScript differs in number formatting and orders object keys by UTF-16
    code units. Execute a fixed, input-only Node program so the observer proves
    the same byte representation that alert-store hashed at commit time.
    """

    encoded = raw_response.encode("utf-8")
    if not encoded or len(encoded) > MAX_STORED_RESPONSE_BYTES:
        raise CohortError("stored analysis response exceeds its safe bound")
    node = shutil.which("node")
    if not node:
        for candidate in (
            Path("/opt/homebrew/bin/node"),
            Path("/usr/local/bin/node"),
            Path("/usr/bin/node"),
        ):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                node = str(candidate)
                break
    if not node:
        raise CohortError(
            "Node.js is required to verify alert-store response receipts"
        )
    try:
        completed = subprocess.run(
            [node, "-e", ALERT_STORE_CANONICAL_SHA256_JS],
            input=encoded,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CohortError(
            "could not canonicalize the stored analysis response"
        ) from exc
    digest = completed.stdout.decode("ascii", errors="ignore").strip()
    if completed.returncode != 0 or not SHA256_RE.fullmatch(digest):
        raise CohortError(
            "alert-store response canonicalization failed closed"
        )
    return digest


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
        expected_release_id=str(
            (contract or {}).get("expected_release_id") or ""
        ),
        expected_assigned_route=str(
            (contract or {}).get("expected_assigned_route") or ""
        ),
        expected_reviewer_route=str(
            (contract or {}).get("expected_reviewer_route") or ""
        ),
        evaluation_profile=str(
            (contract or {}).get("evaluation_profile") or ""
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


def validate_release_id(value: Any, label: str = "expected release ID") -> str:
    release_id = str(value or "").strip()
    if not RELEASE_ID_RE.fullmatch(release_id):
        raise CohortError(
            f"{label} must be exactly 40 lowercase hexadecimal characters"
        )
    return release_id


def validate_stable_group_key(value: Any, label: str) -> str:
    """Validate an opaque stable-group key without changing its identity."""

    if not isinstance(value, str) or not value:
        raise CohortError(f"{label} is missing or malformed")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CohortError(f"{label} is not valid UTF-8") from exc
    if len(encoded) > MAX_STABLE_GROUP_KEY_BYTES or "\x00" in value:
        raise CohortError(
            f"{label} exceeds the bounded stable-group-key contract"
        )
    return value


def _member_stable_group_key(member: Mapping[str, Any]) -> str:
    """Return the exact top-level/detection-bound stable-group key."""

    stable_group_key = validate_stable_group_key(
        member.get("stable_group_key"),
        "frozen member stable_group_key",
    )
    detection = member.get("detection")
    if not isinstance(detection, dict):
        raise CohortError("frozen member detection is missing or malformed")
    detection_group_key = validate_stable_group_key(
        detection.get("stable_group_key"),
        "frozen detection stable_group_key",
    )
    if detection_group_key != stable_group_key:
        raise CohortError(
            "frozen member stable_group_key does not match detection evidence"
        )
    return stable_group_key


def execution_contract(
    *,
    expected_release_id: str,
    expected_assigned_route: str,
    expected_reviewer_route: str = "codex-cli:gpt-5.6-sol:xhigh",
    evaluation_profile: str = "",
) -> dict[str, Any]:
    """Return the immutable controls required for a gradeable harness run."""

    assigned_route = validate_model_route(
        expected_assigned_route,
        "expected assigned route",
    )
    reviewer_route = validate_model_route(
        expected_reviewer_route,
        "expected reviewer route",
    )
    if (
        not CONTROLLED_ROUTE_RE.fullmatch(assigned_route)
        or not CONTROLLED_ROUTE_RE.fullmatch(reviewer_route)
        or assigned_route.rsplit(":", 1)[0]
        == reviewer_route.rsplit(":", 1)[0]
    ):
        raise CohortError(
            "controlled evaluation requires distinct non-empty canonical Codex "
            "primary and reviewer routes"
        )
    profile = str(evaluation_profile or "").strip()
    if profile and (
        profile != CONTROLLED_EVALUATION_PROFILE
        or assigned_route != PROFILE_ASSIGNED_ROUTE
        or reviewer_route != PROFILE_REVIEWER_ROUTE
    ):
        raise CohortError(
            "controlled evaluation profile does not match its exact routes"
        )

    return {
        "harness_required": True,
        "harness_mode": "shadow",
        "memory_frozen": True,
        "expected_release_id": validate_release_id(expected_release_id),
        "expected_assigned_route": assigned_route,
        "expected_reviewer_route": reviewer_route,
        "reviewer_required": True,
        "evaluation_profile": profile,
    }


def ordered_identity_projection(
    members: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "rank": int(member["rank"]),
            "dashboard_group_id": str(member["dashboard_group_id"]),
            "stable_group_id": str(member["stable_group_id"]),
            "stable_group_key": _member_stable_group_key(member),
            "representative_alert_id": str(
                member["representative_alert_id"]
            ),
        }
        for member in members
    ]


def _member_detection_digest(member: Mapping[str, Any]) -> str:
    detection = member.get("detection")
    if not isinstance(detection, dict):
        raise CohortError("frozen plan member detection is missing or malformed")
    return sha256_value(detection)


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
                    "detection_sha256": _member_detection_digest(member),
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


def deterministic_dispatch_id(
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> str:
    """Derive one replay-stable dispatch identity from the frozen plan."""

    cohort_id = str(manifest.get("cohort_id") or "")
    if not COHORT_ID_RE.fullmatch(cohort_id):
        raise CohortError("cohort dispatch has an invalid cohort ID")
    frozen_plan_sha256 = str(manifest.get("frozen_plan_sha256") or "")
    if not SHA256_RE.fullmatch(frozen_plan_sha256):
        raise CohortError("cohort dispatch has an invalid frozen plan digest")
    dashboard_id = str(member.get("dashboard_group_id") or "")
    stable_id = str(member.get("stable_group_id") or "")
    representative_alert_id = str(
        member.get("representative_alert_id") or ""
    )
    stable_group_key = _member_stable_group_key(member)
    dispatch_kind = str((member.get("dispatch") or {}).get("kind") or "")
    if not DASHBOARD_GROUP_ID_RE.fullmatch(dashboard_id):
        raise CohortError("cohort dispatch has an invalid dashboard group ID")
    if not STABLE_GROUP_ID_RE.fullmatch(stable_id):
        raise CohortError("cohort dispatch has an invalid stable group ID")
    if not REPRESENTATIVE_ALERT_ID_RE.fullmatch(representative_alert_id):
        raise CohortError(
            "cohort dispatch has an invalid frozen representative alert ID"
        )
    if dispatch_kind not in {"analyze", "escalate", "reanalyze"}:
        raise CohortError(
            f"cohort dispatch has unsupported kind: {dispatch_kind!r}"
        )
    try:
        rank = int(member["rank"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CohortError("cohort dispatch has an invalid member rank") from exc
    if rank < 1:
        raise CohortError("cohort dispatch has an invalid member rank")
    dispatch_id = sha256_value(
        {
            "schema": DISPATCH_ID_SCHEMA,
            "cohort_id": cohort_id,
            "frozen_plan_sha256": frozen_plan_sha256,
            "rank": rank,
            "dashboard_group_id": dashboard_id,
            "stable_group_id": stable_id,
            "stable_group_key": stable_group_key,
            "representative_alert_id": representative_alert_id,
            "dispatch_kind": dispatch_kind,
        }
    )
    existing = str((member.get("dispatch") or {}).get("dispatch_id") or "")
    if existing and (
        not SHA256_RE.fullmatch(existing)
        or not _constant_time_equal(existing, dispatch_id)
    ):
        raise CohortError(
            f"dispatch ID does not match frozen member rank {rank}"
        )
    return dispatch_id


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


def _durable_dispatch_job(
    connection: sqlite3.Connection,
    *,
    job_type: str,
    stable_group_id: str,
) -> dict[str, Any]:
    if job_type not in {"incident_response_analysis", "ai_analysis"}:
        raise CohortError(f"unsupported durable job type: {job_type}")
    _require_columns(
        connection,
        "durable_jobs",
        {
            "id",
            "job_type",
            "dedupe_key",
            "payload_json",
            "status",
            "attempt_count",
            "requested_at",
            "updated_at",
            "completed_at",
            "last_completed_at",
        },
    )
    row = connection.execute(
        """
        SELECT id, job_type, dedupe_key, payload_json, status, attempt_count,
               requested_at, updated_at, completed_at, last_completed_at
        FROM durable_jobs
        WHERE job_type = ? AND dedupe_key = ?
        """,
        (job_type, stable_group_id),
    ).fetchone()
    if row is None:
        raise AmbiguousDispatchError(
            "dashboard accepted the request but exact durable job readback "
            "failed"
        )
    return dict(row)


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


def _frozen_analysis_ids(
    member: Mapping[str, Any],
    *,
    agent_role: str,
    pre_state_field: str,
) -> set[str]:
    pre_state = member.get("pre_state")
    if not isinstance(pre_state, dict):
        raise CohortError("frozen member pre-state is missing or malformed")
    prior_value = pre_state.get(pre_state_field)
    if (
        not isinstance(prior_value, list)
        or any(not isinstance(item, str) or not item for item in prior_value)
        or len(prior_value) != len(set(prior_value))
    ):
        raise CohortError(
            f"frozen {agent_role} analysis identity set is malformed"
        )
    return set(prior_value)


def _verify_zero_fresh_analyses(
    connection: sqlite3.Connection,
    member: Mapping[str, Any],
    stable_group_id: str,
    *,
    agent_role: str,
    pre_state_field: str,
) -> list[str]:
    """Prove no worker result raced the controlled dispatch readback."""

    prior_ids = _frozen_analysis_ids(
        member,
        agent_role=agent_role,
        pre_state_field=pre_state_field,
    )
    current_ids = set(
        _analysis_ids_for_group(
            connection,
            stable_group_id,
            agent_role=agent_role,
        )
    )
    if not prior_ids.issubset(current_ids):
        raise AmbiguousDispatchError(
            f"prior {agent_role} analysis identities changed during dispatch"
        )
    if current_ids - prior_ids:
        raise AmbiguousDispatchError(
            f"a fresh {agent_role} analysis appeared during the "
            "dispatch/readback window"
        )
    return sorted(current_ids)


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
        "incident_analysis_ids": _analysis_ids_for_group(
            connection,
            stable_group_id,
            agent_role="incident-responder",
        ),
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
    expected_release_id: str,
    expected_assigned_route: str = "codex-cli:gpt-5.5:high",
    expected_reviewer_route: str = "codex-cli:gpt-5.6-sol:xhigh",
    evaluation_profile: str = "",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Compatibility adapter for the extracted cohort-freezing workflow."""
    return run_freeze_cohort(
        _cohort_freeze_policy(),
        _cohort_freeze_sources(),
        database_path,
        manifest_path,
        cohort_id=cohort_id,
        reason=reason,
        count=count,
        expected_release_id=expected_release_id,
        expected_assigned_route=expected_assigned_route,
        expected_reviewer_route=expected_reviewer_route,
        evaluation_profile=evaluation_profile,
        dry_run=dry_run,
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
    if not REPRESENTATIVE_ALERT_ID_RE.fullmatch(representative_alert_id):
        raise CohortError(
            f"source row {dashboard_id} has an invalid representative "
            "alert ID"
        )
    return dashboard_id, stable_id, representative_alert_id


def _source_detection_projection(
    source: Mapping[str, Any],
) -> dict[str, Any]:
    supplied_detection = source.get("detection")
    if supplied_detection is not None and not isinstance(
        supplied_detection,
        dict,
    ):
        raise CohortError("source row detection must be an object")
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
    if "stable_group_key" in source:
        comparisons["stable_group_key"] = source["stable_group_key"]
    if (
        isinstance(supplied_detection, dict)
        and "stable_group_key" in supplied_detection
    ):
        comparisons["stable_group_key"] = supplied_detection[
            "stable_group_key"
        ]
    return comparisons


def _validate_source_detection(
    source: Mapping[str, Any],
    current: Mapping[str, Any],
    dashboard_id: str,
) -> dict[str, Any]:
    try:
        comparisons = _source_detection_projection(source)
    except CohortError as exc:
        raise CohortError(
            f"source row {dashboard_id} detection must be an object"
        ) from exc
    for key, value in comparisons.items():
        if key == "stable_group_key":
            # The summary table does not own this identity field. It is
            # compared against the exact raw alert by representative binding.
            continue
        if current.get(key) != value:
            raise CohortError(
                f"source row {dashboard_id} no longer matches frozen "
                f"detection field {key}"
            )
    return comparisons


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


def _cohort_freeze_policy() -> CohortFreezePolicy:
    return CohortFreezePolicy(
        schema=SCHEMA,
        maximum_cohort_size=MAX_COHORT_SIZE,
        dashboard_group_id_pattern=DASHBOARD_GROUP_ID_RE,
        stable_group_id_pattern=STABLE_GROUP_ID_RE,
        representative_alert_id_pattern=REPRESENTATIVE_ALERT_ID_RE,
    )


def _cohort_freeze_sources() -> CohortFreezeSources:
    """Bind legacy patch points to the extracted freezing workflow."""
    return CohortFreezeSources(
        error_type=CohortError,
        validate_cohort_identity=validate_cohort_identity,
        validate_release_id=validate_release_id,
        validate_agent_role=validate_agent_role,
        connect_read_only=connect_read_only,
        load_aliases=load_aliases,
        incident_cases=_incident_cases,
        summary_rows=_summary_rows,
        resolve_alias=resolve_alias,
        bind_representative_stable_group_key=(
            _bind_representative_stable_group_key
        ),
        validate_stable_group_key=validate_stable_group_key,
        validate_representative_binding=_validate_representative_binding,
        incident_pre_state=_pre_state,
        soc_pre_state=_soc_pre_state,
        source_identity=_source_identity,
        source_detection_projection=_source_detection_projection,
        validate_source_detection=_validate_source_detection,
        validate_source_pre_state=_validate_source_pre_state,
        ordered_identity_projection=ordered_identity_projection,
        utc_now=utc_now,
        sha256_value=sha256_value,
        execution_contract=execution_contract,
        schema_fingerprint=schema_fingerprint,
        frozen_plan_digest=_frozen_plan_digest,
        digest_bound=_digest_bound,
        write_private_json=write_private_json,
        load_private_source_rows=load_private_source_rows,
    )


def freeze_cohort_from_rows(
    database_path: Path,
    source_rows_path: Path,
    manifest_path: Path,
    *,
    cohort_id: str,
    reason: str,
    expected_count: int,
    expected_release_id: str,
    agent_role: str = "incident-responder",
    expected_assigned_route: str = "codex-cli:gpt-5.5:high",
    expected_reviewer_route: str = "codex-cli:gpt-5.6-sol:xhigh",
    evaluation_profile: str = "",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Compatibility adapter for exact imported-row cohort freezing."""
    return run_freeze_cohort_from_rows(
        _cohort_freeze_policy(),
        _cohort_freeze_sources(),
        database_path,
        source_rows_path,
        manifest_path,
        cohort_id=cohort_id,
        reason=reason,
        expected_count=expected_count,
        expected_release_id=expected_release_id,
        agent_role=agent_role,
        expected_assigned_route=expected_assigned_route,
        expected_reviewer_route=expected_reviewer_route,
        evaluation_profile=evaluation_profile,
        dry_run=dry_run,
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


def _alert_representative_identity(
    connection: sqlite3.Connection,
    alert_id: str,
) -> dict[str, Any] | None:
    required = {
        "alert_id",
        "stable_group_id",
        "stable_group_key",
        *FROZEN_REPRESENTATIVE_IMMUTABLE_FIELDS,
    }
    _require_columns(connection, "alerts", required)
    row = connection.execute(
        "SELECT "
        + ", ".join(sorted(required))
        + " FROM alerts WHERE alert_id = ?",
        (alert_id,),
    ).fetchone()
    return dict(row) if row else None


def _bind_representative_stable_group_key(
    connection: sqlite3.Connection,
    representative_alert_id: str,
    detection: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind the raw representative's group key into frozen evidence."""

    bound = dict(detection)
    if "stable_group_key" in bound:
        return bound
    alert = _alert_representative_identity(
        connection,
        representative_alert_id,
    )
    if alert is not None:
        bound["stable_group_key"] = alert.get("stable_group_key")
    return bound


def _validate_representative_binding(
    connection: sqlite3.Connection,
    member: Mapping[str, Any],
    current_representative_alert_id: str,
) -> dict[str, Any]:
    """Prove the frozen and current representatives remain one exact group."""

    dashboard_id = str(member["dashboard_group_id"])
    stable_id = str(member["stable_group_id"])
    stable_group_key = _member_stable_group_key(member)
    frozen_alert_id = str(member["representative_alert_id"])
    if not REPRESENTATIVE_ALERT_ID_RE.fullmatch(frozen_alert_id):
        raise CohortError(
            f"frozen representative alert ID is invalid for dashboard "
            f"group {dashboard_id}"
        )
    if not REPRESENTATIVE_ALERT_ID_RE.fullmatch(
        current_representative_alert_id
    ):
        raise CohortError(
            f"current representative alert ID is invalid for dashboard "
            f"group {dashboard_id}"
        )
    frozen_alert = _alert_representative_identity(
        connection,
        frozen_alert_id,
    )
    if frozen_alert is None:
        raise CohortError(
            f"frozen representative alert is missing for dashboard group "
            f"{dashboard_id}"
        )
    frozen_alert_stable = str(
        frozen_alert.get("stable_group_id") or ""
    )
    if frozen_alert_stable != stable_id:
        raise CohortError(
            f"frozen representative alert stable identity drift for "
            f"dashboard group {dashboard_id}"
        )

    detection = member.get("detection")
    if not isinstance(detection, dict):
        raise CohortError(
            f"frozen representative detection is missing for dashboard "
            f"group {dashboard_id}"
        )
    missing_fields = [
        field
        for field in FROZEN_REPRESENTATIVE_IMMUTABLE_FIELDS
        if field not in detection
    ]
    if missing_fields:
        raise CohortError(
            f"frozen representative detection is missing immutable fields "
            f"for dashboard group {dashboard_id}: "
            + ", ".join(missing_fields)
        )
    drifted_fields = [
        field
        for field in FROZEN_REPRESENTATIVE_IMMUTABLE_FIELDS
        if frozen_alert.get(field) != detection.get(field)
    ]
    if drifted_fields:
        raise CohortError(
            f"frozen representative immutable evidence drift for dashboard "
            f"group {dashboard_id}: "
            + ", ".join(drifted_fields)
        )

    current_alert = _alert_representative_identity(
        connection,
        current_representative_alert_id,
    )
    if current_alert is None:
        raise CohortError(
            f"current representative alert is missing for dashboard group "
            f"{dashboard_id}"
        )
    current_alert_stable = str(
        current_alert.get("stable_group_id") or ""
    )
    if current_alert_stable != stable_id:
        raise CohortError(
            f"current representative alert stable identity drift for "
            f"dashboard group {dashboard_id}"
        )
    frozen_group_key = validate_stable_group_key(
        frozen_alert.get("stable_group_key"),
        (
            "frozen representative alert stable_group_key for dashboard "
            f"group {dashboard_id}"
        ),
    )
    current_group_key = validate_stable_group_key(
        current_alert.get("stable_group_key"),
        (
            "current representative alert stable_group_key for dashboard "
            f"group {dashboard_id}"
        ),
    )
    if frozen_group_key != stable_group_key:
        raise CohortError(
            f"frozen representative alert stable group key drift for "
            f"dashboard group {dashboard_id}"
        )
    if frozen_group_key != current_group_key:
        raise CohortError(
            f"representative alert stable group key drift for dashboard "
            f"group {dashboard_id}"
        )

    immutable_projection = {
        field: frozen_alert.get(field)
        for field in FROZEN_REPRESENTATIVE_IMMUTABLE_FIELDS
    }
    return {
        "schema": REPRESENTATIVE_BINDING_SCHEMA,
        "representative_drifted": (
            current_representative_alert_id != frozen_alert_id
        ),
        "stable_group_id": stable_id,
        "stable_group_key": stable_group_key,
        "frozen_representative_alert_id": frozen_alert_id,
        "current_representative_alert_id": (
            current_representative_alert_id
        ),
        "immutable_fields": list(
            FROZEN_REPRESENTATIVE_IMMUTABLE_FIELDS
        ),
        "frozen_immutable_evidence_sha256": sha256_value(
            immutable_projection
        ),
        "stable_group_key_compatible": True,
    }


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
) -> dict[str, Any]:
    aliases = load_aliases(connection)
    dashboard_id = str(member["dashboard_group_id"])
    stable_id = str(member["stable_group_id"])
    identity = _current_summary_identity(connection, dashboard_id, aliases)
    if identity is None:
        raise CohortError(f"frozen dashboard group disappeared: {dashboard_id}")
    current_stable_id, current_representative_alert_id = identity
    if current_stable_id != stable_id:
        raise CohortError(
            f"frozen stable identity drift for dashboard group {dashboard_id}"
        )
    representative_binding = _validate_representative_binding(
        connection,
        member,
        current_representative_alert_id,
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
        return representative_binding
    frozen_incident_analysis_ids = _frozen_analysis_ids(
        member,
        agent_role="incident-responder",
        pre_state_field="incident_analysis_ids",
    )
    current_incident_analysis_ids = set(
        _analysis_ids_for_group(
            connection,
            stable_id,
            agent_role="incident-responder",
        )
    )
    if current_incident_analysis_ids != frozen_incident_analysis_ids:
        raise CohortError(
            f"Incident Responder analysis pre-state changed for stable "
            f"group {stable_id}"
        )
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
    return representative_binding


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


def load_evaluation_token(path: Path) -> str:
    """Read a fixed-size evaluation token from an owner-only regular file.

    The path, rather than the credential, is accepted by the CLI so the token
    never appears in process arguments.  Open the file without following
    symlinks and revalidate the opened inode to fail closed across replacement
    races.
    """

    target = path.expanduser()
    try:
        link_metadata = os.lstat(target)
    except OSError as exc:
        raise CohortError(
            "evaluation token file is missing or inaccessible"
        ) from exc
    if not stat.S_ISREG(link_metadata.st_mode):
        raise CohortError(
            "evaluation token file must be a regular non-symlink file"
        )
    mode = stat.S_IMODE(link_metadata.st_mode)
    if mode & 0o077:
        raise CohortError(
            "evaluation token file must be owner-only (0600 or stricter)"
        )
    if link_metadata.st_uid != os.geteuid():
        raise CohortError(
            "evaluation token file is not owned by the current user"
        )

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        file_descriptor = os.open(target, flags)
    except OSError as exc:
        raise CohortError(
            "evaluation token file could not be opened safely"
        ) from exc
    try:
        metadata = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_dev != link_metadata.st_dev
            or metadata.st_ino != link_metadata.st_ino
        ):
            raise CohortError(
                "evaluation token file changed during validation"
            )
        opened_mode = stat.S_IMODE(metadata.st_mode)
        if opened_mode & 0o077:
            raise CohortError(
                "evaluation token file must be owner-only (0600 or stricter)"
            )
        if metadata.st_uid != os.geteuid():
            raise CohortError(
                "evaluation token file is not owned by the current user"
            )
        if metadata.st_size != MAX_EVALUATION_TOKEN_BYTES:
            raise CohortError(
                "evaluation token must be exactly 64 lowercase hexadecimal characters"
            )
        raw = os.read(file_descriptor, MAX_EVALUATION_TOKEN_BYTES + 1)
        if (
            len(raw) != MAX_EVALUATION_TOKEN_BYTES
            or os.read(file_descriptor, 1)
        ):
            raise CohortError(
                "evaluation token must be exactly 64 lowercase hexadecimal characters"
            )
    finally:
        os.close(file_descriptor)
    try:
        token = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CohortError(
            "evaluation token must be exactly 64 lowercase hexadecimal characters"
        ) from exc
    if not SHA256_RE.fullmatch(token):
        raise CohortError(
            "evaluation token must be exactly 64 lowercase hexadecimal characters"
        )
    return token


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
    evaluation_token: str | None = None,
) -> HttpResult:
    body = canonical_bytes(payload)
    origin = urllib.parse.urlunsplit(
        (*urllib.parse.urlsplit(url)[:2], "", "", "")
    )
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": origin,
        "Sec-Fetch-Site": "same-origin",
        "X-Onion-Sentinel-Request": "dashboard",
    }
    if evaluation_token is not None:
        if not SHA256_RE.fullmatch(evaluation_token):
            raise CohortError("evaluation token is malformed")
        headers["X-Onion-Sentinel-Evaluation-Token"] = evaluation_token
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers=headers,
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
    dispatch_id = deterministic_dispatch_id(manifest, member)
    reason = f"[cohort:{cohort_id}] {manifest['reason']}"[:1000]
    requested_by = f"harness-cohort:{cohort_id}"[:100]
    release_id = validate_release_id(
        (manifest.get("execution_contract") or {}).get(
            "expected_release_id"
        ),
    )
    contract = manifest["execution_contract"]
    expected_assigned_route = str(contract["expected_assigned_route"])
    expected_reviewer_route = str(contract["expected_reviewer_route"])
    reviewer_required = contract["reviewer_required"]
    stable_group_key = _member_stable_group_key(member)
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
            "stable_group_id": str(member["stable_group_id"]),
            "stable_group_key": stable_group_key,
            "representative_alert_id": str(
                member["representative_alert_id"]
            ),
            "cohort_id": cohort_id,
            "dispatch_id": dispatch_id,
            "release_id": release_id,
            "expected_assigned_route": expected_assigned_route,
            "expected_reviewer_route": expected_reviewer_route,
            "reviewer_required": reviewer_required,
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
            "stable_group_id": str(member["stable_group_id"]),
            "stable_group_key": stable_group_key,
            "representative_alert_id": str(
                member["representative_alert_id"]
            ),
            "cohort_id": cohort_id,
            "dispatch_id": dispatch_id,
            "release_id": release_id,
            "expected_assigned_route": expected_assigned_route,
            "expected_reviewer_route": expected_reviewer_route,
            "reviewer_required": reviewer_required,
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
        payload = {
            "reason": reason,
            "requested_by": requested_by,
            "stable_group_id": str(member["stable_group_id"]),
            "stable_group_key": stable_group_key,
            "representative_alert_id": str(
                member["representative_alert_id"]
            ),
            "cohort_id": cohort_id,
            "dispatch_id": dispatch_id,
            "release_id": release_id,
            "expected_assigned_route": expected_assigned_route,
            "expected_reviewer_route": expected_reviewer_route,
            "reviewer_required": reviewer_required,
        }
    else:
        raise CohortError(f"unsupported dispatch kind: {dispatch_kind!r}")
    return base_url + path, payload


def _validate_success_response(
    manifest: Mapping[str, Any],
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
    contract = manifest["execution_contract"]
    route_identity = {
        "expected_assigned_route": contract["expected_assigned_route"],
        "expected_reviewer_route": contract["expected_reviewer_route"],
        "reviewer_required": contract["reviewer_required"],
    }
    if kind == "escalate":
        expected = {
            "group_id": member["dashboard_group_id"],
            "queue_group_id": member["stable_group_id"],
            "stable_group_id": member["stable_group_id"],
            "stable_group_key": _member_stable_group_key(member),
            "representative_alert_id": member["representative_alert_id"],
            "cohort_id": manifest["cohort_id"],
            "dispatch_id": deterministic_dispatch_id(manifest, member),
            "release_id": manifest["execution_contract"][
                "expected_release_id"
            ],
            **route_identity,
        }
        if any(payload.get(key) != value for key, value in expected.items()):
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
            "stable_group_id": member["stable_group_id"],
            "stable_group_key": _member_stable_group_key(member),
            "representative_alert_id": member["representative_alert_id"],
            "cohort_id": manifest["cohort_id"],
            "dispatch_id": deterministic_dispatch_id(manifest, member),
            "release_id": manifest["execution_contract"][
                "expected_release_id"
            ],
            **route_identity,
        }
        if any(payload.get(key) != value for key, value in expected.items()):
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
        expected = {
            "stable_group_id": member["stable_group_id"],
            "stable_group_key": _member_stable_group_key(member),
            "representative_alert_id": member["representative_alert_id"],
            "cohort_id": manifest["cohort_id"],
            "dispatch_id": deterministic_dispatch_id(manifest, member),
            "release_id": manifest["execution_contract"][
                "expected_release_id"
            ],
            **route_identity,
        }
        if any(payload.get(key) != value for key, value in expected.items()):
            raise AmbiguousDispatchError(
                "reanalysis response identity did not match the frozen member"
            )
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
                **expected,
                "run_id": run_id,
                "case_id": case_id,
                "run_status": str(payload.get("status") or ""),
                "created_at": str(payload.get("created_at") or ""),
            }
        )
    else:
        raise CohortError(f"unsupported dispatch kind: {kind!r}")
    return accepted


def _validate_dispatch_job_payload(
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    job: Mapping[str, Any],
    *,
    manual_reanalysis: bool,
    expected_case_id: str = "",
    expected_reanalysis_run_id: str = "",
) -> dict[str, Any]:
    raw_payload = job.get("payload_json")
    try:
        payload = json.loads(str(raw_payload))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AmbiguousDispatchError(
            "durable job payload is not valid JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise AmbiguousDispatchError(
            "durable job payload is not a JSON object"
        )

    cohort_present = bool(str(payload.get("cohort_id") or ""))
    dispatch_present = bool(str(payload.get("dispatch_id") or ""))
    if cohort_present != dispatch_present:
        raise AmbiguousDispatchError(
            "durable job cohort_id and dispatch_id must be present together"
        )
    expected = {
        "alert_id": member["representative_alert_id"],
        "representative_alert_id": member["representative_alert_id"],
        "group_id": member["stable_group_id"],
        "stable_group_id": member["stable_group_id"],
        "stable_group_key": _member_stable_group_key(member),
        "dashboard_group_id": member["dashboard_group_id"],
        "cohort_id": manifest["cohort_id"],
        "dispatch_id": deterministic_dispatch_id(manifest, member),
        "release_id": manifest["execution_contract"]["expected_release_id"],
        "expected_assigned_route": manifest["execution_contract"][
            "expected_assigned_route"
        ],
        "expected_reviewer_route": manifest["execution_contract"][
            "expected_reviewer_route"
        ],
        "reviewer_required": manifest["execution_contract"][
            "reviewer_required"
        ],
        "agent_role": manifest["agent_role"],
    }
    if expected_case_id:
        expected["case_id"] = expected_case_id
    if expected_reanalysis_run_id:
        expected["reanalysis_run_id"] = expected_reanalysis_run_id
    if any(payload.get(key) != value for key, value in expected.items()):
        raise AmbiguousDispatchError(
            "durable job payload identity did not match the frozen member"
        )
    if payload.get("manual_reanalysis") is not manual_reanalysis:
        raise AmbiguousDispatchError(
            "durable job manual_reanalysis did not match the dispatch kind"
        )
    return {
        **expected,
        "manual_reanalysis": manual_reanalysis,
        "payload_sha256": sha256_value(payload),
    }


def _verify_dispatch_readback(
    database_path: Path,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    accepted: Mapping[str, Any],
) -> dict[str, Any]:
    connection = connect_read_only(database_path)
    try:
        aliases = load_aliases(connection)
        stable_id = str(member["stable_group_id"])
        stable_group_key = _member_stable_group_key(member)
        kind = str((member.get("dispatch") or {}).get("kind") or "")
        if kind == "analyze":
            job = _durable_dispatch_job(
                connection,
                job_type="ai_analysis",
                stable_group_id=stable_id,
            )
            job_binding = _validate_dispatch_job_payload(
                manifest,
                member,
                job,
                manual_reanalysis=True,
            )
            _verify_zero_fresh_analyses(
                connection,
                member,
                stable_id,
                agent_role="soc-analyst",
                pre_state_field="soc_analysis_ids",
            )
            job_status = str(job.get("status") or "")
            if job_status not in ACTIVE_JOB_STATES:
                raise AmbiguousDispatchError(
                    "SOC analysis acceptance did not leave one exact active job"
                )
            return {
                "stable_group_id": stable_id,
                "stable_group_key": stable_group_key,
                "dashboard_group_id": str(member["dashboard_group_id"]),
                "representative_alert_id": str(
                    member["representative_alert_id"]
                ),
                "cohort_id": str(manifest["cohort_id"]),
                "dispatch_id": deterministic_dispatch_id(manifest, member),
                "release_id": str(
                    manifest["execution_contract"]["expected_release_id"]
                ),
                "expected_assigned_route": job_binding[
                    "expected_assigned_route"
                ],
                "expected_reviewer_route": job_binding[
                    "expected_reviewer_route"
                ],
                "reviewer_required": job_binding["reviewer_required"],
                "job_id": int(job["id"]),
                "job_status": job_status,
                "job_payload_sha256": job_binding["payload_sha256"],
                "analysis_id": "",
                "fresh_analysis_count": 0,
            }
        _verify_zero_fresh_analyses(
            connection,
            member,
            stable_id,
            agent_role="incident-responder",
            pre_state_field="incident_analysis_ids",
        )
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
            not in ACTIVE_AGENT_STATES
        ):
            raise AmbiguousDispatchError(
                "dashboard accepted the request but exact case readback failed"
            )
        output = {
            "case_id": case_id,
            "stable_group_id": stable_id,
            "stable_group_key": stable_group_key,
            "dashboard_group_id": str(member["dashboard_group_id"]),
            "representative_alert_id": str(member["representative_alert_id"]),
            "release_id": str(
                manifest["execution_contract"]["expected_release_id"]
            ),
            "expected_assigned_route": manifest["execution_contract"][
                "expected_assigned_route"
            ],
            "expected_reviewer_route": manifest["execution_contract"][
                "expected_reviewer_route"
            ],
            "reviewer_required": manifest["execution_contract"][
                "reviewer_required"
            ],
            "agent_status": str(case.get("agent_status") or ""),
            "fresh_analysis_count": 0,
        }
        if kind == "escalate":
            job = _durable_dispatch_job(
                connection,
                job_type="incident_response_analysis",
                stable_group_id=stable_id,
            )
            job_binding = _validate_dispatch_job_payload(
                manifest,
                member,
                job,
                manual_reanalysis=False,
                expected_case_id=case_id,
            )
            job_status = str(job.get("status") or "")
            if job_status not in ACTIVE_JOB_STATES:
                raise AmbiguousDispatchError(
                    "escalation acceptance did not leave one exact active job"
                )
            output.update(
                {
                    "cohort_id": str(manifest["cohort_id"]),
                    "dispatch_id": deterministic_dispatch_id(
                        manifest,
                        member,
                    ),
                    "job_id": int(job["id"]),
                    "job_status": job_status,
                    "job_payload_sha256": job_binding[
                        "payload_sha256"
                    ],
                }
            )
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
                not in ACTIVE_REANALYSIS_STATES
            ):
                raise AmbiguousDispatchError(
                    "dashboard accepted reanalysis but exact run readback failed"
                )
            job = _durable_dispatch_job(
                connection,
                job_type="incident_response_analysis",
                stable_group_id=stable_id,
            )
            job_binding = _validate_dispatch_job_payload(
                manifest,
                member,
                job,
                manual_reanalysis=True,
                expected_case_id=case_id,
                expected_reanalysis_run_id=run_id,
            )
            job_status = str(job.get("status") or "")
            if job_status not in ACTIVE_JOB_STATES:
                raise AmbiguousDispatchError(
                    "reanalysis acceptance did not leave one exact active job"
                )
            output.update(
                {
                    "run_id": run_id,
                    "run_case_status": str(row["status"]),
                    "queued_at": str(row["queued_at"] or ""),
                    "cohort_id": str(manifest["cohort_id"]),
                    "dispatch_id": deterministic_dispatch_id(
                        manifest,
                        member,
                    ),
                    "job_id": int(job["id"]),
                    "job_status": job_status,
                    "job_payload_sha256": job_binding[
                        "payload_sha256"
                    ],
                }
            )
        return output
    finally:
        connection.close()


def _monitor_dispatch_job_binding(
    connection: sqlite3.Connection,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> dict[str, Any]:
    """Re-prove the accepted durable job before trusting any monitor state."""

    dispatch = member.get("dispatch")
    if not isinstance(dispatch, dict):
        raise CohortError("accepted member has no dispatch record")
    accepted = dispatch.get("accepted")
    readback = dispatch.get("readback")
    if not isinstance(accepted, dict) or not isinstance(readback, dict):
        raise CohortError("accepted member has incomplete dispatch provenance")

    kind = str(dispatch.get("kind") or "")
    if kind not in {"analyze", "escalate", "reanalyze"}:
        raise CohortError(f"unsupported dispatch kind: {kind!r}")
    stable_id = str(member["stable_group_id"])
    stable_group_key = _member_stable_group_key(member)
    aliases = load_aliases(connection)
    current_identity = _current_summary_identity(
        connection,
        str(member["dashboard_group_id"]),
        aliases,
    )
    if current_identity is None or current_identity[0] != stable_id:
        raise CohortError(
            "frozen representative identity changed during monitoring"
        )
    representative_binding = _validate_representative_binding(
        connection,
        member,
        current_identity[1],
    )
    job_type = (
        "ai_analysis"
        if kind == "analyze"
        else "incident_response_analysis"
    )
    case_id = str(accepted.get("case_id") or "") if kind != "analyze" else ""
    run_id = (
        str(accepted.get("run_id") or "")
        if kind == "reanalyze"
        else ""
    )
    job = _durable_dispatch_job(
        connection,
        job_type=job_type,
        stable_group_id=stable_id,
    )
    binding = _validate_dispatch_job_payload(
        manifest,
        member,
        job,
        manual_reanalysis=kind != "escalate",
        expected_case_id=case_id,
        expected_reanalysis_run_id=run_id,
    )

    try:
        expected_job_id = int(readback.get("job_id"))
        current_job_id = int(job.get("id"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise CohortError("accepted dispatch has an invalid durable job ID") from exc
    if expected_job_id < 1 or current_job_id != expected_job_id:
        raise CohortError("accepted durable job identity changed during monitoring")

    expected_payload_sha256 = str(
        readback.get("job_payload_sha256") or ""
    )
    if (
        not SHA256_RE.fullmatch(expected_payload_sha256)
        or not _constant_time_equal(
            expected_payload_sha256,
            str(binding["payload_sha256"]),
        )
    ):
        raise CohortError("accepted durable job payload changed during monitoring")

    expected_dispatch_id = deterministic_dispatch_id(manifest, member)
    expected_cohort_id = str(manifest["cohort_id"])
    expected_release_id = str(
        manifest["execution_contract"]["expected_release_id"]
    )
    expected_assigned_route = str(
        manifest["execution_contract"]["expected_assigned_route"]
    )
    expected_reviewer_route = str(
        manifest["execution_contract"]["expected_reviewer_route"]
    )
    reviewer_required = manifest["execution_contract"][
        "reviewer_required"
    ]
    provenance_sources = (
        ("accepted response", accepted),
        ("durable readback", readback),
    )
    for label, source in provenance_sources:
        if (
            source.get("dispatch_id") != expected_dispatch_id
            or source.get("cohort_id") != expected_cohort_id
            or source.get("stable_group_key") != stable_group_key
            or source.get("release_id") != expected_release_id
            or source.get("expected_assigned_route")
            != expected_assigned_route
            or source.get("expected_reviewer_route")
            != expected_reviewer_route
            or source.get("reviewer_required") is not reviewer_required
        ):
            raise CohortError(
                f"{label} dispatch identity changed during monitoring"
            )
    if str(dispatch.get("dispatch_id") or "") != expected_dispatch_id:
        raise CohortError("member dispatch identity changed during monitoring")
    if _parse_timestamp(
        job.get("requested_at"),
        "accepted durable job requested_at",
    ) < _parse_timestamp(
        dispatch.get("started_at"),
        "accepted dispatch started_at",
    ):
        raise CohortError(
            "accepted durable job predates the dispatch POST window"
        )

    expected_readback = {
        "stable_group_id": stable_id,
        "stable_group_key": stable_group_key,
        "representative_alert_id": member["representative_alert_id"],
        "release_id": expected_release_id,
        "expected_assigned_route": expected_assigned_route,
        "expected_reviewer_route": expected_reviewer_route,
        "reviewer_required": reviewer_required,
    }
    if kind != "analyze":
        expected_readback["case_id"] = case_id
    if kind == "reanalyze":
        expected_readback["run_id"] = run_id
    if any(
        readback.get(field) != expected
        for field, expected in expected_readback.items()
    ):
        raise CohortError("durable readback identity changed during monitoring")

    return {
        key: value
        for key, value in job.items()
        if key != "payload_json"
    } | {
        "payload_sha256": binding["payload_sha256"],
        "cohort_id": expected_cohort_id,
        "dispatch_id": expected_dispatch_id,
        "release_id": expected_release_id,
        "expected_assigned_route": expected_assigned_route,
        "expected_reviewer_route": expected_reviewer_route,
        "reviewer_required": reviewer_required,
        "stable_group_id": stable_id,
        "stable_group_key": stable_group_key,
        "representative_alert_id": str(
            member["representative_alert_id"]
        ),
        "representative_binding_sha256": sha256_value(
            representative_binding
        ),
    }


Poster = Callable[[str, Mapping[str, Any]], HttpResult]


def queue_cohort(
    database_path: Path,
    manifest_path: Path,
    *,
    base_url: str,
    timeout: float = 15.0,
    dry_run: bool = False,
    poster: Poster | None = None,
    evaluation_token_file: Path | None = None,
) -> dict[str, Any]:
    manifest = load_private_manifest(manifest_path)
    base_url = validate_loopback_base_url(base_url)
    evaluation_token = (
        load_evaluation_token(evaluation_token_file)
        if evaluation_token_file is not None
        else None
    )
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
    dispatch_ids = [
        deterministic_dispatch_id(manifest, member)
        for member in manifest["members"]
    ]
    if len(dispatch_ids) != len(set(dispatch_ids)):
        raise CohortError("cohort members derived duplicate dispatch IDs")
    if dry_run:
        return manifest
    for member, dispatch_id in zip(manifest["members"], dispatch_ids):
        member["dispatch"]["dispatch_id"] = dispatch_id

    def do_post(url: str, payload: Mapping[str, Any]) -> HttpResult:
        if poster is not None:
            return poster(url, payload)
        return dashboard_post_json(
            url,
            payload,
            timeout=timeout,
            evaluation_token=evaluation_token,
        )

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
            representative_binding = validate_member_preflight(
                connection,
                member,
            )
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
                "representative_binding": representative_binding,
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
            accepted = _validate_success_response(manifest, member, result)
            readback = _verify_dispatch_readback(
                database_path,
                manifest,
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
    expected_alert_id: str,
    expected_agent_role: str = "incident-responder",
) -> dict[str, Any]:
    columns = _require_columns(
        connection,
        "ai_analysis_runs",
        {
            "analysis_id",
            "group_id",
            "alert_id",
            "agent_role",
            "response_json",
        },
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
        or str(item.get("alert_id") or "") != expected_alert_id
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
    item["response_canonical_sha256"] = alert_store_response_sha256(
        raw_response
    )
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
    second_opinion = (
        response.get("_second_opinion")
        if isinstance(response.get("_second_opinion"), dict)
        else {}
    )
    reviewer_response = (
        second_opinion.get("response")
        if isinstance(second_opinion.get("response"), dict)
        else {}
    )
    if second_opinion:
        item["result"]["_second_opinion"] = {
            "status": str(second_opinion.get("status") or ""),
            "model_route": str(second_opinion.get("model_route") or ""),
            "response": {
                "_analysis_model_route": str(
                    reviewer_response.get("_analysis_model_route") or ""
                )
            },
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


def _durable_job_monitor_state(job: Mapping[str, Any]) -> str:
    """Return the bound job state after validating its terminal timestamps."""

    status = str(job.get("status") or "")
    state = {
        "pending": "queued",
        "processing": "running",
        "completed": "completed",
        "failed": "failed",
    }.get(status)
    if state is None:
        raise CohortError(
            f"accepted durable job has unsupported status: {status!r}"
        )
    requested_at = _parse_timestamp(
        job.get("requested_at"),
        "accepted durable job requested_at",
    )
    updated_at = _parse_timestamp(
        job.get("updated_at"),
        "accepted durable job updated_at",
    )
    if updated_at < requested_at:
        raise CohortError(
            "accepted durable job timestamp order is inconsistent"
        )
    if status != "completed":
        return state
    completed_at = _parse_timestamp(
        job.get("completed_at"),
        "accepted durable job completed_at",
    )
    last_completed_at = _parse_timestamp(
        job.get("last_completed_at"),
        "accepted durable job last_completed_at",
    )
    if (
        completed_at < requested_at
        or last_completed_at < completed_at
        or updated_at < last_completed_at
    ):
        raise CohortError(
            "accepted durable job completion timestamps are inconsistent"
        )
    return state


def _validate_completed_analysis_job_window(
    *,
    dispatch: Mapping[str, Any],
    job: Mapping[str, Any],
    analysis: Mapping[str, Any],
) -> None:
    """Bind one credited analysis to its exact accepted job's lifetime."""

    if str(job.get("status") or "") != "completed":
        raise CohortError(
            "credited analysis does not belong to a completed durable job"
        )
    dispatch_started = _parse_timestamp(
        dispatch.get("started_at"),
        "credited dispatch started_at",
    )
    requested_at = _parse_timestamp(
        job.get("requested_at"),
        "credited durable job requested_at",
    )
    generated_at = _parse_timestamp(
        analysis.get("generated_at"),
        "credited analysis generated_at",
    )
    completed_at = _parse_timestamp(
        job.get("completed_at"),
        "credited durable job completed_at",
    )
    last_completed_at = _parse_timestamp(
        job.get("last_completed_at"),
        "credited durable job last_completed_at",
    )
    updated_at = _parse_timestamp(
        job.get("updated_at"),
        "credited durable job updated_at",
    )
    if (
        requested_at < dispatch_started
        or generated_at < dispatch_started
        or generated_at < requested_at
        or generated_at > completed_at
        or generated_at > last_completed_at
        or completed_at > last_completed_at
        or last_completed_at > updated_at
    ):
        raise CohortError(
            "credited analysis falls outside its exact durable job window"
        )


def monitor_member(
    connection: sqlite3.Connection,
    manifest: Mapping[str, Any],
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
    job = _monitor_dispatch_job_binding(connection, manifest, member)
    job_state = _durable_job_monitor_state(job)
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
        if new_ids and job_state == "completed":
            analysis_id = new_ids[0]
            state = "completed"
            analysis = _analysis_metadata(
                connection,
                analysis_id,
                stable_id,
                expected_alert_id=str(member["representative_alert_id"]),
                expected_agent_role="soc-analyst",
            )
            _validate_completed_analysis_job_window(
                dispatch=dispatch,
                job=job,
                analysis=analysis,
            )
        elif new_ids and job_state == "failed":
            raise CohortError(
                f"SOC job for {stable_id} failed but a fresh analysis exists"
            )
        else:
            analysis_id = ""
            state = job_state
            if state == "completed":
                raise CohortError(
                    f"SOC job for {stable_id} is completed "
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
    source_status = str(case.get("agent_status") or "")
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
        source_status = str(row["status"] or "")
        analysis_id = str(row["analysis_id"] or "")
    elif kind == "escalate":
        source_status = {
            "queued": "queued",
            "analyzing": "running",
            "analyzed": "completed",
            "failed": "failed",
        }.get(source_status, source_status or "unknown")
        analysis_id = str(case.get("latest_analysis_id") or "")
    else:
        raise CohortError(f"unsupported dispatch kind: {kind!r}")

    prior_ids = _frozen_analysis_ids(
        member,
        agent_role="incident-responder",
        pre_state_field="incident_analysis_ids",
    )
    current_ids = set(
        _analysis_ids_for_group(
            connection,
            stable_id,
            agent_role="incident-responder",
        )
    )
    if not prior_ids.issubset(current_ids):
        raise CohortError(
            f"prior Incident Responder analysis identity disappeared for "
            f"{stable_id}"
        )
    fresh_ids = sorted(current_ids - prior_ids)
    if len(fresh_ids) > 1:
        raise CohortError(
            f"more than one new Incident Responder analysis exists for "
            f"{stable_id}; the cohort result is ambiguous"
        )
    fresh_analysis_id = fresh_ids[0] if fresh_ids else ""
    if analysis_id and analysis_id != fresh_analysis_id:
        raise CohortError(
            f"incident result pointer is not the exact fresh analysis for "
            f"{stable_id}"
        )

    if job_state in {"queued", "running"}:
        status = job_state
        analysis_id = ""
    elif job_state == "failed":
        if source_status != "failed" or fresh_analysis_id:
            raise CohortError(
                f"incident result state disagrees with failed accepted job "
                f"for {stable_id}"
            )
        status = "failed"
        analysis_id = ""
    elif source_status == "skipped" and not fresh_analysis_id:
        status = "skipped"
        analysis_id = ""
    elif (
        source_status == "completed"
        and fresh_analysis_id
        and analysis_id == fresh_analysis_id
    ):
        status = "completed"
    else:
        raise CohortError(
            f"incident result state does not agree with completed accepted "
            f"job for {stable_id}"
        )

    analysis = (
        _analysis_metadata(
            connection,
            analysis_id,
            stable_id,
            expected_alert_id=str(member["representative_alert_id"]),
        )
        if analysis_id
        else None
    )
    if analysis is not None:
        _validate_completed_analysis_job_window(
            dispatch=dispatch,
            job=job,
            analysis=analysis,
        )
    return {
        "state": status,
        "checked_at": utc_now(),
        "case_id": case_id,
        "run_id": str(accepted.get("run_id") or ""),
        "analysis_id": analysis_id,
        "job": job,
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
            monitor = monitor_member(connection, manifest, member)
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
    identities: set[str] = set()
    for field in ("soc_analysis_ids", "incident_analysis_ids"):
        values = pre_state.get(field)
        if isinstance(values, list):
            identities.update(str(item) for item in values if str(item))
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
    second_opinion = (
        analysis_result.get("_second_opinion")
        if isinstance(analysis_result.get("_second_opinion"), dict)
        else {}
    )
    reviewer_response = (
        second_opinion.get("response")
        if isinstance(second_opinion.get("response"), dict)
        else {}
    )
    if contract.get("reviewer_required") is True and (
        second_opinion.get("status") != "completed"
        or second_opinion.get("model_route") != expected_reviewer_route
        or reviewer_response.get("_analysis_model_route")
        != expected_reviewer_route
    ):
        failures.append("analysis-reviewer-route-mismatch")

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
    reviewer = (
        trace.get("reviewer")
        if isinstance(trace.get("reviewer"), dict)
        else {}
    )
    model_call_contract = (
        models.get("model_call_contract")
        if isinstance(models.get("model_call_contract"), dict)
        else {}
    )
    terminal = (
        trace.get("terminal_execution_summary")
        if isinstance(trace.get("terminal_execution_summary"), dict)
        else {}
    )
    skill_attestation = (
        trace.get("skill_selection_attestation")
        if isinstance(trace.get("skill_selection_attestation"), dict)
        else {}
    )
    selected_skills = skill_attestation.get("selected")
    selected_skills = selected_skills if isinstance(selected_skills, list) else []
    skill_summary_selected: list[dict[str, Any]] = []
    skill_identity_valid = len(selected_skills) <= (
        MAX_ATTESTED_INVESTIGATION_SKILLS
    )
    for selected_skill in selected_skills:
        if not isinstance(selected_skill, dict):
            skill_identity_valid = False
            continue
        skill_id = str(selected_skill.get("id") or "")
        version = selected_skill.get("version")
        skill_sha256 = str(selected_skill.get("skill_sha256") or "")
        if (
            set(selected_skill) != {"id", "version", "skill_sha256"}
            or not SKILL_ID_RE.fullmatch(skill_id)
            or not isinstance(version, int)
            or isinstance(version, bool)
            or version < 1
            or not SHA256_RE.fullmatch(skill_sha256)
        ):
            skill_identity_valid = False
            continue
        skill_summary_selected.append(
            {
                "id": skill_id,
                "version": version,
                "skill_sha256": skill_sha256,
            }
        )
    registry_version = skill_attestation.get("registry_version")
    registry_sha256 = str(skill_attestation.get("registry_sha256") or "")
    selected_count = skill_attestation.get("selected_count")
    truncated = skill_attestation.get("truncated")
    advisory_mode = str(skill_attestation.get("advisory_mode") or "")
    skill_attestation_valid = (
        skill_attestation.get("present") is True
        and skill_attestation.get("legacy") is False
        and skill_attestation.get("valid") is True
        and skill_attestation.get("available") is True
        and skill_attestation.get("job_digest_bound") is True
        and skill_attestation.get("mandatory_ready") is True
        and skill_attestation.get("error_count") == 0
        and skill_attestation.get("errors") == []
        and isinstance(registry_version, int)
        and not isinstance(registry_version, bool)
        and registry_version > 0
        and SHA256_RE.fullmatch(registry_sha256) is not None
        and skill_identity_valid
        and len(skill_summary_selected) == len(selected_skills)
        and isinstance(selected_count, int)
        and not isinstance(selected_count, bool)
        and selected_count == len(skill_summary_selected)
        and isinstance(truncated, bool)
        and advisory_mode == "advisory_only"
    )
    if not skill_attestation_valid:
        failures.append("harness-skill-selection-attestation-invalid")
    skill_selection_summary = {
        "registry_version": registry_version,
        "registry_sha256": registry_sha256,
        "selected": skill_summary_selected,
        "selected_count": selected_count,
        "truncated": truncated,
        "advisory_mode": advisory_mode,
    }
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
    model_call_count = int(
        (trace.get("counts") or {}).get("model_calls") or 0
    )
    successful_model_call_count = int(
        models.get("successful_call_count") or 0
    )
    model_purpose_count = int(models.get("purpose_count") or 0)
    terminally_successful_model_purpose_count = int(
        models.get("terminally_successful_purpose_count") or 0
    )
    incomplete_model_purpose_count = int(
        models.get("incomplete_purpose_count") or 0
    )
    exact_reviewer_repair_count = int(
        models.get("exact_reviewer_repair_count") or 0
    )
    exact_adjudication_repair_count = int(
        models.get("exact_adjudication_repair_count") or 0
    )
    superseded_validation_failure_count = int(
        models.get("superseded_validation_failure_count") or 0
    )
    unexpected_unsuccessful_model_call_count = int(
        models.get("unexpected_unsuccessful_call_count") or 0
    )
    malformed_model_purpose_sequence_count = int(
        models.get("malformed_purpose_sequence_count") or 0
    )
    reviewer_model_call_count = int(
        reviewer.get("model_call_count") or 0
    )
    reviewer_completed_model_call_count = int(
        reviewer.get("completed_model_call_count") or 0
    )
    reviewer_supplemental_model_call_count = int(
        reviewer.get("supplemental_model_call_count") or 0
    )
    reviewer_supplemental_completed_model_call_count = int(
        reviewer.get("supplemental_completed_model_call_count") or 0
    )
    reviewer_primary_decision_count = int(
        reviewer.get("primary_decision_count") or 0
    )
    reviewer_decision_count = int(
        reviewer.get("reviewer_decision_count") or 0
    )
    if (
        contract.get("reviewer_required") is True
        and reviewer_model_call_count < 1
    ):
        failures.append("harness-required-reviewer-call-missing")
    if reviewer_model_call_count > 0 and (
        reviewer_completed_model_call_count
        != 1 + reviewer_supplemental_model_call_count
        or reviewer_primary_decision_count != 1
        or reviewer_decision_count != 1
        or reviewer.get("has_primary_decision") is not True
        or reviewer.get("has_reviewer_decision") is not True
        or reviewer.get("decision_comparable") is not True
        or reviewer.get("missing_reviewer_decision") is not False
        or reviewer_model_call_count
        != (
            1
            + exact_reviewer_repair_count
            + reviewer_supplemental_model_call_count
        )
        or reviewer_supplemental_model_call_count not in {0, 1}
        or reviewer_supplemental_completed_model_call_count
        != reviewer_supplemental_model_call_count
        or reviewer.get("completion_contract_required") is not True
        or reviewer.get("completion_contract_satisfied") is not True
        or reviewer.get("completion_contract_failure_reasons") != []
    ):
        failures.append("harness-reviewer-completion-incomplete")
    elif reviewer_model_call_count == 0 and (
        reviewer_completed_model_call_count != 0
        or reviewer_decision_count != 0
        or reviewer.get("has_reviewer_decision") is not False
        or reviewer.get("missing_reviewer_decision") is not False
        or reviewer.get("completion_contract_required") is not False
        or reviewer.get("completion_contract_satisfied") is not True
        or reviewer.get("completion_contract_failure_reasons") != []
    ):
        failures.append("harness-reviewer-completion-incomplete")
    model_call_facts = model_call_contract.get("facts")
    if (
        model_call_contract.get("schema") != MODEL_CALL_CONTRACT_SCHEMA
        or model_call_contract.get("valid") is not True
        or int(model_call_contract.get("model_call_count") or 0)
        != model_call_count
        or int(
            model_call_contract.get("canonical_model_call_count") or 0
        )
        != model_call_count
        or int(
            model_call_contract.get("noncanonical_model_call_count") or 0
        )
        != 0
        or int(
            model_call_contract.get("primary_initial_call_count") or 0
        )
        != 1
        or int(model_call_contract.get("violation_count") or 0) != 0
        or model_call_contract.get("violations") != []
        or model_call_contract.get("global_reasons") != []
        or not isinstance(model_call_facts, list)
        or len(model_call_facts) != model_call_count
        or len(model_call_facts) > MAX_RUNTIME_MODEL_CALLS
        or str(model_call_contract.get("facts_sha256") or "")
        != sha256_value(model_call_facts)
        or int(
            model_call_contract.get("reviewer_model_call_count") or 0
        )
        != reviewer_model_call_count
    ):
        failures.append("harness-model-call-contract-noncanonical")
    if (
        model_purpose_count < 1
        or terminally_successful_model_purpose_count
        != model_purpose_count
        or incomplete_model_purpose_count != 0
        or successful_model_call_count != model_purpose_count
        or model_call_count
        != (
            successful_model_call_count
            + superseded_validation_failure_count
        )
        or (
            exact_reviewer_repair_count
            + exact_adjudication_repair_count
        )
        != superseded_validation_failure_count
        or exact_reviewer_repair_count not in {0, 1}
        or exact_adjudication_repair_count not in {0, 1}
        or unexpected_unsuccessful_model_call_count != 0
        or malformed_model_purpose_sequence_count != 0
    ):
        failures.append("harness-model-purpose-incomplete")
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
        "release_id": str(contract.get("expected_release_id") or ""),
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
            "skill_selection_attestation_validated": True,
            "skill_selection_attestation": skill_selection_summary,
            "model_call_count": int(
                (trace.get("counts") or {}).get("model_calls") or 0
            ),
            "successful_model_call_count": successful_model_call_count,
            "successful_primary_model_call_count": int(
                models.get("successful_primary_call_count") or 0
            ),
            "model_purpose_count": model_purpose_count,
            "terminally_successful_model_purpose_count": (
                terminally_successful_model_purpose_count
            ),
            "incomplete_model_purpose_count": (
                incomplete_model_purpose_count
            ),
            "exact_reviewer_repair_count": (
                exact_reviewer_repair_count
            ),
            "exact_adjudication_repair_count": (
                exact_adjudication_repair_count
            ),
            "superseded_validation_failure_count": (
                superseded_validation_failure_count
            ),
            "unexpected_unsuccessful_model_call_count": (
                unexpected_unsuccessful_model_call_count
            ),
            "malformed_model_purpose_sequence_count": (
                malformed_model_purpose_sequence_count
            ),
            "model_call_contract": {
                "schema": str(model_call_contract.get("schema") or ""),
                "valid": model_call_contract.get("valid") is True,
                "model_call_count": int(
                    model_call_contract.get("model_call_count") or 0
                ),
                "canonical_model_call_count": int(
                    model_call_contract.get("canonical_model_call_count")
                    or 0
                ),
                "noncanonical_model_call_count": int(
                    model_call_contract.get("noncanonical_model_call_count")
                    or 0
                ),
                "primary_initial_call_count": int(
                    model_call_contract.get("primary_initial_call_count")
                    or 0
                ),
                "query_planning_call_count": int(
                    model_call_contract.get("query_planning_call_count")
                    or 0
                ),
                "query_planning_repair_call_count": int(
                    model_call_contract.get(
                        "query_planning_repair_call_count"
                    )
                    or 0
                ),
                "primary_followup_call_count": int(
                    model_call_contract.get("primary_followup_call_count")
                    or 0
                ),
                "reviewer_model_call_count": int(
                    model_call_contract.get("reviewer_model_call_count")
                    or 0
                ),
                "adjudicator_model_call_count": int(
                    model_call_contract.get("adjudicator_model_call_count")
                    or 0
                ),
                "facts": list(model_call_facts or []),
                "facts_sha256": str(
                    model_call_contract.get("facts_sha256") or ""
                ),
                "violation_count": int(
                    model_call_contract.get("violation_count") or 0
                ),
                "violations": list(
                    model_call_contract.get("violations") or []
                ),
                "global_reasons": list(
                    model_call_contract.get("global_reasons") or []
                ),
            },
            "reviewer_completion": {
                "model_call_count": reviewer_model_call_count,
                "completed_model_call_count": (
                    reviewer_completed_model_call_count
                ),
                "supplemental_model_call_count": (
                    reviewer_supplemental_model_call_count
                ),
                "supplemental_completed_model_call_count": (
                    reviewer_supplemental_completed_model_call_count
                ),
                "primary_decision_count": reviewer_primary_decision_count,
                "reviewer_decision_count": reviewer_decision_count,
                "has_primary_decision": (
                    reviewer.get("has_primary_decision") is True
                ),
                "has_reviewer_decision": (
                    reviewer.get("has_reviewer_decision") is True
                ),
                "decision_comparable": (
                    reviewer.get("decision_comparable") is True
                ),
                "missing_reviewer_decision": (
                    reviewer.get("missing_reviewer_decision") is True
                ),
                "completion_contract_required": (
                    reviewer.get("completion_contract_required") is True
                ),
                "completion_contract_satisfied": (
                    reviewer.get("completion_contract_satisfied") is True
                ),
                "completion_contract_failure_reasons": list(
                    reviewer.get("completion_contract_failure_reasons") or []
                ),
            },
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
                "stable_group_key": _member_stable_group_key(member),
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
    freeze.add_argument("--expected-release-id", required=True)
    freeze.add_argument("--expected-assigned-route", required=True)
    freeze.add_argument("--expected-reviewer-route", required=True)
    freeze.add_argument(
        "--evaluation-profile",
        default="",
        help=(
            "optional exact controlled campaign profile; the named profile "
            "pins its approved primary and reviewer routes"
        ),
    )
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
    imported.add_argument("--expected-release-id", required=True)
    imported.add_argument("--expected-assigned-route", required=True)
    imported.add_argument("--expected-reviewer-route", required=True)
    imported.add_argument(
        "--evaluation-profile",
        default="",
        help=(
            "optional exact controlled campaign profile; the named profile "
            "pins its approved primary and reviewer routes"
        ),
    )
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
        "--evaluation-token-file",
        type=Path,
        help=(
            "owner-only file containing the 64-character evaluation token; "
            "the token is sent only as an evaluation POST header"
        ),
    )
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
                expected_release_id=args.expected_release_id,
                expected_assigned_route=args.expected_assigned_route,
                expected_reviewer_route=args.expected_reviewer_route,
                evaluation_profile=args.evaluation_profile,
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
                expected_release_id=args.expected_release_id,
                agent_role=args.agent_role,
                expected_assigned_route=args.expected_assigned_route,
                expected_reviewer_route=args.expected_reviewer_route,
                evaluation_profile=args.evaluation_profile,
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
                evaluation_token_file=args.evaluation_token_file,
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
