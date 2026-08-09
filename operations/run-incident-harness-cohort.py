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
from cohort_dispatch_contract import (
    CohortDispatchContract,
    request_for_member as build_dispatch_request,
    validate_dispatch_job_payload as validate_job_payload,
    validate_success_response as validate_dispatch_response,
)
from cohort_dispatch_readback import (
    CohortDispatchReadbackSources,
    verify_dispatch_readback as prove_dispatch_readback,
)
from cohort_dispatch_workflow import (
    CohortDispatchSources,
    Poster,
    queue_cohort as run_queue_cohort,
)
from cohort_http import (
    CohortHttpPolicy,
    HttpResult,
    dashboard_post_json as post_dashboard_json,
    load_evaluation_token as read_evaluation_token,
    validate_loopback_base_url as validate_dashboard_base_url,
)
from cohort_monitor_binding import (
    CohortMonitorBindingSources,
    monitor_dispatch_job_binding as prove_monitor_dispatch_binding,
)
from cohort_monitor_contract import (
    CohortMonitorContract,
    durable_job_monitor_state as resolve_durable_job_monitor_state,
    validate_completed_analysis_job_window as validate_analysis_job_window,
)
from cohort_monitor_workflow import (
    CohortMonitorSources,
    monitor_cohort as run_monitor_cohort,
    monitor_cohort_once as run_monitor_cohort_once,
    monitor_member as observe_monitor_member,
)
from cohort_execution_models import (
    ModelExecutionPolicy,
    evaluate_model_execution,
)
from cohort_execution_skills import (
    SkillAttestationPolicy,
    validate_skill_attestation,
)
from cohort_execution_tools import evaluate_tool_execution
from cohort_execution_trace import (
    TraceExecutionExpectation,
    TraceExecutionPolicy,
    evaluate_trace_execution,
)
from cohort_execution_render import ExecutionProofView, render_execution_proof
from cohort_execution_result import (
    ResultExecutionPolicy,
    evaluate_result_execution,
    expected_task_kind as resolve_expected_task_kind,
    prior_analysis_ids as collect_prior_analysis_ids,
)
from cohort_export import (
    CohortExportSources,
    export_cohort as run_export_cohort,
)
from cohort_query_audit_projection import project_query_audit
from cohort_evaluation_query_audit import (
    QueryAuditPolicy,
    query_audit_execution_binding as normalize_query_audit_binding,
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


def _cohort_http_policy() -> CohortHttpPolicy:
    return CohortHttpPolicy(
        maximum_http_body_bytes=MAX_HTTP_BODY_BYTES,
        evaluation_token_bytes=MAX_EVALUATION_TOKEN_BYTES,
        token_pattern=SHA256_RE,
        cohort_error=CohortError,
        ambiguous_dispatch_error=AmbiguousDispatchError,
        canonical_bytes=canonical_bytes,
    )


def validate_loopback_base_url(value: str) -> str:
    """Compatibility adapter for loopback-origin validation."""
    return validate_dashboard_base_url(_cohort_http_policy(), value)


def load_evaluation_token(path: Path) -> str:
    """Compatibility adapter for private evaluation-token loading."""
    return read_evaluation_token(_cohort_http_policy(), path)


def dashboard_post_json(
    url: str,
    payload: Mapping[str, Any],
    *,
    timeout: float,
    evaluation_token: str | None = None,
) -> HttpResult:
    """Compatibility adapter for bounded dashboard POST requests."""
    return post_dashboard_json(
        _cohort_http_policy(),
        url,
        payload,
        timeout=timeout,
        evaluation_token=evaluation_token,
    )


def _cohort_dispatch_contract() -> CohortDispatchContract:
    return CohortDispatchContract(
        cohort_error=CohortError,
        ambiguous_dispatch_error=AmbiguousDispatchError,
        case_id_pattern=CASE_ID_RE,
        run_id_pattern=RUN_ID_RE,
        validate_release_id=validate_release_id,
        member_stable_group_key=_member_stable_group_key,
        deterministic_dispatch_id=deterministic_dispatch_id,
        sha256_value=sha256_value,
    )


def _request_for_member(
    base_url: str,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Compatibility adapter for frozen dispatch request construction."""
    return build_dispatch_request(
        _cohort_dispatch_contract(), base_url, manifest, member
    )


def _validate_success_response(
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    result: HttpResult,
) -> dict[str, Any]:
    """Compatibility adapter for dashboard acceptance validation."""
    return validate_dispatch_response(
        _cohort_dispatch_contract(), manifest, member, result
    )


def _validate_dispatch_job_payload(
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    job: Mapping[str, Any],
    *,
    manual_reanalysis: bool,
    expected_case_id: str = "",
    expected_reanalysis_run_id: str = "",
) -> dict[str, Any]:
    """Compatibility adapter for durable dispatch payload validation."""
    return validate_job_payload(
        _cohort_dispatch_contract(),
        manifest,
        member,
        job,
        manual_reanalysis=manual_reanalysis,
        expected_case_id=expected_case_id,
        expected_reanalysis_run_id=expected_reanalysis_run_id,
    )


def _cohort_dispatch_readback_sources() -> CohortDispatchReadbackSources:
    return CohortDispatchReadbackSources(
        ambiguous_dispatch_error=AmbiguousDispatchError,
        active_job_states=frozenset(ACTIVE_JOB_STATES),
        active_agent_states=frozenset(ACTIVE_AGENT_STATES),
        active_reanalysis_states=frozenset(ACTIVE_REANALYSIS_STATES),
        connect_read_only=connect_read_only,
        load_aliases=load_aliases,
        member_stable_group_key=_member_stable_group_key,
        durable_dispatch_job=_durable_dispatch_job,
        validate_dispatch_job_payload=_validate_dispatch_job_payload,
        verify_zero_fresh_analyses=_verify_zero_fresh_analyses,
        deterministic_dispatch_id=deterministic_dispatch_id,
        case_for_stable=_case_for_stable,
        resolve_alias=resolve_alias,
    )


def _verify_dispatch_readback(
    database_path: Path,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    accepted: Mapping[str, Any],
) -> dict[str, Any]:
    """Compatibility adapter for durable dispatch readback proof."""
    return prove_dispatch_readback(
        _cohort_dispatch_readback_sources(),
        database_path,
        manifest,
        member,
        accepted,
    )


def _cohort_monitor_binding_sources() -> CohortMonitorBindingSources:
    return CohortMonitorBindingSources(
        cohort_error=CohortError,
        sha256_pattern=SHA256_RE,
        constant_time_equal=_constant_time_equal,
        member_stable_group_key=_member_stable_group_key,
        load_aliases=load_aliases,
        current_summary_identity=_current_summary_identity,
        validate_representative_binding=_validate_representative_binding,
        durable_dispatch_job=_durable_dispatch_job,
        validate_dispatch_job_payload=_validate_dispatch_job_payload,
        deterministic_dispatch_id=deterministic_dispatch_id,
        parse_timestamp=_parse_timestamp,
        sha256_value=sha256_value,
    )


def _monitor_dispatch_job_binding(
    connection: sqlite3.Connection,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> dict[str, Any]:
    """Compatibility adapter for monitor-time durable-job rebinding."""
    return prove_monitor_dispatch_binding(
        _cohort_monitor_binding_sources(), connection, manifest, member
    )


def _cohort_dispatch_sources() -> CohortDispatchSources:
    """Bind legacy queue patch points to the extracted dispatch workflow."""
    return CohortDispatchSources(
        cohort_error=CohortError,
        ambiguous_dispatch_error=AmbiguousDispatchError,
        load_private_manifest=load_private_manifest,
        validate_loopback_base_url=validate_loopback_base_url,
        load_evaluation_token=load_evaluation_token,
        validate_frozen_cohort=validate_frozen_cohort,
        deterministic_dispatch_id=deterministic_dispatch_id,
        utc_now=utc_now,
        write_private_json=write_private_json,
        connect_read_only=connect_read_only,
        validate_member_preflight=validate_member_preflight,
        request_for_member=_request_for_member,
        validate_success_response=_validate_success_response,
        verify_dispatch_readback=_verify_dispatch_readback,
        dashboard_post_json=dashboard_post_json,
        sha256_value=sha256_value,
    )


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
    """Compatibility adapter for the extracted cohort queue state machine."""
    return run_queue_cohort(
        _cohort_dispatch_sources(),
        database_path,
        manifest_path,
        base_url=base_url,
        timeout=timeout,
        dry_run=dry_run,
        poster=poster,
        evaluation_token_file=evaluation_token_file,
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
    return project_query_audit(response)


def _query_audit_policy() -> QueryAuditPolicy:
    return QueryAuditPolicy(
        successful_statuses=frozenset(
            {"ok", "complete", "completed", "success", "succeeded"}
        ),
        sha256_pattern=SHA256_RE,
        sha256_value=sha256_value,
    )


def _query_audit_execution_binding(
    analysis: Mapping[str, Any],
) -> dict[str, Any]:
    return normalize_query_audit_binding(analysis, _query_audit_policy())


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


def _cohort_monitor_contract() -> CohortMonitorContract:
    return CohortMonitorContract(
        cohort_error=CohortError,
        parse_timestamp=_parse_timestamp,
    )


def _durable_job_monitor_state(job: Mapping[str, Any]) -> str:
    """Compatibility adapter for durable-job monitor state validation."""
    return resolve_durable_job_monitor_state(_cohort_monitor_contract(), job)


def _validate_completed_analysis_job_window(
    *,
    dispatch: Mapping[str, Any],
    job: Mapping[str, Any],
    analysis: Mapping[str, Any],
) -> None:
    """Compatibility adapter for credited analysis time-window validation."""
    validate_analysis_job_window(
        _cohort_monitor_contract(),
        dispatch=dispatch,
        job=job,
        analysis=analysis,
    )


def _reanalysis_monitor_case(
    connection: sqlite3.Connection,
    run_id: str,
    case_id: str,
) -> dict[str, Any] | None:
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
    return dict(row) if row else None


def _cohort_monitor_sources() -> CohortMonitorSources:
    return CohortMonitorSources(
        cohort_error=CohortError,
        terminal_monitor_states=frozenset(TERMINAL_MONITOR_STATES),
        monitor_dispatch_job_binding=_monitor_dispatch_job_binding,
        durable_job_monitor_state=_durable_job_monitor_state,
        analysis_ids_for_group=_analysis_ids_for_group,
        analysis_metadata=_analysis_metadata,
        validate_completed_analysis_job_window=(
            _validate_completed_analysis_job_window
        ),
        second_opinion_metadata=_second_opinion_metadata,
        utc_now=utc_now,
        load_aliases=load_aliases,
        case_for_stable=_case_for_stable,
        reanalysis_run_case=_reanalysis_monitor_case,
        resolve_alias=resolve_alias,
        frozen_analysis_ids=_frozen_analysis_ids,
        load_private_manifest=load_private_manifest,
        connect_read_only=connect_read_only,
        write_private_json=write_private_json,
        monotonic=time.monotonic,
        sleep=time.sleep,
    )


def monitor_member(
    connection: sqlite3.Connection,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> dict[str, Any]:
    """Compatibility adapter for exact terminal member observation."""
    return observe_monitor_member(
        _cohort_monitor_sources(), connection, manifest, member
    )


def monitor_cohort_once(
    database_path: Path,
    manifest_path: Path,
) -> tuple[dict[str, Any], bool]:
    """Compatibility adapter for one sealed cohort monitor snapshot."""
    return run_monitor_cohort_once(
        _cohort_monitor_sources(), database_path, manifest_path
    )


def monitor_cohort(
    database_path: Path,
    manifest_path: Path,
    *,
    timeout: float,
    poll_interval: float,
) -> tuple[dict[str, Any], bool]:
    """Compatibility adapter for bounded cohort polling."""
    return run_monitor_cohort(
        _cohort_monitor_sources(),
        database_path,
        manifest_path,
        timeout=timeout,
        poll_interval=poll_interval,
    )


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
    """Compatibility adapter for frozen prior-analysis identities."""
    return collect_prior_analysis_ids(member)


def _expected_task_kind(role: str, dispatch_kind: str) -> str:
    """Compatibility adapter for role/dispatch task-kind binding."""
    return resolve_expected_task_kind(role, dispatch_kind, CohortError)


def _harness_execution_proof(
    *,
    harness_database_path: Path,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    monitor: Mapping[str, Any],
) -> dict[str, Any]:
    """Fail closed unless one fresh result has one valid successful trace."""

    result_execution = evaluate_result_execution(
        manifest,
        member,
        monitor,
        ResultExecutionPolicy(
            cohort_error=CohortError,
            parse_timestamp=_parse_timestamp,
        ),
    )
    role = result_execution.role
    contract = result_execution.contract
    dispatch = result_execution.dispatch
    analysis = result_execution.analysis
    analysis_id = result_execution.analysis_id
    expected_route = result_execution.expected_route
    expected_reviewer_route = result_execution.expected_reviewer_route
    dispatch_started = result_execution.dispatch_started
    analysis_generated = result_execution.analysis_generated
    failures = list(result_execution.failures)

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
    skill_attestation = (
        trace.get("skill_selection_attestation")
        if isinstance(trace.get("skill_selection_attestation"), dict)
        else {}
    )
    skill_selection_summary, skill_attestation_valid = (
        validate_skill_attestation(
            skill_attestation,
            SkillAttestationPolicy(
                skill_id_pattern=SKILL_ID_RE,
                sha256_pattern=SHA256_RE,
                maximum_selected=MAX_ATTESTED_INVESTIGATION_SKILLS,
            ),
        )
    )
    if not skill_attestation_valid:
        failures.append("harness-skill-selection-attestation-invalid")
    dispatch_kind = str(dispatch.get("kind") or "")
    trace_execution = evaluate_trace_execution(
        trace_report,
        trace,
        models,
        analysis,
        TraceExecutionExpectation(
            analysis_id=analysis_id,
            role=role,
            task_kind=_expected_task_kind(role, dispatch_kind),
            stable_group_id=str(member.get("stable_group_id") or ""),
            representative_alert_id=str(
                member.get("representative_alert_id") or ""
            ),
            harness_mode=str(contract.get("harness_mode") or ""),
            assigned_route=expected_route,
            reviewer_route=expected_reviewer_route,
        ),
        TraceExecutionPolicy(
            timestamp_error=CohortError,
            parse_timestamp=_parse_timestamp,
            sha256_pattern=SHA256_RE,
        ),
        dispatch_started=dispatch_started,
        analysis_generated=analysis_generated,
    )
    failures.extend(trace_execution.failures)
    integrity = trace_execution.integrity
    model_execution = evaluate_model_execution(
        trace,
        models,
        reviewer,
        model_call_contract,
        reviewer_required=contract.get("reviewer_required") is True,
        policy=ModelExecutionPolicy(
            contract_schema=MODEL_CALL_CONTRACT_SCHEMA,
            maximum_model_calls=MAX_RUNTIME_MODEL_CALLS,
            sha256_value=sha256_value,
        ),
    )
    failures.extend(model_execution.failures)
    query_audit_binding = _query_audit_execution_binding(analysis)
    tool_execution = evaluate_tool_execution(
        trace,
        routes,
        tools,
        query_audit_binding,
        role=role,
        sha256_value=sha256_value,
    )
    failures.extend(tool_execution.failures)

    if failures:
        raise CohortError(
            f"execution gate failed for {analysis_id}: "
            + ", ".join(sorted(set(failures)))
        )
    return render_execution_proof(
        ExecutionProofView(
            analysis_id=analysis_id,
            analysis_generated_at=str(analysis.get("generated_at") or ""),
            release_id=str(contract.get("expected_release_id") or ""),
            role=role,
            trace=trace,
            integrity=integrity,
            skill_selection=skill_selection_summary,
            model_execution=model_execution,
            tool_execution=tool_execution,
            submitted_response_sha256=(
                trace_execution.submitted_response_sha256
            ),
            response_canonical_sha256=(
                trace_execution.canonical_response_sha256
            ),
        ),
        sha256_value,
    )


def _cohort_export_sources() -> CohortExportSources:
    return CohortExportSources(
        cohort_error=CohortError,
        export_schema=EXPORT_SCHEMA,
        monitor_cohort_once=monitor_cohort_once,
        harness_execution_proof=_harness_execution_proof,
        member_stable_group_key=_member_stable_group_key,
        utc_now=utc_now,
        sha256_value=sha256_value,
        ordered_identity_projection=ordered_identity_projection,
        write_private_json=write_private_json,
    )


def export_cohort(
    database_path: Path,
    manifest_path: Path,
    output_path: Path,
    *,
    harness_database_path: Path | None = None,
) -> dict[str, Any]:
    """Compatibility adapter for a digest-sealed terminal cohort export."""
    return run_export_cohort(
        _cohort_export_sources(),
        database_path,
        manifest_path,
        output_path,
        harness_database_path=harness_database_path,
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
