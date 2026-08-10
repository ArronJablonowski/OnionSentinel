"""Immutable job, metadata, skill, and ledger contracts for the harness."""
from __future__ import annotations

import dataclasses
import hashlib
import sqlite3
from typing import Any, Iterable, Mapping, Sequence

from harness_policy import (
    AgentRole,
    DIGEST_RE,
    HARNESS_SCHEMA,
    HarnessIntegrityError,
    HarnessPolicyError,
    IDENTIFIER_RE,
    INVESTIGATION_SKILL_ADVISORY_MODE,
    INVESTIGATION_SKILL_UNAVAILABLE_MODE,
    LEDGER_MANIFEST_SCHEMA,
    LEDGER_MANIFEST_SCHEMA_V1,
    MAX_ATTESTED_INVESTIGATION_SKILLS,
    MAX_EVENT_ITEMS,
    MAX_EVENT_PAYLOAD_BYTES,
    MAX_EVENT_STRING,
    SECRET_KEY_RE,
    SECRET_VALUE_PATTERNS,
    _model_route,
    _valid_identifier,
    canonical_json,
    digest_json,
    task_kind_for_role,
    utc_now,
)


def _redacted_string(value: object, maximum: int = MAX_EVENT_STRING) -> str:
    text = str(value or "")
    if any(pattern.search(text) for pattern in SECRET_VALUE_PATTERNS):
        return "[redacted-sensitive-value]"
    return text[:maximum]


def sanitize_metadata(
    value: Any,
    *,
    depth: int = 0,
    item_budget: list[int] | None = None,
) -> Any:
    """Return bounded audit metadata without prompt bodies or common secrets."""
    if item_budget is None:
        item_budget = [MAX_EVENT_ITEMS]
    if depth > 8 or item_budget[0] <= 0:
        return "[truncated]"
    item_budget[0] -= 1
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _redacted_string(value)
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for raw_key, child in list(value.items())[:MAX_EVENT_ITEMS]:
            if item_budget[0] <= 0:
                output["_truncated"] = True
                break
            key = _redacted_string(raw_key, 128)
            output[key] = (
                "[redacted-sensitive-field]"
                if SECRET_KEY_RE.search(key)
                else sanitize_metadata(
                    child,
                    depth=depth + 1,
                    item_budget=item_budget,
                )
            )
        return output
    if isinstance(value, Sequence) and not isinstance(
        value,
        (bytes, bytearray, memoryview),
    ):
        return [
            sanitize_metadata(item, depth=depth + 1, item_budget=item_budget)
            for item in list(value)[:MAX_EVENT_ITEMS]
            if item_budget[0] > 0
        ]
    return _redacted_string(value)


def bounded_metadata(value: Any) -> dict[str, Any]:
    sanitized = sanitize_metadata(value)
    if not isinstance(sanitized, dict):
        sanitized = {"value": sanitized}
    encoded = canonical_json(sanitized).encode("utf-8")
    if len(encoded) <= MAX_EVENT_PAYLOAD_BYTES:
        return sanitized
    return {
        "payload_omitted": True,
        "original_bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def investigation_skill_selection_attestation(
    prompt_package: Mapping[str, Any],
) -> dict[str, Any]:
    """Project prompt skill selection into a bounded, content-free identity.

    Skill bodies and alert context remain in the prompt package digest.  This
    separate projection makes the exact registry and selected skill versions
    easy to attest without copying guidance, evidence, telemetry, or secrets
    into the audit event stream.
    """
    raw = prompt_package.get("investigation_skills")
    if raw is None:
        return {
            "registry_version": 0,
            "registry_sha256": "",
            "selected": [],
            "selected_count": 0,
            "truncated": False,
            "advisory_mode": INVESTIGATION_SKILL_UNAVAILABLE_MODE,
        }
    if not isinstance(raw, Mapping):
        raise HarnessIntegrityError(
            "investigation skill selection must be an object"
        )
    registry_version = raw.get("registry_version")
    if (
        not isinstance(registry_version, int)
        or isinstance(registry_version, bool)
        or registry_version < 0
    ):
        raise HarnessIntegrityError(
            "investigation skill registry version is invalid"
        )
    registry_sha256 = str(raw.get("registry_sha256") or "")
    if not DIGEST_RE.fullmatch(registry_sha256):
        raise HarnessIntegrityError(
            "investigation skill registry digest is invalid"
        )
    if (
        raw.get("mode") != "shadow"
        or raw.get("enforcement") != INVESTIGATION_SKILL_ADVISORY_MODE
    ):
        raise HarnessIntegrityError(
            "investigation skills must remain advisory-only in shadow mode"
        )
    selected = raw.get("selected")
    if (
        not isinstance(selected, list)
        or len(selected) > MAX_ATTESTED_INVESTIGATION_SKILLS
    ):
        raise HarnessIntegrityError(
            "investigation skill selection exceeds its bounded list"
        )
    projected: list[dict[str, Any]] = []
    identities: set[tuple[str, int]] = set()
    for item in selected:
        if not isinstance(item, Mapping):
            raise HarnessIntegrityError(
                "selected investigation skill identity must be an object"
            )
        skill_id = str(item.get("id") or "")
        version = item.get("version")
        skill_sha256 = str(item.get("skill_sha256") or "")
        if not IDENTIFIER_RE.fullmatch(skill_id):
            raise HarnessIntegrityError(
                "selected investigation skill id is invalid"
            )
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version < 1
        ):
            raise HarnessIntegrityError(
                "selected investigation skill version is invalid"
            )
        if not DIGEST_RE.fullmatch(skill_sha256):
            raise HarnessIntegrityError(
                "selected investigation skill digest is invalid"
            )
        identity = (skill_id, version)
        if identity in identities:
            raise HarnessIntegrityError(
                "selected investigation skill identities must be unique"
            )
        identities.add(identity)
        projected.append(
            {
                "id": skill_id,
                "version": version,
                "skill_sha256": skill_sha256,
            }
        )
    selected_count = raw.get("selected_count")
    if (
        not isinstance(selected_count, int)
        or isinstance(selected_count, bool)
        or selected_count != len(projected)
    ):
        raise HarnessIntegrityError(
            "investigation skill selected count does not match selection"
        )
    truncated = raw.get("truncated")
    if not isinstance(truncated, bool):
        raise HarnessIntegrityError(
            "investigation skill truncation flag is invalid"
        )
    advisory_mode = INVESTIGATION_SKILL_ADVISORY_MODE
    if registry_version == 0:
        if projected or selected_count or truncated:
            raise HarnessIntegrityError(
                "unavailable investigation skill registry must be empty"
            )
        advisory_mode = INVESTIGATION_SKILL_UNAVAILABLE_MODE
    projected.sort(
        key=lambda item: (
            str(item["id"]),
            int(item["version"]),
            str(item["skill_sha256"]),
        )
    )
    return {
        "registry_version": registry_version,
        "registry_sha256": registry_sha256,
        "selected": projected,
        "selected_count": selected_count,
        "truncated": truncated,
        "advisory_mode": advisory_mode,
    }


def hypothesis_manifest_digest(rows: Iterable[Mapping[str, Any]]) -> str:
    manifest = [
        {
            "hypothesis_id": str(row["hypothesis_id"]),
            "statement_digest": str(row["statement_digest"]),
            "status": str(row["status"]),
            "supporting_refs_json": str(row["supporting_refs_json"]),
            "contradicting_refs_json": str(row["contradicting_refs_json"]),
            "next_discriminator_digest": digest_json(
                str(row["next_discriminator"])
            ),
            "revision": int(row["revision"]),
        }
        for row in rows
    ]
    return digest_json(manifest)


LEDGER_TABLE_ORDERS: tuple[tuple[str, str], ...] = (
    ("harness_evidence", "evidence_ref"),
    ("harness_hypotheses", "hypothesis_id"),
    ("harness_decisions", "created_at, decision_id"),
    ("harness_model_calls", "created_at, call_id"),
    ("harness_tool_calls", "round_number, call_id"),
    (
        "harness_budget_reservations",
        "reservation_type, reservation_id",
    ),
)
RUN_IDENTITY_COLUMNS = (
    "run_id",
    "trace_id",
    "correlation_id",
    "case_id",
    "alert_id",
    "role",
    "task_kind",
    "assigned_route",
    "assigned_reviewer_route",
    "prompt_digest",
    "evidence_manifest_digest",
    "configuration_digest",
    "policy_version",
    "policy_digest",
    "policy_mode",
    "parent_run_id",
    "job_digest",
    "started_at",
)
LEGACY_RUN_IDENTITY_COLUMNS_V1 = tuple(
    column
    for column in RUN_IDENTITY_COLUMNS
    if column != "assigned_reviewer_route"
)
SUPPORTED_LEDGER_MANIFEST_SCHEMAS = frozenset(
    {LEDGER_MANIFEST_SCHEMA_V1, LEDGER_MANIFEST_SCHEMA}
)


def ledger_manifest(
    connection: sqlite3.Connection,
    run_id: str,
    *,
    schema: str = LEDGER_MANIFEST_SCHEMA,
) -> dict[str, Any]:
    """Digest every non-event ledger at a terminal state.

    Table and ordering identifiers are closed constants above. Only the run ID
    is caller-controlled and it remains a bound SQL parameter.
    """
    if schema == LEDGER_MANIFEST_SCHEMA:
        run_identity_columns = RUN_IDENTITY_COLUMNS
    elif schema == LEDGER_MANIFEST_SCHEMA_V1:
        # Manifest v1 predates the separately bound reviewer assignment. Keep
        # this projection so a schema-v4 store can still verify terminal traces
        # produced before that column was added.
        run_identity_columns = LEGACY_RUN_IDENTITY_COLUMNS_V1
    else:
        raise HarnessIntegrityError(
            f"unsupported ledger manifest schema: {schema}"
        )
    tables: dict[str, dict[str, Any]] = {}
    run_identity = connection.execute(
        f"""
        SELECT {", ".join(run_identity_columns)}
        FROM harness_runs
        WHERE run_id = ?
        """,
        (run_id,),
    ).fetchone()
    run_identity_rows = [dict(run_identity)] if run_identity is not None else []
    tables["harness_run_identity"] = {
        "count": len(run_identity_rows),
        "sha256": digest_json(run_identity_rows),
    }
    for table, order_by in LEDGER_TABLE_ORDERS:
        rows = [
            dict(row)
            for row in connection.execute(
                f"SELECT * FROM {table} WHERE run_id = ? ORDER BY {order_by}",
                (run_id,),
            ).fetchall()
        ]
        tables[table] = {
            "count": len(rows),
            "sha256": digest_json(rows),
        }
    return {
        "schema": schema,
        "tables": tables,
    }


def approximate_evidence_rows(value: Any, *, depth: int = 0) -> int:
    """Conservatively count model-visible evidence records for budget checks."""
    if depth > 12:
        return 0
    if isinstance(value, Mapping):
        total = 0
        for raw_key, child in value.items():
            key = str(raw_key).strip().lower()
            if isinstance(child, list) and key in {
                "events",
                "hits",
                "parsed_evidence",
                "records",
                "results",
                "rows",
                "rows_preview",
                "samples",
            }:
                total += len(child)
                # Result containers can carry nested bounded result rows.
                if key == "results":
                    total += sum(
                        approximate_evidence_rows(item, depth=depth + 1)
                        for item in child
                    )
            else:
                total += approximate_evidence_rows(child, depth=depth + 1)
        return total
    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray, memoryview),
    ):
        return sum(
            approximate_evidence_rows(item, depth=depth + 1)
            for item in value
        )
    return 0


@dataclasses.dataclass(frozen=True)
class JobEnvelope:
    run_id: str
    trace_id: str
    correlation_id: str
    case_id: str
    alert_id: str
    role: str
    task_kind: str
    assigned_route: str
    assigned_reviewer_route: str
    prompt_digest: str
    evidence_manifest_digest: str
    configuration_digest: str
    skill_selection_attestation: dict[str, Any]
    parent_run_id: str
    created_at: str

    @classmethod
    def from_prompt(
        cls,
        *,
        run_id: str,
        prompt_package: Mapping[str, Any],
        role: str,
        assigned_route: str,
        configuration: Mapping[str, Any],
        reanalysis_attempt_id: str = "",
    ) -> "JobEnvelope":
        try:
            AgentRole(role)
        except ValueError as exc:
            raise HarnessPolicyError(f"unsupported agent role: {role}") from exc
        alert = (
            prompt_package.get("alert")
            if isinstance(prompt_package.get("alert"), dict)
            else {}
        )
        incident = (
            prompt_package.get("incident_response_evidence")
            if isinstance(prompt_package.get("incident_response_evidence"), dict)
            else {}
        )
        alert_id = str(alert.get("alert_id") or prompt_package.get("alert_id") or "")
        case_id = str(
            incident.get("case_id")
            or prompt_package.get("case_id")
            or alert_id
            or run_id
        )
        correlation_id = str(
            prompt_package.get("group_id")
            or (
                prompt_package.get("grouped_alert_context", {}).get("group_id")
                if isinstance(prompt_package.get("grouped_alert_context"), dict)
                else ""
            )
            or case_id
        )
        contract = prompt_package.get("evidence_reference_contract")
        if not isinstance(contract, dict):
            contract = {}
        task_kind = task_kind_for_role(
            role,
            reanalysis_attempt_id=reanalysis_attempt_id,
            manual_reanalysis=bool(prompt_package.get("manual_reanalysis")),
        )
        run_id = _valid_identifier(run_id, "run_id", 128)
        return cls(
            run_id=run_id,
            trace_id=hashlib.sha256(
                f"{HARNESS_SCHEMA}:{run_id}".encode("utf-8")
            ).hexdigest()[:32],
            correlation_id=_valid_identifier(
                correlation_id or run_id,
                "correlation_id",
            ),
            case_id=_valid_identifier(case_id or run_id, "case_id"),
            alert_id=(
                _valid_identifier(alert_id, "alert_id") if alert_id else ""
            ),
            role=role,
            task_kind=task_kind,
            assigned_route=_model_route(
                assigned_route,
                "assigned primary route",
            ),
            assigned_reviewer_route=_model_route(
                configuration.get("reviewer_route"),
                "assigned reviewer route",
                allow_empty=True,
            ),
            prompt_digest=digest_json(prompt_package),
            evidence_manifest_digest=digest_json(contract),
            configuration_digest=digest_json(configuration),
            skill_selection_attestation=(
                investigation_skill_selection_attestation(prompt_package)
            ),
            parent_run_id=str(
                prompt_package.get("parent_analysis_id")
                or prompt_package.get("prior_analysis_id")
                or ""
            )[:128],
            created_at=utc_now(),
        )

    @property
    def job_digest(self) -> str:
        value = dataclasses.asdict(self)
        value.pop("created_at", None)
        return digest_json(value)
