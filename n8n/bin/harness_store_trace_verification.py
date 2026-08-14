"""Read-only event-chain and terminal-ledger integrity verification."""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Callable, Iterable, Mapping

from harness_contracts import (
    SUPPORTED_LEDGER_MANIFEST_SCHEMAS,
    hypothesis_manifest_digest,
    ledger_manifest,
)
from harness_policy import (
    LEDGER_MANIFEST_SCHEMA_V1,
    LEDGER_MANIFEST_SCHEMA_V2,
    HarnessIntegrityError,
    RunStatus,
    digest_json,
)


ConnectionFactory = Callable[[Any], Iterable[Any]]


def _digest_matches(observed: object, expected: object) -> bool:
    """Compare text/byte digests in constant time without changing equality."""
    if type(observed) is type(expected) and isinstance(observed, (str, bytes)):
        return hmac.compare_digest(observed, expected)
    return observed == expected


def _load_verification_state(connection, run_id: str) -> tuple:
    run = connection.execute(
        "SELECT status FROM harness_runs WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    if run is None:
        raise HarnessIntegrityError("unknown harness run")
    rows = connection.execute(
        """
        SELECT * FROM harness_events
        WHERE run_id = ?
        ORDER BY sequence
        """,
        (run_id,),
    ).fetchall()
    actual_ledger_manifests = {
        schema: ledger_manifest(connection, run_id, schema=schema)
        for schema in SUPPORTED_LEDGER_MANIFEST_SCHEMAS
    }
    hypothesis_rows = connection.execute(
        """
        SELECT hypothesis_id, statement_digest, status,
               supporting_refs_json, contradicting_refs_json,
               next_discriminator, revision
        FROM harness_hypotheses
        WHERE run_id = ?
        ORDER BY hypothesis_id
        """,
        (run_id,),
    ).fetchall()
    return run, rows, actual_ledger_manifests, hypothesis_rows


def _verify_event_chain(
    run_id: str,
    rows: Iterable[Mapping[str, Any]],
) -> tuple[list[str], str, int]:
    previous = "0" * 64
    errors: list[str] = []
    expected_sequence = 1
    event_count = 0
    for row in rows:
        event_count += 1
        payload_hash = hashlib.sha256(
            str(row["payload_json"]).encode("utf-8")
        ).hexdigest()
        body = {
            "run_id": run_id,
            "sequence": int(row["sequence"]),
            "idempotency_key": row["idempotency_key"],
            "event_type": row["event_type"],
            "stage": row["stage"],
            "created_at": row["created_at"],
            "payload_sha256": row["payload_sha256"],
            "previous_event_sha256": row["previous_event_sha256"],
        }
        expected_hash = digest_json(body)
        if int(row["sequence"]) != expected_sequence:
            errors.append(f"sequence gap at {row['sequence']}")
        if not _digest_matches(row["payload_sha256"], payload_hash):
            errors.append(f"payload digest mismatch at {row['sequence']}")
        if not _digest_matches(row["previous_event_sha256"], previous):
            errors.append(f"previous hash mismatch at {row['sequence']}")
        if not _digest_matches(row["event_sha256"], expected_hash):
            errors.append(f"event hash mismatch at {row['sequence']}")
        if not _digest_matches(row["event_id"], f"evt-{expected_hash[:32]}"):
            errors.append(f"event id mismatch at {row['sequence']}")
        previous = str(row["event_sha256"])
        expected_sequence += 1
    return errors, previous, event_count


def _latest_event(rows: Iterable[Mapping[str, Any]], event_type: str):
    return next(
        (row for row in reversed(rows) if row["event_type"] == event_type),
        None,
    )


def _event_payload(event: Mapping[str, Any] | None) -> dict:
    try:
        value = json.loads(event["payload_json"]) if event is not None else {}
    except (TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else value


def _verify_hypothesis_manifest(
    rows: list[Mapping[str, Any]],
    hypothesis_rows: Iterable[Mapping[str, Any]],
    errors: list[str],
) -> None:
    latest_event = _latest_event(rows, "hypotheses.updated")
    if latest_event is None:
        return
    payload = _event_payload(latest_event)
    expected_manifest = str(payload.get("manifest_digest") or "")
    actual_manifest = hypothesis_manifest_digest(hypothesis_rows)
    if not expected_manifest:
        errors.append("latest hypothesis event has no manifest digest")
    elif not _digest_matches(expected_manifest, actual_manifest):
        errors.append("hypothesis ledger manifest mismatch")


def _legacy_manifest_eligible(
    rows: list[Mapping[str, Any]],
    schema: str,
) -> bool:
    started_event = next(
        (row for row in rows if row["event_type"] == "run.started"),
        None,
    )
    started_payload = _event_payload(started_event)
    if started_event is None or not isinstance(started_payload, dict):
        return False
    if schema == LEDGER_MANIFEST_SCHEMA_V1:
        return not {
            "assigned_reviewer_route",
            "execution_contract",
            "execution_contract_digest",
        }.intersection(started_payload)
    if schema == LEDGER_MANIFEST_SCHEMA_V2:
        return not {
            "execution_contract",
            "execution_contract_digest",
        }.intersection(started_payload)
    return False


def _verify_terminal_manifest(
    run: Mapping[str, Any],
    rows: list[Mapping[str, Any]],
    actual_manifests: Mapping[str, Mapping[str, Any]],
    errors: list[str],
) -> tuple[bool, str]:
    if run["status"] not in {
        RunStatus.SUCCEEDED.value,
        RunStatus.FAILED.value,
        RunStatus.CANCELLED.value,
    }:
        return False, ""
    terminal_event = _latest_event(rows, f"run.{run['status']}")
    if terminal_event is None:
        errors.append("terminal run has no matching terminal event")
        return False, ""
    terminal_payload = _event_payload(terminal_event)
    expected_manifest = terminal_payload.get("ledger_manifest")
    if not isinstance(expected_manifest, dict):
        errors.append("terminal ledger manifest is missing or malformed")
        return False, ""
    schema = str(expected_manifest.get("schema") or "")
    actual_manifest = actual_manifests.get(schema)
    if (
        schema in {LEDGER_MANIFEST_SCHEMA_V1, LEDGER_MANIFEST_SCHEMA_V2}
        and not _legacy_manifest_eligible(rows, schema)
    ):
        errors.append("terminal ledger manifest schema downgrade")
        return False, schema
    if actual_manifest is None:
        errors.append("unsupported terminal ledger manifest schema")
        return False, schema
    if not _digest_matches(digest_json(expected_manifest), digest_json(actual_manifest)):
        errors.append("terminal ledger manifest mismatch")
    return True, schema


def verify_trace_chain(
    path: Any,
    run_id: str,
    *,
    connection_factory: ConnectionFactory,
) -> dict[str, Any]:
    """Verify one persisted trace without mutating its database or audit log."""
    with connection_factory(path) as connection:
        run, rows, actual_manifests, hypothesis_rows = _load_verification_state(
            connection,
            run_id,
        )
    errors, previous, event_count = _verify_event_chain(run_id, rows)
    _verify_hypothesis_manifest(rows, hypothesis_rows, errors)
    manifest_bound, manifest_schema = _verify_terminal_manifest(
        run,
        rows,
        actual_manifests,
        errors,
    )
    return {
        "run_id": run_id,
        "valid": not errors and bool(rows),
        "event_count": event_count,
        "head_sha256": previous if rows else "",
        "ledger_manifest_bound": manifest_bound,
        "ledger_manifest_schema": manifest_schema,
        "errors": errors,
    }
