#!/usr/bin/env python3
"""Verify harness event chains and terminal ledger-manifest binding."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence


@dataclass(frozen=True)
class TraceIntegrityPolicy:
    current_manifest_schema: str
    supported_manifest_schemas: frozenset[str]
    run_identity_columns_by_schema: Mapping[str, Sequence[str]]
    legacy_absent_started_fields: Mapping[str, Sequence[str]]
    terminal_statuses: frozenset[str]
    maximum_reported_errors: int
    digest_value: Callable[[Any], str]
    normalize_status: Callable[[object], str]
    error: type[RuntimeError]


@dataclass
class _Errors:
    maximum: int
    count: int = 0
    messages: list[str] = field(default_factory=list)

    def add(self, message: str) -> None:
        self.count += 1
        if len(self.messages) < self.maximum:
            self.messages.append(message)


def hypothesis_manifest_digest(
    rows: Iterable[Mapping[str, Any]], digest_value: Callable[[Any], str]
) -> str:
    projection = [
        {
            "hypothesis_id": str(row["hypothesis_id"]),
            "statement_digest": str(row["statement_digest"]),
            "status": str(row["status"]),
            "supporting_refs_json": str(row["supporting_refs_json"]),
            "contradicting_refs_json": str(row["contradicting_refs_json"]),
            "next_discriminator_digest": digest_value(
                str(row["next_discriminator"])
            ),
            "revision": int(row["revision"]),
        }
        for row in rows
    ]
    return digest_value(projection)


def ledger_manifest(
    ledgers: Mapping[str, Iterable[Mapping[str, Any]]],
    *,
    schema: str,
    policy: TraceIntegrityPolicy,
) -> dict[str, Any]:
    columns = _run_identity_columns(schema, policy)
    normalized = {
        table: _normalized_rows(table, source_rows, columns)
        for table, source_rows in ledgers.items()
    }
    return {
        "schema": schema,
        "tables": {
            table: {
                "count": len(rows),
                "sha256": policy.digest_value(rows),
            }
            for table, rows in sorted(normalized.items())
        },
    }


def _run_identity_columns(
    schema: str, policy: TraceIntegrityPolicy
) -> Sequence[str]:
    columns = policy.run_identity_columns_by_schema.get(schema)
    if columns is not None:
        return columns
    raise policy.error(f"unsupported ledger manifest schema: {schema}")


def _normalized_rows(
    table: str,
    source_rows: Iterable[Mapping[str, Any]],
    run_identity_columns: Sequence[str],
) -> list[dict[str, Any]]:
    rows = [dict(row) for row in source_rows]
    if table != "harness_run_identity":
        return rows
    return [
        {key: row[key] for key in run_identity_columns if key in row}
        for row in rows
    ]


def _event_body(run_id: str, row: Mapping[str, Any], sequence: int) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "sequence": sequence,
        "idempotency_key": row.get("idempotency_key"),
        "event_type": row.get("event_type"),
        "stage": row.get("stage"),
        "created_at": row.get("created_at"),
        "payload_sha256": row.get("payload_sha256"),
        "previous_event_sha256": row.get("previous_event_sha256"),
    }


def _verify_event(
    run_id: str,
    row: Mapping[str, Any],
    expected_sequence: int,
    previous: str,
    errors: _Errors,
    policy: TraceIntegrityPolicy,
) -> str:
    sequence = int(row.get("sequence"))
    payload = str(row.get("payload_json"))
    payload_digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    expected_hash = policy.digest_value(_event_body(run_id, row, sequence))
    checks = (
        (sequence == expected_sequence, f"sequence gap at {sequence}"),
        (row.get("payload_sha256") == payload_digest, f"payload digest mismatch at {sequence}"),
        (row.get("previous_event_sha256") == previous, f"previous hash mismatch at {sequence}"),
        (row.get("event_sha256") == expected_hash, f"event hash mismatch at {sequence}"),
        (row.get("event_id") == f"evt-{expected_hash[:32]}", f"event id mismatch at {sequence}"),
    )
    for valid, message in checks:
        if not valid:
            errors.add(message)
    return str(row.get("event_sha256") or "")


def _verify_events(
    run_id: str,
    events: Sequence[Mapping[str, Any]],
    errors: _Errors,
    policy: TraceIntegrityPolicy,
) -> str:
    previous = "0" * 64
    for position, row in enumerate(events, start=1):
        try:
            previous = _verify_event(
                run_id, row, position, previous, errors, policy
            )
        except (TypeError, ValueError, OverflowError) as exc:
            errors.add(f"malformed event at position {position}: {exc}")
    if not events:
        errors.add("run has no events")
    return previous


def _payload(row: Mapping[str, Any] | None) -> dict[str, Any]:
    if row is None:
        return {}
    try:
        value = json.loads(str(row.get("payload_json") or ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _verify_hypothesis_manifest(
    events: Sequence[Mapping[str, Any]],
    hypotheses: Sequence[Mapping[str, Any]],
    errors: _Errors,
    policy: TraceIntegrityPolicy,
) -> None:
    latest = next(
        (row for row in reversed(events) if row.get("event_type") == "hypotheses.updated"),
        None,
    )
    if latest is None:
        return
    expected = str(_payload(latest).get("manifest_digest") or "")
    actual = hypothesis_manifest_digest(hypotheses, policy.digest_value)
    if not expected:
        errors.add("latest hypothesis event has no manifest digest")
    elif expected != actual:
        errors.add("hypothesis ledger manifest mismatch")


def _terminal_event(
    events: Sequence[Mapping[str, Any]], normalized_status: str
) -> Mapping[str, Any] | None:
    return next(
        (
            row
            for row in reversed(events)
            if row.get("event_type") == f"run.{normalized_status}"
        ),
        None,
    )


def _manifest_schema_valid(
    schema: str,
    started_payload: Mapping[str, Any],
    errors: _Errors,
    policy: TraceIntegrityPolicy,
) -> bool:
    if schema not in policy.supported_manifest_schemas:
        errors.add("unsupported terminal ledger manifest schema")
        return False
    absent_fields = policy.legacy_absent_started_fields.get(schema, ())
    if any(field in started_payload for field in absent_fields):
        errors.add("terminal ledger manifest schema downgrade")
        return False
    return True


def _started_payload(events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    started = next(
        (row for row in events if row.get("event_type") == "run.started"),
        None,
    )
    return _payload(started)


def _verify_terminal_manifest(
    events: Sequence[Mapping[str, Any]],
    run_status: str,
    ledgers: Mapping[str, Iterable[Mapping[str, Any]]],
    required: bool,
    errors: _Errors,
    policy: TraceIntegrityPolicy,
) -> tuple[bool, str]:
    normalized = policy.normalize_status(run_status)
    if normalized not in policy.terminal_statuses:
        return False, ""
    terminal = _terminal_event(events, normalized)
    if terminal is None:
        errors.add("terminal run has no matching terminal event")
        return False, ""
    expected = _payload(terminal).get("ledger_manifest")
    if not isinstance(expected, dict):
        if required:
            errors.add("terminal ledger manifest is missing or malformed")
        return False, ""
    schema = str(expected.get("schema") or "")
    if not _manifest_schema_valid(
        schema,
        _started_payload(events),
        errors,
        policy,
    ):
        return False, schema
    actual = ledger_manifest(ledgers, schema=schema, policy=policy)
    if policy.digest_value(expected) != policy.digest_value(actual):
        errors.add("terminal ledger manifest mismatch")
    return True, schema


def verify_chain(
    run_id: str,
    events: Iterable[Mapping[str, Any]],
    hypotheses: Iterable[Mapping[str, Any]],
    *,
    run_status: str,
    ledgers: Mapping[str, Iterable[Mapping[str, Any]]],
    require_ledger_manifest: bool,
    policy: TraceIntegrityPolicy,
) -> dict[str, Any]:
    event_rows = list(events)
    hypothesis_rows = list(hypotheses)
    errors = _Errors(policy.maximum_reported_errors)
    head = _verify_events(run_id, event_rows, errors, policy)
    _verify_hypothesis_manifest(event_rows, hypothesis_rows, errors, policy)
    bound, schema = _verify_terminal_manifest(
        event_rows, run_status, ledgers, require_ledger_manifest, errors, policy
    )
    return {
        "valid": errors.count == 0,
        "event_count": len(event_rows),
        "head_sha256": head if event_rows else "",
        "ledger_manifest_bound": bound,
        "ledger_manifest_schema": schema,
        "ledger_manifest_required": require_ledger_manifest,
        "error_count": errors.count,
        "errors": errors.messages,
    }
