"""Budget, model-call, and tool-call execution repository."""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from harness_contracts import _redacted_string
from harness_policy import (
    HarnessIntegrityError,
    HarnessPolicyError,
    Stage,
    _digest_or_hash,
    _valid_identifier,
    digest_json,
    utc_now,
)
from harness_store_foundation import _connect


def _reservation_rows(
    connection: Any,
    run_id: str,
    reservation_type: str,
    reservation_id: str,
) -> tuple[Any, Any]:
    existing = connection.execute(
        """
        SELECT amount
        FROM harness_budget_reservations
        WHERE run_id = ? AND reservation_type = ?
          AND reservation_id = ?
        """,
        (run_id, reservation_type, reservation_id),
    ).fetchone()
    totals = connection.execute(
        """
        SELECT COUNT(*) operation_count, COALESCE(SUM(amount), 0) total
        FROM harness_budget_reservations
        WHERE run_id = ? AND reservation_type = ?
        """,
        (run_id, reservation_type),
    ).fetchone()
    return existing, totals


def _existing_reservation_result(
    existing: Any,
    totals: Any,
    amount: int,
    preexisting_violations: Sequence[str],
) -> dict[str, Any]:
    if int(existing["amount"]) != amount:
        raise HarnessIntegrityError(
            "budget reservation collides with different amount"
        )
    return {
        "reserved": True,
        "existing": True,
        "operation_count": int(totals["operation_count"]),
        "total": int(totals["total"]),
        "violations": sorted(set(preexisting_violations)),
    }


def _budget_violation(
    reservation_type: str,
    *,
    total: bool,
) -> str:
    if reservation_type == "model-call":
        return "max_model_calls"
    return "max_queries_total" if total else "max_query_rounds"


def _new_reservation_result(
    connection: Any,
    *,
    run_id: str,
    reservation_type: str,
    reservation_id: str,
    amount: int,
    totals: Any,
    max_total: int,
    max_operations: int,
    enforce: bool,
    preexisting_violations: Sequence[str],
) -> dict[str, Any]:
    proposed_operations = int(totals["operation_count"]) + 1
    proposed_total = int(totals["total"]) + amount
    violations = list(preexisting_violations)
    if proposed_operations > int(max_operations):
        violations.append(_budget_violation(reservation_type, total=False))
    if proposed_total > int(max_total):
        violations.append(_budget_violation(reservation_type, total=True))
    reserved = not violations or not enforce
    if reserved:
        connection.execute(
            """
            INSERT INTO harness_budget_reservations(
                run_id, reservation_type, reservation_id, amount, created_at
            ) VALUES(?, ?, ?, ?, ?)
            """,
            (run_id, reservation_type, reservation_id, amount, utc_now()),
        )
    return {
        "reserved": reserved,
        "existing": False,
        "operation_count": proposed_operations,
        "total": proposed_total,
        "violations": sorted(set(violations)),
    }


def _model_call_values(
    *,
    purpose: str,
    requested_route: str,
    response: Mapping[str, Any],
    independent_review: bool,
    input_digest: str,
    output_digest: str,
    duration_ms: int,
    status: str,
) -> tuple[Any, ...]:
    return (
        _redacted_string(purpose, 160),
        str(requested_route or "")[:256],
        str(response.get("_analysis_model") or "")[:256],
        str(response.get("_analysis_model_path") or "")[:80],
        str(response.get("_analysis_provider") or "")[:80],
        str(response.get("_analysis_harness") or "")[:80],
        1 if independent_review else 0,
        str(status or "")[:80],
        _digest_or_hash(input_digest),
        output_digest,
        max(0, int(duration_ms)),
        utc_now(),
    )


def _persist_model_call(
    connection: Any,
    run_id: str,
    call_id: str,
    values: tuple[Any, ...],
) -> int:
    existing = connection.execute(
        """
        SELECT purpose, requested_route, observed_model,
               observed_model_path, observed_provider,
               observed_harness, independent_review, status,
               input_digest, output_digest, duration_ms, created_at
        FROM harness_model_calls
        WHERE run_id = ? AND call_id = ?
        """,
        (run_id, call_id),
    ).fetchone()
    if existing is not None:
        if tuple(existing)[:10] != values[:10]:
            raise HarnessIntegrityError(
                "model call_id collides with different call content"
            )
        return int(existing["duration_ms"])
    connection.execute(
        """
        INSERT INTO harness_model_calls(
            run_id, call_id, purpose, requested_route,
            observed_model, observed_model_path, observed_provider,
            observed_harness, independent_review, status,
            input_digest, output_digest, duration_ms, created_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, call_id, *values),
    )
    return int(values[10])


def _append_model_event(
    repository: Any,
    connection: Any,
    *,
    run_id: str,
    call_id: str,
    purpose: str,
    requested_route: str,
    response: Mapping[str, Any],
    independent_review: bool,
    output_digest: str,
    event_duration_ms: int,
    status: str,
    values: tuple[Any, ...],
) -> dict[str, Any]:
    model_stage = (
        Stage.INDEPENDENT_REVIEW.value
        if independent_review
        else Stage.PRIMARY_ANALYSIS.value
    )
    event = repository._append_event_tx(
        connection,
        run_id=run_id,
        event_type="model.completed",
        stage=model_stage,
        payload={
            "call_id": call_id,
            "purpose": purpose,
            "requested_route": requested_route,
            "observed_model": response.get("_analysis_model"),
            "observed_model_path": response.get("_analysis_model_path"),
            "observed_provider": response.get("_analysis_provider"),
            "observed_harness": response.get("_analysis_harness"),
            "independent_review": independent_review,
            "input_digest": values[8],
            "output_digest": output_digest,
            "duration_ms": event_duration_ms,
            "status": status,
        },
        idempotency_key=f"model.completed:{call_id}",
    )
    repository._update_run_stage_tx(
        connection,
        run_id=run_id,
        stage=model_stage,
        updated_at=event["created_at"],
        active_route=str(requested_route or ""),
    )
    return event


def _tool_call_values(
    *,
    round_number: int,
    backend: str,
    capability: str,
    purpose: str,
    request_digest: str,
    result_digest: str,
    status: str,
    read_only: bool,
    coverage: str,
    truncated: bool,
) -> tuple[Any, ...]:
    return (
        max(0, int(round_number)),
        str(backend or "")[:80],
        str(capability or "")[:120],
        _redacted_string(purpose, 500),
        _digest_or_hash(request_digest),
        _digest_or_hash(result_digest),
        str(status or "")[:80],
        1 if read_only else 0,
        str(coverage or "unknown")[:80],
        1 if truncated else 0,
        utc_now(),
    )


def _persist_tool_call(
    connection: Any,
    run_id: str,
    call_id: str,
    values: tuple[Any, ...],
) -> None:
    existing = connection.execute(
        """
        SELECT round_number, backend, capability, purpose,
               request_digest, result_digest, status, read_only,
               coverage, truncated, created_at
        FROM harness_tool_calls
        WHERE run_id = ? AND call_id = ?
        """,
        (run_id, call_id),
    ).fetchone()
    if existing is not None:
        if tuple(existing)[:10] != values[:10]:
            raise HarnessIntegrityError(
                "tool call_id collides with different call content"
            )
        return
    connection.execute(
        """
        INSERT INTO harness_tool_calls(
            run_id, call_id, round_number, backend, capability,
            purpose, request_digest, result_digest, status,
            read_only, coverage, truncated, created_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, call_id, *values),
    )


def _append_tool_event(
    repository: Any,
    connection: Any,
    *,
    run_id: str,
    call_id: str,
    values: tuple[Any, ...],
) -> dict[str, Any]:
    event = repository._append_event_tx(
        connection,
        run_id=run_id,
        event_type="tool.completed",
        stage=Stage.QUERY_EXECUTION.value,
        payload={
            "call_id": call_id,
            "round": values[0],
            "backend": values[1],
            "capability": values[2],
            "request_digest": values[4],
            "result_digest": values[5],
            "status": values[6],
            "read_only": bool(values[7]),
            "coverage": values[8],
            "truncated": bool(values[9]),
        },
        idempotency_key=f"tool.completed:{call_id}",
    )
    repository._update_run_stage_tx(
        connection,
        run_id=run_id,
        stage=Stage.QUERY_EXECUTION.value,
        updated_at=event["created_at"],
    )
    return event


class HarnessStoreExecutionRepository:
    """Atomic budget reservations and immutable execution ledgers."""

    def reserve_budget_operation(
        self,
        run_id: str,
        *,
        reservation_type: str,
        reservation_id: str,
        amount: int,
        max_total: int,
        max_operations: int,
        enforce: bool,
        preexisting_violations: Sequence[str] = (),
    ) -> dict[str, Any]:
        """Atomically reserve bounded work before a model or broker executes."""
        if reservation_type not in {"model-call", "query-round"}:
            raise HarnessPolicyError("unknown budget reservation type")
        reservation_id = _valid_identifier(reservation_id, "budget reservation_id", 128)
        amount = max(0, int(amount))
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_mutable_run_tx(connection, run_id)
            existing, totals = _reservation_rows(
                connection,
                run_id,
                reservation_type,
                reservation_id,
            )
            if existing is not None:
                result = _existing_reservation_result(
                    existing,
                    totals,
                    amount,
                    preexisting_violations,
                )
                connection.commit()
                return result
            result = _new_reservation_result(
                connection,
                run_id=run_id,
                reservation_type=reservation_type,
                reservation_id=reservation_id,
                amount=amount,
                totals=totals,
                max_total=max_total,
                max_operations=max_operations,
                enforce=enforce,
                preexisting_violations=preexisting_violations,
            )
            connection.commit()
        return result

    def record_model_call(
        self,
        run_id: str,
        *,
        call_id: str,
        purpose: str,
        requested_route: str,
        response: Mapping[str, Any],
        independent_review: bool,
        input_digest: str,
        duration_ms: int,
        status: str = "completed",
    ) -> None:
        call_id = _valid_identifier(call_id, "model call_id", 128)
        output_digest = digest_json(response)
        values = _model_call_values(
            purpose=purpose,
            requested_route=requested_route,
            response=response,
            independent_review=independent_review,
            input_digest=input_digest,
            output_digest=output_digest,
            duration_ms=duration_ms,
            status=status,
        )
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            event_duration_ms = _persist_model_call(
                connection,
                run_id,
                call_id,
                values,
            )
            event = _append_model_event(
                self,
                connection,
                run_id=run_id,
                call_id=call_id,
                purpose=purpose,
                requested_route=requested_route,
                response=response,
                independent_review=independent_review,
                output_digest=output_digest,
                event_duration_ms=event_duration_ms,
                status=status,
                values=values,
            )
            connection.commit()
        self._audit_event(event)

    def record_tool_call(
        self,
        run_id: str,
        *,
        call_id: str,
        round_number: int,
        backend: str,
        capability: str,
        purpose: str,
        request_digest: str,
        result_digest: str,
        status: str,
        read_only: bool,
        coverage: str,
        truncated: bool,
    ) -> None:
        call_id = _valid_identifier(call_id, "tool call_id", 128)
        values = _tool_call_values(
            round_number=round_number,
            backend=backend,
            capability=capability,
            purpose=purpose,
            request_digest=request_digest,
            result_digest=result_digest,
            status=status,
            read_only=read_only,
            coverage=coverage,
            truncated=truncated,
        )
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            _persist_tool_call(connection, run_id, call_id, values)
            event = _append_tool_event(
                self,
                connection,
                run_id=run_id,
                call_id=call_id,
                values=values,
            )
            connection.commit()
        self._audit_event(event)
