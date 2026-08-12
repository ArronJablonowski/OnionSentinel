"""Atomic evidence-bound hypothesis normalization and persistence."""
from __future__ import annotations

import re
from typing import Any, Callable, Mapping, Sequence

from harness_contracts import (
    _redacted_string,
    hypothesis_manifest_digest,
)
from harness_policy import (
    HarnessIntegrityError,
    MAX_DECISION_EVIDENCE_REFS,
    MAX_HYPOTHESES,
    Stage,
    canonical_json,
    digest_json,
    utc_now,
)


def record_hypotheses(
    repository: Any,
    run_id: str,
    hypotheses: Any,
    *,
    revision: int,
    connect: Callable[[Any], Any],
) -> dict[str, int]:
    """Persist one bounded revision and its manifest event atomically."""
    if not isinstance(hypotheses, list):
        return {"accepted": 0, "rejected": 0}
    with connect(repository.path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        known_refs = _known_evidence_refs(connection, run_id)
        accepted, rejected = _persist_hypothesis_items(
            connection,
            run_id=run_id,
            hypotheses=hypotheses,
            revision=revision,
            known_refs=known_refs,
        )
        event = _append_hypothesis_event(
            repository,
            connection,
            run_id=run_id,
            revision=revision,
            accepted=accepted,
            rejected=rejected,
        )
        repository._update_run_stage_tx(
            connection,
            run_id=run_id,
            stage=Stage.EVIDENCE_SYNTHESIS.value,
            updated_at=event["created_at"],
        )
        connection.commit()
    repository._audit_event(event)
    return {"accepted": accepted, "rejected": rejected}


def _known_evidence_refs(connection: Any, run_id: str) -> set[str]:
    return {
        str(row["evidence_ref"])
        for row in connection.execute(
            "SELECT evidence_ref FROM harness_evidence WHERE run_id = ?",
            (run_id,),
        ).fetchall()
    }


def _persist_hypothesis_items(
    connection: Any,
    *,
    run_id: str,
    hypotheses: Sequence[Any],
    revision: int,
    known_refs: set[str],
) -> tuple[int, int]:
    accepted = 0
    rejected = 0
    for index, item in enumerate(hypotheses[:MAX_HYPOTHESES], 1):
        normalized = _normalize_hypothesis(item, index, known_refs)
        if normalized is None:
            rejected += 1
            continue
        _persist_hypothesis(
            connection,
            run_id=run_id,
            revision=revision,
            normalized=normalized,
        )
        accepted += 1
    return accepted, rejected


def _normalize_hypothesis(
    item: Any,
    index: int,
    known_refs: set[str],
) -> dict[str, str] | None:
    if not isinstance(item, dict):
        return None
    hypothesis_id = re.sub(
        r"[^A-Za-z0-9._-]+",
        "-",
        str(item.get("id") or f"hypothesis-{index}"),
    ).strip("-")[:64]
    statement = _redacted_string(
        str(item.get("statement") or "").strip(),
        4_000,
    )
    status = str(item.get("status") or "unresolved").strip().lower()
    if (
        not hypothesis_id
        or not statement
        or status not in {"supported", "contradicted", "unresolved"}
    ):
        return None
    supporting = _known_references(item, "supporting_evidence", known_refs)
    contradicting = _known_references(item, "contradicting_evidence", known_refs)
    if status == "supported" and not supporting:
        status = "unresolved"
    elif status == "contradicted" and not contradicting:
        status = "unresolved"
    return {
        "hypothesis_id": hypothesis_id,
        "statement": statement,
        "statement_digest": digest_json(statement),
        "status": status,
        "supporting_json": canonical_json(supporting),
        "contradicting_json": canonical_json(contradicting),
        "next_discriminator": _redacted_string(
            item.get("next_discriminator"),
            2_000,
        ),
    }


def _known_references(
    item: Mapping[str, Any],
    key: str,
    known_refs: set[str],
) -> list[str]:
    values = item.get(key) if isinstance(item.get(key), list) else []
    return [
        str(ref)[:512]
        for ref in values[:MAX_DECISION_EVIDENCE_REFS]
        if str(ref) in known_refs
    ]


def _persist_hypothesis(
    connection: Any,
    *,
    run_id: str,
    revision: int,
    normalized: Mapping[str, str],
) -> None:
    normalized_revision = max(0, int(revision))
    existing = connection.execute(
        """
        SELECT statement_digest, status, supporting_refs_json,
               contradicting_refs_json, next_discriminator, revision
        FROM harness_hypotheses
        WHERE run_id = ? AND hypothesis_id = ?
        """,
        (run_id, normalized["hypothesis_id"]),
    ).fetchone()
    content = _hypothesis_content(normalized)
    _admit_hypothesis_revision(existing, content, normalized_revision)
    connection.execute(
        """
        INSERT INTO harness_hypotheses(
            run_id, hypothesis_id, statement, statement_digest,
            status, supporting_refs_json, contradicting_refs_json,
            next_discriminator, revision, updated_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(run_id, hypothesis_id) DO UPDATE SET
            statement = excluded.statement,
            statement_digest = excluded.statement_digest,
            status = excluded.status,
            supporting_refs_json = excluded.supporting_refs_json,
            contradicting_refs_json = excluded.contradicting_refs_json,
            next_discriminator = excluded.next_discriminator,
            revision = excluded.revision,
            updated_at = excluded.updated_at
        WHERE excluded.revision > harness_hypotheses.revision
        """,
        (
            run_id,
            normalized["hypothesis_id"],
            normalized["statement"],
            *content,
            normalized_revision,
            utc_now(),
        ),
    )


def _hypothesis_content(normalized: Mapping[str, str]) -> tuple[str, ...]:
    return (
        normalized["statement_digest"],
        normalized["status"],
        normalized["supporting_json"],
        normalized["contradicting_json"],
        normalized["next_discriminator"],
    )


def _admit_hypothesis_revision(
    existing: Any,
    content: tuple[str, ...],
    revision: int,
) -> None:
    if existing is None:
        return
    existing_content = tuple(existing)[:5]
    existing_revision = int(existing["revision"])
    if revision < existing_revision:
        raise HarnessIntegrityError("hypothesis revision cannot move backwards")
    if revision == existing_revision and content != existing_content:
        raise HarnessIntegrityError(
            "hypothesis revision collides with different content"
        )


def _append_hypothesis_event(
    repository: Any,
    connection: Any,
    *,
    run_id: str,
    revision: int,
    accepted: int,
    rejected: int,
) -> dict[str, Any]:
    manifest_digest = hypothesis_manifest_digest(
        connection.execute(
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
    )
    return repository._append_event_tx(
        connection,
        run_id=run_id,
        event_type="hypotheses.updated",
        stage=Stage.EVIDENCE_SYNTHESIS.value,
        payload={
            "accepted": accepted,
            "rejected": rejected,
            "revision": revision,
            "manifest_digest": manifest_digest,
        },
        idempotency_key=f"hypotheses:{revision}",
    )
