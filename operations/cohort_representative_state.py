"""Read and bind cohort representative identities from the alert store."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence, Type

from cohort_storage_core import CohortStoragePolicy, require_columns


@dataclass(frozen=True)
class CohortRepresentativeStatePolicy:
    """Injected storage and identity dependencies for representative reads."""

    error: Type[Exception]
    storage: CohortStoragePolicy
    resolve_alias: Callable[[str, Mapping[str, str]], str]
    incident_cases: Callable[
        [sqlite3.Connection, Mapping[str, str]],
        dict[str, list[dict[str, Any]]],
    ]
    immutable_fields: Sequence[str]


def current_summary_identity(
    connection: sqlite3.Connection,
    dashboard_group_id: str,
    aliases: Mapping[str, str],
    policy: CohortRepresentativeStatePolicy,
) -> tuple[str, str] | None:
    """Return the current stable group and representative alert identity."""
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
        policy.resolve_alias(str(row["group_id"] or ""), aliases),
        str(row["representative_alert_id"] or ""),
    )


def alert_representative_identity(
    connection: sqlite3.Connection,
    alert_id: str,
    policy: CohortRepresentativeStatePolicy,
) -> dict[str, Any] | None:
    """Read the immutable identity fields for one exact raw alert."""
    required = {
        "alert_id",
        "stable_group_id",
        "stable_group_key",
        *policy.immutable_fields,
    }
    require_columns(connection, "alerts", required, policy.storage)
    row = connection.execute(
        "SELECT "
        + ", ".join(sorted(required))
        + " FROM alerts WHERE alert_id = ?",
        (alert_id,),
    ).fetchone()
    return dict(row) if row else None


def bind_representative_stable_group_key(
    connection: sqlite3.Connection,
    representative_alert_id: str,
    detection: Mapping[str, Any],
    policy: CohortRepresentativeStatePolicy,
    *,
    alert_identity: Callable[
        [sqlite3.Connection, str], dict[str, Any] | None
    ],
) -> dict[str, Any]:
    """Bind the raw representative's group key into frozen evidence."""
    bound = dict(detection)
    if "stable_group_key" in bound:
        return bound
    alert = alert_identity(connection, representative_alert_id)
    if alert is not None:
        bound["stable_group_key"] = alert.get("stable_group_key")
    return bound


def case_for_stable(
    connection: sqlite3.Connection,
    stable_group_id: str,
    aliases: Mapping[str, str],
    policy: CohortRepresentativeStatePolicy,
) -> dict[str, Any] | None:
    """Return the sole incident case for a stable group, if one exists."""
    cases = policy.incident_cases(connection, aliases).get(stable_group_id, [])
    if len(cases) > 1:
        raise policy.error(
            f"multiple incident cases resolve to {stable_group_id}"
        )
    return cases[0] if cases else None
