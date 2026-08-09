#!/usr/bin/env python3
"""Validate frozen representative identity and member pre-run state."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Pattern


@dataclass(frozen=True)
class RepresentativeBindingPolicy:
    error: type[RuntimeError]
    representative_alert_id_pattern: Pattern[str]
    immutable_fields: Sequence[str]
    binding_schema: str
    validate_stable_group_key: Callable[[Any, str], str]
    sha256_value: Callable[[Any], str]


@dataclass(frozen=True)
class MemberPreflightSources:
    error: type[RuntimeError]
    active_agent_states: frozenset[str]
    load_aliases: Callable[[Any], Mapping[str, str]]
    current_summary_identity: Callable[..., tuple[str, str] | None]
    validate_representative_binding: Callable[..., dict[str, Any]]
    soc_pre_state: Callable[..., dict[str, Any]]
    frozen_analysis_ids: Callable[..., set[str]]
    analysis_ids_for_group: Callable[..., list[str]]
    case_for_stable: Callable[..., dict[str, Any] | None]
    active_jobs: Callable[..., list[dict[str, Any]]]
    active_reanalysis: Callable[..., list[dict[str, Any]]]


def _member_identity(
    member: Mapping[str, Any],
    current_alert_id: str,
    policy: RepresentativeBindingPolicy,
) -> tuple[str, str, str, str]:
    dashboard_id = str(member["dashboard_group_id"])
    stable_id = str(member["stable_group_id"])
    stable_group_key = str(member.get("stable_group_key") or "")
    frozen_alert_id = str(member["representative_alert_id"])
    if not policy.representative_alert_id_pattern.fullmatch(frozen_alert_id):
        raise policy.error(
            "frozen representative alert ID is invalid for dashboard "
            f"group {dashboard_id}"
        )
    if not policy.representative_alert_id_pattern.fullmatch(current_alert_id):
        raise policy.error(
            "current representative alert ID is invalid for dashboard "
            f"group {dashboard_id}"
        )
    return dashboard_id, stable_id, stable_group_key, frozen_alert_id


def _require_alert(
    alert: Mapping[str, Any] | None,
    *,
    kind: str,
    dashboard_id: str,
    stable_id: str,
    policy: RepresentativeBindingPolicy,
) -> Mapping[str, Any]:
    if alert is None:
        raise policy.error(
            f"{kind} representative alert is missing for dashboard group "
            f"{dashboard_id}"
        )
    if str(alert.get("stable_group_id") or "") != stable_id:
        raise policy.error(
            f"{kind} representative alert stable identity drift for "
            f"dashboard group {dashboard_id}"
        )
    return alert


def _validate_immutable_detection(
    member: Mapping[str, Any],
    frozen_alert: Mapping[str, Any],
    dashboard_id: str,
    policy: RepresentativeBindingPolicy,
) -> Mapping[str, Any]:
    detection = member.get("detection")
    if not isinstance(detection, dict):
        raise policy.error(
            "frozen representative detection is missing for dashboard "
            f"group {dashboard_id}"
        )
    missing = [field for field in policy.immutable_fields if field not in detection]
    if missing:
        raise policy.error(
            "frozen representative detection is missing immutable fields "
            f"for dashboard group {dashboard_id}: " + ", ".join(missing)
        )
    drifted = [
        field
        for field in policy.immutable_fields
        if frozen_alert.get(field) != detection.get(field)
    ]
    if drifted:
        raise policy.error(
            "frozen representative immutable evidence drift for dashboard "
            f"group {dashboard_id}: " + ", ".join(drifted)
        )
    return detection


def _validate_group_keys(
    frozen_alert: Mapping[str, Any],
    current_alert: Mapping[str, Any],
    stable_group_key: str,
    dashboard_id: str,
    policy: RepresentativeBindingPolicy,
) -> None:
    frozen_key = policy.validate_stable_group_key(
        frozen_alert.get("stable_group_key"),
        f"frozen representative alert stable_group_key for dashboard group {dashboard_id}",
    )
    current_key = policy.validate_stable_group_key(
        current_alert.get("stable_group_key"),
        f"current representative alert stable_group_key for dashboard group {dashboard_id}",
    )
    if frozen_key != stable_group_key:
        raise policy.error(
            "frozen representative alert stable group key drift for "
            f"dashboard group {dashboard_id}"
        )
    if frozen_key != current_key:
        raise policy.error(
            "representative alert stable group key drift for dashboard "
            f"group {dashboard_id}"
        )


def validate_representative_binding(
    connection: Any,
    member: Mapping[str, Any],
    current_representative_alert_id: str,
    *,
    alert_identity: Callable[[Any, str], Mapping[str, Any] | None],
    member_stable_group_key: Callable[[Mapping[str, Any]], str],
    policy: RepresentativeBindingPolicy,
) -> dict[str, Any]:
    """Prove frozen/current representatives remain one exact stable group."""
    prepared = dict(member)
    prepared["stable_group_key"] = member_stable_group_key(member)
    dashboard_id, stable_id, stable_key, frozen_alert_id = _member_identity(
        prepared, current_representative_alert_id, policy
    )
    frozen_alert = _require_alert(
        alert_identity(connection, frozen_alert_id),
        kind="frozen",
        dashboard_id=dashboard_id,
        stable_id=stable_id,
        policy=policy,
    )
    _validate_immutable_detection(prepared, frozen_alert, dashboard_id, policy)
    current_alert = _require_alert(
        alert_identity(connection, current_representative_alert_id),
        kind="current",
        dashboard_id=dashboard_id,
        stable_id=stable_id,
        policy=policy,
    )
    _validate_group_keys(
        frozen_alert, current_alert, stable_key, dashboard_id, policy
    )
    immutable = {field: frozen_alert.get(field) for field in policy.immutable_fields}
    return {
        "schema": policy.binding_schema,
        "representative_drifted": current_representative_alert_id != frozen_alert_id,
        "stable_group_id": stable_id,
        "stable_group_key": stable_key,
        "frozen_representative_alert_id": frozen_alert_id,
        "current_representative_alert_id": current_representative_alert_id,
        "immutable_fields": list(policy.immutable_fields),
        "frozen_immutable_evidence_sha256": policy.sha256_value(immutable),
        "stable_group_key_compatible": True,
    }


def _validate_incident_pre_state(
    connection: Any,
    member: Mapping[str, Any],
    stable_id: str,
    aliases: Mapping[str, str],
    sources: MemberPreflightSources,
) -> None:
    frozen_ids = sources.frozen_analysis_ids(
        member,
        agent_role="incident-responder",
        pre_state_field="incident_analysis_ids",
    )
    current_ids = set(
        sources.analysis_ids_for_group(
            connection, stable_id, agent_role="incident-responder"
        )
    )
    if current_ids != frozen_ids:
        raise sources.error(
            "Incident Responder analysis pre-state changed for stable "
            f"group {stable_id}"
        )
    pre_case = (member.get("pre_state") or {}).get("incident_case")
    current_case = sources.case_for_stable(connection, stable_id, aliases)
    if current_case != pre_case:
        raise sources.error(
            f"incident case pre-state changed for stable group {stable_id}"
        )
    _validate_incident_activity(
        connection, stable_id, current_case, aliases, sources
    )


def _validate_incident_activity(
    connection: Any,
    stable_id: str,
    current_case: Mapping[str, Any] | None,
    aliases: Mapping[str, str],
    sources: MemberPreflightSources,
) -> None:
    if (
        current_case
        and str(current_case.get("agent_status") or "")
        in sources.active_agent_states
    ):
        raise sources.error(f"incident case {current_case.get('case_id')} became active")
    if sources.active_jobs(connection, stable_id, aliases):
        raise sources.error(f"stable group {stable_id} has a pending/processing job")
    case_id = str((current_case or {}).get("case_id") or "")
    if sources.active_reanalysis(connection, stable_id, case_id, aliases):
        raise sources.error(f"stable group {stable_id} has a queued/running reanalysis")


def validate_member_preflight(
    connection: Any,
    member: Mapping[str, Any],
    sources: MemberPreflightSources,
) -> dict[str, Any]:
    """Require unchanged dashboard identity, representative, and pre-state."""
    aliases = sources.load_aliases(connection)
    dashboard_id = str(member["dashboard_group_id"])
    stable_id = str(member["stable_group_id"])
    identity = sources.current_summary_identity(connection, dashboard_id, aliases)
    if identity is None:
        raise sources.error(f"frozen dashboard group disappeared: {dashboard_id}")
    current_stable_id, current_alert_id = identity
    if current_stable_id != stable_id:
        raise sources.error(
            f"frozen stable identity drift for dashboard group {dashboard_id}"
        )
    binding = sources.validate_representative_binding(
        connection, member, current_alert_id
    )
    if str((member.get("dispatch") or {}).get("kind") or "") == "analyze":
        current = sources.soc_pre_state(connection, stable_id, aliases)
        if current != (member.get("pre_state") or {}):
            raise sources.error(
                f"SOC Analyst pre-state changed for stable group {stable_id}"
            )
        return binding
    _validate_incident_pre_state(connection, member, stable_id, aliases, sources)
    return binding
