#!/usr/bin/env python3
"""Monitor-time rebinding of accepted cohort dispatch provenance."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Pattern


@dataclass(frozen=True)
class CohortMonitorBindingSources:
    cohort_error: type[RuntimeError]
    sha256_pattern: Pattern[str]
    constant_time_equal: Callable[[str, str], bool]
    member_stable_group_key: Callable[[Mapping[str, Any]], str]
    load_aliases: Callable[[Any], Mapping[str, str]]
    current_summary_identity: Callable[[Any, str, Mapping[str, str]], tuple[str, str] | None]
    validate_representative_binding: Callable[[Any, Mapping[str, Any], str], dict[str, Any]]
    durable_dispatch_job: Callable[..., dict[str, Any]]
    validate_dispatch_job_payload: Callable[..., dict[str, Any]]
    deterministic_dispatch_id: Callable[[Mapping[str, Any], Mapping[str, Any]], str]
    parse_timestamp: Callable[[Any, str], Any]
    sha256_value: Callable[[Any], str]


def _dispatch_records(
    sources: CohortMonitorBindingSources,
    member: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    dispatch = member.get("dispatch")
    if not isinstance(dispatch, dict):
        raise sources.cohort_error("accepted member has no dispatch record")
    accepted = dispatch.get("accepted")
    readback = dispatch.get("readback")
    if not isinstance(accepted, dict) or not isinstance(readback, dict):
        raise sources.cohort_error(
            "accepted member has incomplete dispatch provenance"
        )
    kind = str(dispatch.get("kind") or "")
    if kind not in {"analyze", "escalate", "reanalyze"}:
        raise sources.cohort_error(f"unsupported dispatch kind: {kind!r}")
    return dispatch, accepted, readback, kind


def _current_representative_binding(
    sources: CohortMonitorBindingSources,
    connection: Any,
    member: Mapping[str, Any],
    stable_id: str,
) -> dict[str, Any]:
    aliases = sources.load_aliases(connection)
    identity = sources.current_summary_identity(
        connection, str(member["dashboard_group_id"]), aliases
    )
    if identity is None or identity[0] != stable_id:
        raise sources.cohort_error(
            "frozen representative identity changed during monitoring"
        )
    return sources.validate_representative_binding(
        connection, member, identity[1]
    )


def _durable_job_binding(
    sources: CohortMonitorBindingSources,
    connection: Any,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    accepted: Mapping[str, Any],
    kind: str,
    stable_id: str,
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    job_type = "ai_analysis" if kind == "analyze" else "incident_response_analysis"
    case_id = str(accepted.get("case_id") or "") if kind != "analyze" else ""
    run_id = str(accepted.get("run_id") or "") if kind == "reanalyze" else ""
    job = sources.durable_dispatch_job(
        connection, job_type=job_type, stable_group_id=stable_id
    )
    binding = sources.validate_dispatch_job_payload(
        manifest,
        member,
        job,
        manual_reanalysis=kind != "escalate",
        expected_case_id=case_id,
        expected_reanalysis_run_id=run_id,
    )
    return job, binding, case_id, run_id


def _validate_job_receipt(
    sources: CohortMonitorBindingSources,
    job: Mapping[str, Any],
    binding: Mapping[str, Any],
    readback: Mapping[str, Any],
) -> None:
    try:
        expected_job_id = int(readback.get("job_id"))
        current_job_id = int(job.get("id"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise sources.cohort_error(
            "accepted dispatch has an invalid durable job ID"
        ) from exc
    if expected_job_id < 1 or current_job_id != expected_job_id:
        raise sources.cohort_error(
            "accepted durable job identity changed during monitoring"
        )
    expected_digest = str(readback.get("job_payload_sha256") or "")
    if (
        not sources.sha256_pattern.fullmatch(expected_digest)
        or not sources.constant_time_equal(
            expected_digest, str(binding["payload_sha256"])
        )
    ):
        raise sources.cohort_error(
            "accepted durable job payload changed during monitoring"
        )


def _expected_dispatch_identity(
    sources: CohortMonitorBindingSources,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> dict[str, Any]:
    contract = manifest["execution_contract"]
    return {
        "dispatch_id": sources.deterministic_dispatch_id(manifest, member),
        "cohort_id": str(manifest["cohort_id"]),
        "stable_group_key": sources.member_stable_group_key(member),
        "release_id": str(contract["expected_release_id"]),
        "expected_assigned_route": str(contract["expected_assigned_route"]),
        "expected_reviewer_route": str(contract["expected_reviewer_route"]),
        "reviewer_required": contract["reviewer_required"],
    }


def _validate_provenance_identity(
    sources: CohortMonitorBindingSources,
    expected: Mapping[str, Any],
    accepted: Mapping[str, Any],
    readback: Mapping[str, Any],
) -> None:
    for label, record in (
        ("accepted response", accepted),
        ("durable readback", readback),
    ):
        if any(
            record.get(field) != value
            if field != "reviewer_required"
            else record.get(field) is not value
            for field, value in expected.items()
        ):
            raise sources.cohort_error(
                f"{label} dispatch identity changed during monitoring"
            )


def _validate_dispatch_window(
    sources: CohortMonitorBindingSources,
    expected_dispatch_id: str,
    dispatch: Mapping[str, Any],
    job: Mapping[str, Any],
) -> None:
    if str(dispatch.get("dispatch_id") or "") != expected_dispatch_id:
        raise sources.cohort_error(
            "member dispatch identity changed during monitoring"
        )
    if sources.parse_timestamp(
        job.get("requested_at"), "accepted durable job requested_at"
    ) < sources.parse_timestamp(
        dispatch.get("started_at"), "accepted dispatch started_at"
    ):
        raise sources.cohort_error(
            "accepted durable job predates the dispatch POST window"
        )


def _validate_readback_identity(
    sources: CohortMonitorBindingSources,
    readback: Mapping[str, Any],
    expected: Mapping[str, Any],
    member: Mapping[str, Any],
    stable_id: str,
    kind: str,
    case_id: str,
    run_id: str,
) -> None:
    required = {
        "stable_group_id": stable_id,
        "stable_group_key": expected["stable_group_key"],
        "representative_alert_id": member["representative_alert_id"],
        "release_id": expected["release_id"],
        "expected_assigned_route": expected["expected_assigned_route"],
        "expected_reviewer_route": expected["expected_reviewer_route"],
        "reviewer_required": expected["reviewer_required"],
    }
    if kind != "analyze":
        required["case_id"] = case_id
    if kind == "reanalyze":
        required["run_id"] = run_id
    if any(readback.get(field) != value for field, value in required.items()):
        raise sources.cohort_error(
            "durable readback identity changed during monitoring"
        )


def monitor_dispatch_job_binding(
    sources: CohortMonitorBindingSources,
    connection: Any,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> dict[str, Any]:
    dispatch, accepted, readback, kind = _dispatch_records(sources, member)
    stable_id = str(member["stable_group_id"])
    representative = _current_representative_binding(
        sources, connection, member, stable_id
    )
    job, binding, case_id, run_id = _durable_job_binding(
        sources, connection, manifest, member, accepted, kind, stable_id
    )
    _validate_job_receipt(sources, job, binding, readback)
    expected = _expected_dispatch_identity(sources, manifest, member)
    _validate_provenance_identity(sources, expected, accepted, readback)
    _validate_dispatch_window(sources, expected["dispatch_id"], dispatch, job)
    _validate_readback_identity(
        sources, readback, expected, member, stable_id, kind, case_id, run_id
    )
    return {
        key: value for key, value in job.items() if key != "payload_json"
    } | {
        "payload_sha256": binding["payload_sha256"],
        **expected,
        "stable_group_id": stable_id,
        "representative_alert_id": str(member["representative_alert_id"]),
        "representative_binding_sha256": sources.sha256_value(representative),
    }
