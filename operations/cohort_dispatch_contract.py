#!/usr/bin/env python3
"""Pure request, acceptance, and durable-job contracts for cohort dispatch."""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Callable, Mapping, Pattern
import urllib.parse

from cohort_http import HttpResult


@dataclass(frozen=True)
class CohortDispatchContract:
    cohort_error: type[RuntimeError]
    ambiguous_dispatch_error: type[RuntimeError]
    case_id_pattern: Pattern[str]
    run_id_pattern: Pattern[str]
    validate_release_id: Callable[[Any], str]
    member_stable_group_key: Callable[[Mapping[str, Any]], str]
    deterministic_dispatch_id: Callable[[Mapping[str, Any], Mapping[str, Any]], str]
    sha256_value: Callable[[Any], str]
    related_limit: int = 500
    pcap_analysis_limit: int = 25


def _dispatch_identity(
    policy: CohortDispatchContract,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> dict[str, Any]:
    contract = manifest["execution_contract"]
    return {
        "stable_group_id": str(member["stable_group_id"]),
        "stable_group_key": policy.member_stable_group_key(member),
        "representative_alert_id": str(member["representative_alert_id"]),
        "cohort_id": str(manifest["cohort_id"]),
        "dispatch_id": policy.deterministic_dispatch_id(manifest, member),
        "release_id": policy.validate_release_id(contract.get("expected_release_id")),
        "expected_assigned_route": str(contract["expected_assigned_route"]),
        "expected_reviewer_route": str(contract["expected_reviewer_route"]),
        "reviewer_required": contract["reviewer_required"],
    }


def _request_context(manifest: Mapping[str, Any]) -> dict[str, str]:
    cohort_id = str(manifest["cohort_id"])
    return {
        "reason": f"[cohort:{cohort_id}] {manifest['reason']}"[:1000],
        "requested_by": f"harness-cohort:{cohort_id}"[:100],
    }


def _alert_request(
    policy: CohortDispatchContract,
    base_url: str,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    kind: str,
) -> tuple[str, dict[str, Any]]:
    dashboard_id = str(member["dashboard_group_id"])
    path = f"/api/soc-alerts/{urllib.parse.quote(dashboard_id, safe='')}/{kind}"
    return base_url + path, {
        **_request_context(manifest),
        "related_limit": policy.related_limit,
        "pcap_analysis_limit": policy.pcap_analysis_limit,
        **_dispatch_identity(policy, manifest, member),
    }


def _reanalysis_request(
    policy: CohortDispatchContract,
    base_url: str,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> tuple[str, dict[str, Any]]:
    case_id = str(
        ((member.get("pre_state") or {}).get("incident_case") or {}).get("case_id")
        or ""
    )
    if not policy.case_id_pattern.fullmatch(case_id):
        raise policy.cohort_error(f"invalid frozen incident case ID: {case_id!r}")
    path = f"/api/soc-incidents/{urllib.parse.quote(case_id, safe='')}/reanalyze"
    return base_url + path, {
        **_request_context(manifest),
        **_dispatch_identity(policy, manifest, member),
    }


def request_for_member(
    policy: CohortDispatchContract,
    base_url: str,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> tuple[str, dict[str, Any]]:
    kind = str((member.get("dispatch") or {}).get("kind") or "")
    if kind in {"escalate", "analyze"}:
        return _alert_request(policy, base_url, manifest, member, kind)
    if kind == "reanalyze":
        return _reanalysis_request(policy, base_url, manifest, member)
    raise policy.cohort_error(f"unsupported dispatch kind: {kind!r}")


def _expected_response_identity(
    policy: CohortDispatchContract,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    *,
    include_group_ids: bool,
) -> dict[str, Any]:
    expected = _dispatch_identity(policy, manifest, member)
    if include_group_ids:
        expected = {
            "group_id": member["dashboard_group_id"],
            "queue_group_id": member["stable_group_id"],
            **expected,
        }
    return expected


def _require_expected_payload(
    policy: CohortDispatchContract,
    payload: Mapping[str, Any],
    expected: Mapping[str, Any],
    message: str,
) -> None:
    if any(payload.get(key) != value for key, value in expected.items()):
        raise policy.ambiguous_dispatch_error(message)


def _validate_alert_response(
    policy: CohortDispatchContract,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    payload: Mapping[str, Any],
    accepted: dict[str, Any],
    kind: str,
) -> dict[str, Any]:
    expected = _expected_response_identity(
        policy, manifest, member, include_group_ids=True
    )
    _require_expected_payload(
        policy,
        payload,
        expected,
        (
            "escalation response identity did not match the frozen member"
            if kind == "escalate"
            else "SOC analysis response identity did not match the frozen member"
        ),
    )
    requested_at = str(payload.get("requested_at") or "")
    if kind == "analyze" and not requested_at:
        raise policy.ambiguous_dispatch_error(
            "SOC analysis response did not include requested_at"
        )
    if kind == "escalate":
        case_id = str(payload.get("case_id") or "")
        if not policy.case_id_pattern.fullmatch(case_id):
            raise policy.ambiguous_dispatch_error(
                "escalation response did not contain a valid case ID"
            )
        accepted["case_id"] = case_id
    accepted.update(expected)
    accepted["requested_at"] = requested_at
    return accepted


def _is_single_case_response(
    policy: CohortDispatchContract,
    payload: Mapping[str, Any],
    run_id: str,
    total_count: int,
) -> bool:
    return bool(
        policy.run_id_pattern.fullmatch(run_id)
        and str(payload.get("scope") or "") == "single_case"
        and total_count == 1
    )


def _validate_reanalysis_response(
    policy: CohortDispatchContract,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    payload: Mapping[str, Any],
    accepted: dict[str, Any],
) -> dict[str, Any]:
    expected = _expected_response_identity(
        policy, manifest, member, include_group_ids=False
    )
    _require_expected_payload(
        policy,
        payload,
        expected,
        "reanalysis response identity did not match the frozen member",
    )
    run_id = str(payload.get("run_id") or "")
    try:
        total_count = int(payload.get("total_count") or 0)
    except (TypeError, ValueError) as exc:
        raise policy.ambiguous_dispatch_error(
            "reanalysis response has an invalid case count"
        ) from exc
    if not _is_single_case_response(policy, payload, run_id, total_count):
        raise policy.ambiguous_dispatch_error(
            "reanalysis response did not identify one exact single-case run"
        )
    case_id = str(
        ((member.get("pre_state") or {}).get("incident_case") or {}).get("case_id")
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
    return accepted


def validate_success_response(
    policy: CohortDispatchContract,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    result: HttpResult,
) -> dict[str, Any]:
    if result.status != 202:
        if 400 <= result.status < 500 and result.status not in {408, 425}:
            raise policy.cohort_error(
                f"dashboard rejected request with HTTP {result.status}"
            )
        raise policy.ambiguous_dispatch_error(
            f"dashboard returned ambiguous HTTP {result.status}"
        )
    payload = result.payload
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise policy.ambiguous_dispatch_error(
            "dashboard returned an invalid success response"
        )
    accepted = {
        "http_status": result.status,
        "response_sha256": result.body_sha256,
    }
    kind = str((member.get("dispatch") or {}).get("kind") or "")
    if kind in {"escalate", "analyze"}:
        return _validate_alert_response(
            policy, manifest, member, payload, accepted, kind
        )
    if kind == "reanalyze":
        return _validate_reanalysis_response(
            policy, manifest, member, payload, accepted
        )
    raise policy.cohort_error(f"unsupported dispatch kind: {kind!r}")


def _durable_payload_identity(
    policy: CohortDispatchContract,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> dict[str, Any]:
    identity = _dispatch_identity(policy, manifest, member)
    return {
        "alert_id": member["representative_alert_id"],
        "representative_alert_id": member["representative_alert_id"],
        "group_id": member["stable_group_id"],
        "dashboard_group_id": member["dashboard_group_id"],
        **identity,
        "agent_role": manifest["agent_role"],
    }


def validate_dispatch_job_payload(
    policy: CohortDispatchContract,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    job: Mapping[str, Any],
    *,
    manual_reanalysis: bool,
    expected_case_id: str = "",
    expected_reanalysis_run_id: str = "",
) -> dict[str, Any]:
    try:
        payload = json.loads(str(job.get("payload_json")))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise policy.ambiguous_dispatch_error(
            "durable job payload is not valid JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise policy.ambiguous_dispatch_error(
            "durable job payload is not a JSON object"
        )
    cohort_present = bool(str(payload.get("cohort_id") or ""))
    dispatch_present = bool(str(payload.get("dispatch_id") or ""))
    if cohort_present != dispatch_present:
        raise policy.ambiguous_dispatch_error(
            "durable job cohort_id and dispatch_id must be present together"
        )
    expected = _durable_payload_identity(policy, manifest, member)
    if expected_case_id:
        expected["case_id"] = expected_case_id
    if expected_reanalysis_run_id:
        expected["reanalysis_run_id"] = expected_reanalysis_run_id
    _require_expected_payload(
        policy,
        payload,
        expected,
        "durable job payload identity did not match the frozen member",
    )
    if payload.get("manual_reanalysis") is not manual_reanalysis:
        raise policy.ambiguous_dispatch_error(
            "durable job manual_reanalysis did not match the dispatch kind"
        )
    return {
        **expected,
        "manual_reanalysis": manual_reanalysis,
        "payload_sha256": policy.sha256_value(payload),
    }
