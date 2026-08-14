#!/usr/bin/env python3
"""Build an independent evidence seal from pristine frozen role manifests."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Pattern


DRAFT_KEYS = frozenset(
    {
        "schema", "experiment_id", "expected_count", "independent_review",
        "reviewer_count", "cases", "draft_sha256",
    }
)
DRAFT_CASE_KEYS = frozenset({"rank", "stable_group_id", "ground_truth"})
DISPATCH_EVIDENCE_KEYS = frozenset(
    {"started_at", "accepted", "readback", "dispatch_id", "error"}
)


@dataclass(frozen=True)
class EvidenceSealingPolicy:
    error: type[RuntimeError]
    draft_schema: str
    seal_schema: str
    roles: tuple[str, ...]
    maximum_count: int
    sha256_pattern: Pattern[str]
    stable_group_id_pattern: Pattern[str]
    utc_now: Callable[[], str]
    sha256_value: Callable[[Any], str]
    constant_time_equal: Callable[[str, str], bool]
    validate_embedded_digest: Callable[[Mapping[str, Any], str], None]
    normalize_ground_truth: Callable[[Any, str], Mapping[str, Any]]
    ordered_identity_projection: Callable[[list[dict[str, Any]]], list[dict[str, Any]]]


def _exact_keys(
    value: Mapping[str, Any],
    expected: frozenset[str],
    label: str,
    policy: EvidenceSealingPolicy,
) -> None:
    if set(value) != set(expected):
        raise policy.error(f"{label} must contain its exact versioned fields")


def _integer(value: Any, label: str, policy: EvidenceSealingPolicy) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise policy.error(f"{label} must be an integer")
    return value


def _digest(value: Any, label: str, policy: EvidenceSealingPolicy) -> str:
    digest = str(value or "")
    if policy.sha256_pattern.fullmatch(digest) is None:
        raise policy.error(f"{label} is missing or invalid")
    return digest


def _draft_case(
    value: Any,
    rank: int,
    seen: set[str],
    policy: EvidenceSealingPolicy,
) -> dict[str, Any]:
    label = f"ground-truth case {rank}"
    if not isinstance(value, dict):
        raise policy.error(f"{label} must be an object")
    _exact_keys(value, DRAFT_CASE_KEYS, label, policy)
    observed_rank = _integer(value.get("rank"), f"{label} rank", policy)
    if observed_rank != rank:
        raise policy.error(f"{label} rank/order binding is invalid")
    stable_id = str(value.get("stable_group_id") or "").strip().lower()
    if (
        policy.stable_group_id_pattern.fullmatch(stable_id) is None
        or stable_id in seen
    ):
        raise policy.error(f"{label} stable_group_id is invalid or duplicated")
    seen.add(stable_id)
    return {
        "rank": rank,
        "stable_group_id": stable_id,
        "ground_truth": dict(
            policy.normalize_ground_truth(value.get("ground_truth"), label)
        ),
    }


def validate_ground_truth_draft(
    document: Mapping[str, Any],
    *,
    expected_count: int,
    policy: EvidenceSealingPolicy,
) -> dict[str, Any]:
    """Validate one digest-bound independent ground-truth draft."""
    experiment, reviewers = _draft_metadata(document, expected_count, policy)
    cases = document.get("cases")
    if not isinstance(cases, list) or len(cases) != expected_count:
        raise policy.error(f"ground-truth draft must contain {expected_count} cases")
    seen: set[str] = set()
    return {
        "experiment_id": experiment,
        "reviewer_count": reviewers,
        "cases": [
            _draft_case(value, rank, seen, policy)
            for rank, value in enumerate(cases, start=1)
        ],
    }


def _draft_metadata(
    document: Mapping[str, Any],
    expected_count: int,
    policy: EvidenceSealingPolicy,
) -> tuple[str, int]:
    _exact_keys(document, DRAFT_KEYS, "ground-truth draft", policy)
    if document.get("schema") != policy.draft_schema:
        raise policy.error("unsupported independent ground-truth draft schema")
    policy.validate_embedded_digest(document, "draft_sha256")
    if document.get("independent_review") is not True:
        raise policy.error("ground-truth draft must affirm independent_review=true")
    reviewers = _draft_counts(document, expected_count, policy)
    experiment = _experiment_id(document.get("experiment_id"), policy)
    return experiment, reviewers


def _draft_counts(
    document: Mapping[str, Any],
    expected_count: int,
    policy: EvidenceSealingPolicy,
) -> int:
    count = _integer(document.get("expected_count"), "expected_count", policy)
    if count != expected_count or not 1 <= count <= policy.maximum_count:
        raise policy.error("ground-truth draft expected_count does not match")
    reviewers = _integer(document.get("reviewer_count"), "reviewer_count", policy)
    if not 1 <= reviewers <= 20:
        raise policy.error("reviewer_count must be between 1 and 20")
    return reviewers


def _experiment_id(value: Any, policy: EvidenceSealingPolicy) -> str:
    experiment = str(value or "").strip()
    if not 3 <= len(experiment) <= 100 or not all(
        character.isalnum() or character in "._-" for character in experiment
    ) or not experiment[0].isalnum():
        raise policy.error("ground-truth draft experiment_id is invalid")
    return experiment


def _pristine_member(
    member: Mapping[str, Any],
    rank: int,
    role: str,
    policy: EvidenceSealingPolicy,
) -> None:
    if _integer(member.get("rank"), f"{role} member rank", policy) != rank:
        raise policy.error(f"{role} manifest member order is invalid")
    dispatch = member.get("dispatch")
    if not isinstance(dispatch, dict):
        raise policy.error(f"{role} manifest dispatch is missing")
    allowed_kind = (
        dispatch.get("kind") == "analyze"
        if role == "soc-analyst"
        else dispatch.get("kind") in {"escalate", "reanalyze"}
    )
    pristine = (
        dispatch.get("state") == "unattempted"
        and dispatch.get("attempt_count") == 0
        and not DISPATCH_EVIDENCE_KEYS.intersection(dispatch)
    )
    if not allowed_kind or not pristine:
        raise policy.error(f"{role} manifest is not pristine before dispatch")


def _manifest_binding(
    manifest: Mapping[str, Any],
    role: str,
    expected_count: int,
    policy: EvidenceSealingPolicy,
) -> dict[str, Any]:
    members, selection = _manifest_inputs(
        manifest, role, expected_count, policy
    )
    _validate_pristine_members(members, role, policy)
    identities, detections = _frozen_projections(members, policy)
    identity_digest = policy.sha256_value(identities)
    observed_identity = _digest(
        selection.get("ordered_identity_sha256"), "identity digest", policy
    )
    if not policy.constant_time_equal(identity_digest, observed_identity):
        raise policy.error(f"{role} ordered identity digest does not match")
    return _binding_projection(
        manifest, selection, role, identities, detections, identity_digest, policy
    )


def _manifest_inputs(
    manifest: Mapping[str, Any],
    role: str,
    expected_count: int,
    policy: EvidenceSealingPolicy,
) -> tuple[list[dict[str, Any]], Mapping[str, Any]]:
    members = manifest.get("members")
    selection = manifest.get("selection")
    database = manifest.get("database")
    checks = (
        manifest.get("agent_role") == role,
        manifest.get("state") == "frozen",
        manifest.get("security_onion_access") == "none",
        isinstance(members, list),
        len(members) == expected_count if isinstance(members, list) else False,
        manifest.get("count") == expected_count,
        isinstance(selection, dict),
        selection.get("mode") == "imported_rows" if isinstance(selection, dict) else False,
        selection.get("source_count") == expected_count if isinstance(selection, dict) else False,
        selection.get("order_preserved") is True if isinstance(selection, dict) else False,
        isinstance(database, dict),
        database.get("read_only") is True if isinstance(database, dict) else False,
        isinstance(manifest.get("execution_contract"), dict),
    )
    if not all(checks):
        raise policy.error(f"{role} manifest is not a pristine imported-row freeze")
    return members, selection


def _validate_pristine_members(
    members: list[dict[str, Any]],
    role: str,
    policy: EvidenceSealingPolicy,
) -> None:
    for rank, member in enumerate(members, start=1):
        if not isinstance(member, dict):
            raise policy.error(f"{role} manifest member {rank} is invalid")
        _pristine_member(member, rank, role, policy)


def _frozen_projections(
    members: list[dict[str, Any]],
    policy: EvidenceSealingPolicy,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    identities = policy.ordered_identity_projection(members)
    detections = [
        {
            **identity,
            "detection_sha256": policy.sha256_value(member["detection"]),
        }
        for identity, member in zip(identities, members)
    ]
    return identities, detections


def _binding_projection(
    manifest: Mapping[str, Any],
    selection: Mapping[str, Any],
    role: str,
    identities: list[dict[str, Any]],
    detections: list[dict[str, Any]],
    identity_digest: str,
    policy: EvidenceSealingPolicy,
) -> dict[str, Any]:
    return {
        "source_rows_sha256": _digest(
            selection.get("source_sha256"), "source rows digest", policy
        ),
        "ordered_identity_sha256": identity_digest,
        "ordered_detection_sha256": policy.sha256_value(detections),
        "execution_contract": dict(manifest["execution_contract"]),
        "role_plan": {
            "cohort_id": str(manifest.get("cohort_id") or ""),
            "frozen_plan_sha256": _digest(
                manifest.get("frozen_plan_sha256"),
                f"{role} frozen plan digest",
                policy,
            ),
        },
        "cases": [
            {
                "rank": item["rank"],
                "stable_group_id": item["stable_group_id"],
                "detection_sha256": item["detection_sha256"],
            }
            for item in detections
        ],
    }


def validate_frozen_manifests(
    manifests: Mapping[str, Mapping[str, Any]],
    *,
    expected_count: int,
    policy: EvidenceSealingPolicy,
) -> dict[str, Any]:
    """Bind the exact pristine role plans for one matched imported-row cohort."""
    if set(manifests) != set(policy.roles):
        raise policy.error("manifests must identify every evaluated role exactly")
    bindings = {
        role: _manifest_binding(manifests[role], role, expected_count, policy)
        for role in policy.roles
    }
    anchor = bindings[policy.roles[0]]
    shared_fields = (
        "source_rows_sha256", "ordered_identity_sha256",
        "ordered_detection_sha256", "execution_contract", "cases",
    )
    for role in policy.roles[1:]:
        if any(bindings[role][field] != anchor[field] for field in shared_fields):
            raise policy.error(f"{role} manifest does not match the frozen cohort")
    return {
        key: anchor[key]
        for key in (
            "source_rows_sha256", "ordered_identity_sha256",
            "ordered_detection_sha256", "cases",
        )
    } | {
        "role_plans": {
            role: bindings[role]["role_plan"] for role in policy.roles
        }
    }


def build_evidence_seal(
    draft_document: Mapping[str, Any],
    manifests: Mapping[str, Mapping[str, Any]],
    *,
    methodology_sha256: str,
    expected_count: int,
    policy: EvidenceSealingPolicy,
) -> dict[str, Any]:
    """Build one canonical seal without reading result exports or dispatching."""
    draft = validate_ground_truth_draft(
        draft_document, expected_count=expected_count, policy=policy
    )
    binding = validate_frozen_manifests(
        manifests, expected_count=expected_count, policy=policy
    )
    for ground_truth, frozen in zip(draft["cases"], binding["cases"]):
        exact = (
            ground_truth["rank"] == frozen["rank"]
            and ground_truth["stable_group_id"] == frozen["stable_group_id"]
            and ground_truth["ground_truth"]["detection_sha256"]
            == frozen["detection_sha256"]
        )
        if not exact:
            raise policy.error("ground truth does not match the frozen cohort")
    seal = {
        "schema": policy.seal_schema,
        "experiment_id": draft["experiment_id"],
        "expected_count": expected_count,
        "independent_review": True,
        "reviewer_count": draft["reviewer_count"],
        "sealed_at": policy.utc_now(),
        "methodology_sha256": _digest(
            methodology_sha256, "methodology_sha256", policy
        ),
        "source_rows_sha256": binding["source_rows_sha256"],
        "ordered_identity_sha256": binding["ordered_identity_sha256"],
        "ordered_detection_sha256": binding["ordered_detection_sha256"],
        "role_plans": binding["role_plans"],
        "cases": draft["cases"],
    }
    seal["seal_sha256"] = policy.sha256_value(seal)
    return seal
