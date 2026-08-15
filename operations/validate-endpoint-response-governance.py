#!/usr/bin/env python3
"""Validate the inert, secret-free endpoint-response governance contract."""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "operations/security/endpoint-response-governance.json"
MAX_FILE_BYTES = 256 * 1024
SCHEMA = "onion-sentinel-endpoint-response-governance-v1"
RESULT_SCHEMA = "onion-sentinel-endpoint-response-governance-result-v1"
ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
SENSITIVE_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----"
    r"|(?:token|secret|password|passwd|api[_-]?key)\s*[:=]\s*\S+"
    r"|(?:gh[pousr]_|xox[baprs]-|sk-)\S+"
    r"|\b\d{6,12}:[A-Za-z0-9_-]{20,}\b",
    re.IGNORECASE,
)

ROOT_FIELDS = {
    "schema",
    "status",
    "purpose",
    "review_gates",
    "capability_tiers",
    "principals",
    "approval_policy",
    "target_policy",
    "action_catalog",
    "execution_policy",
    "evidence_policy",
    "audit_policy",
    "threat_model",
    "source_anchors",
}
REVIEW_FIELDS = {
    "security_review_approved",
    "guarded_poc_approved",
    "security_review_issue",
    "guarded_poc_issue",
}
TIER_FIELDS = {
    "broker_identity",
    "credential_scope",
    "route_scope",
    "state_change_allowed",
    "enabled",
}
PRINCIPAL_FIELDS = {"id", "authority", "human", "can_approve", "can_execute"}
APPROVAL_FIELDS = {
    "minimum_distinct_human_approvers",
    "maximum_approval_age_seconds",
    "model_identity_may_approve",
    "free_text_is_authorization",
    "approvers_must_be_distinct_from_requester",
    "operator_trust_store_required",
    "one_time_nonce_required",
    "digest_binding_fields",
}
TARGET_FIELDS = {
    "exact_asset_id_required",
    "model_may_select_target",
    "wildcard_targets_allowed",
    "inventory_authority",
    "target_binding_fields",
    "network_scope",
}
ACTION_FIELDS = {
    "id",
    "capability_tier",
    "risk",
    "reversible",
    "rollback_action_id",
    "maximum_timeout_seconds",
    "parameter_fields",
    "initial_poc_allowed",
    "requires_pre_action_evidence",
    "requires_postcondition_verification",
}
EXECUTION_FIELDS = {
    "enabled",
    "interactive_shell_allowed",
    "unrestricted_ssh_allowed",
    "arbitrary_command_allowed",
    "model_direct_broker_access",
    "credential_delivery",
    "code_owned_adapter_required",
    "idempotency_key_required",
    "maximum_timeout_seconds",
    "refuse_non_reversible_actions",
    "refuse_unknown_fields",
}
EVIDENCE_FIELDS = {
    "pre_action_evidence_seal_required",
    "evidence_digest_binding_required",
    "independent_postcondition_verification_required",
    "endpoint_self_report_is_sufficient",
    "rollback_verification_required",
    "preserve_original_provenance",
}
AUDIT_FIELDS = {
    "append_only_receipt_required",
    "independent_receipt_store_required",
    "receipt_fields",
    "secret_values_forbidden",
    "raw_endpoint_output_forbidden",
}
THREAT_FIELDS = {"id", "controls", "fail_closed_result"}
REQUIRED_THREATS = {
    "compromised_endpoint",
    "command_injection",
    "credential_theft",
    "lateral_movement",
    "evidence_tampering",
}
REQUIRED_ACTIONS = {"endpoint_network_isolation"}
APPROVAL_BINDINGS = {
    "request_id",
    "action_id",
    "target_asset_id",
    "parameters_sha256",
    "expires_at",
}
TARGET_BINDINGS = {"asset_id", "hardware_identity_sha256", "response_agent_identity"}
RECEIPT_FIELDS = {
    "request_digest",
    "approval_digests",
    "action_id",
    "target_binding_digest",
    "started_at",
    "completed_at",
    "result",
    "postcondition_digest",
    "rollback_receipt_digest",
}


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("contract contains a duplicate JSON field")
        result[key] = value
    return result


def _bounded_json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ValueError("contract must be a regular non-symlink file")
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("contract exceeds its byte budget")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_fields)


def load_contract(path: Path = DEFAULT_CONTRACT) -> dict[str, object]:
    payload = _bounded_json(Path(path))
    if not isinstance(payload, dict):
        raise ValueError("endpoint-response governance contract must be an object")
    return payload


def _text(value: object, *, maximum: int = 800) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= maximum


def _identifier(value: object) -> bool:
    return isinstance(value, str) and bool(ID_RE.fullmatch(value))


def _unique_text_list(value: object, *, maximum: int = 24) -> bool:
    return bool(
        isinstance(value, list)
        and value
        and len(value) <= maximum
        and all(_text(item) for item in value)
        and len(value) == len(set(value))
    )


def _object(
    value: object,
    fields: set[str],
    label: str,
    errors: list[str],
) -> dict[str, object] | None:
    if not isinstance(value, dict):
        errors.append(f"{label}: must be an object")
        return None
    if set(value) != fields:
        errors.append(f"{label}: field set is invalid")
        return None
    return value


def _required_bool(
    value: object,
    expected: bool,
    label: str,
    errors: list[str],
) -> None:
    if not isinstance(value, bool) or value is not expected:
        errors.append(f"{label}: must be {str(expected).lower()}")


def _source_anchor_valid(root: Path, value: object) -> bool:
    if not _text(value, maximum=240):
        return False
    path = PurePosixPath(str(value))
    if path.is_absolute() or not path.parts or ".." in path.parts:
        return False
    root = root.resolve()
    candidate = root.joinpath(*path.parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return False
    cursor = root
    for part in path.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            return False
    return resolved.is_file()


def _validate_review(contract: dict[str, object], errors: list[str]) -> None:
    review = _object(contract.get("review_gates"), REVIEW_FIELDS, "review_gates", errors)
    if review is None:
        return
    _required_bool(review["security_review_approved"], False, "review_gates.security_review_approved", errors)
    _required_bool(review["guarded_poc_approved"], False, "review_gates.guarded_poc_approved", errors)
    for field in ("security_review_issue", "guarded_poc_issue"):
        if not _text(review[field], maximum=96):
            errors.append(f"review_gates.{field}: is invalid")


def _validate_tiers(contract: dict[str, object], errors: list[str]) -> None:
    tiers = _object(
        contract.get("capability_tiers"),
        {"investigation_read_only", "response_mutation"},
        "capability_tiers",
        errors,
    )
    if tiers is None:
        return
    admitted: dict[str, dict[str, object]] = {}
    for name in ("investigation_read_only", "response_mutation"):
        tier = _object(tiers[name], TIER_FIELDS, f"capability_tiers.{name}", errors)
        if tier is None:
            continue
        admitted[name] = tier
        for field in ("broker_identity", "credential_scope", "route_scope"):
            if not _identifier(tier[field]):
                errors.append(f"capability_tiers.{name}.{field}: is invalid")
    if set(admitted) != set(tiers):
        return
    read = admitted["investigation_read_only"]
    mutation = admitted["response_mutation"]
    _required_bool(read["state_change_allowed"], False, "investigation read state change", errors)
    _required_bool(read["enabled"], True, "investigation read enabled", errors)
    _required_bool(mutation["state_change_allowed"], True, "response mutation state change", errors)
    _required_bool(mutation["enabled"], False, "response mutation enabled", errors)
    for field in ("broker_identity", "credential_scope", "route_scope"):
        if read[field] == mutation[field]:
            errors.append(f"capability tiers: {field} must be isolated")


def _admit_principal(
    value: object,
    index: int,
    admitted: dict[str, dict[str, object]],
    errors: list[str],
) -> None:
    label = f"principals[{index}]"
    principal = _object(value, PRINCIPAL_FIELDS, label, errors)
    if principal is None:
        return
    identifier = principal["id"]
    if not _identifier(identifier) or identifier in admitted:
        errors.append(f"{label}.id: is invalid or duplicated")
        return
    admitted[str(identifier)] = principal
    if not _identifier(principal["authority"]):
        errors.append(f"{label}.authority: is invalid")
    for field in ("human", "can_approve", "can_execute"):
        if not isinstance(principal[field], bool):
            errors.append(f"{label}.{field}: must be boolean")


def _validate_principal_authorities(
    admitted: dict[str, dict[str, object]], errors: list[str]
) -> None:
    model = admitted["model_recommender"]
    if model["authority"] != "recommend_only" or any(
        model[field] is not False for field in ("human", "can_approve", "can_execute")
    ):
        errors.append("principals: model authority must remain recommendation-only")
    human = admitted["trusted_human_approver"]
    if human["human"] is not True or human["can_approve"] is not True or human["can_execute"] is not False:
        errors.append("principals: trusted human approval authority is invalid")
    broker = admitted["response_broker"]
    if broker["human"] is not False or broker["can_approve"] is not False or broker["can_execute"] is not True:
        errors.append("principals: broker execution authority is invalid")


def _validate_principals(contract: dict[str, object], errors: list[str]) -> None:
    principals = contract.get("principals")
    if not isinstance(principals, list) or not 1 <= len(principals) <= 12:
        errors.append("principals: must contain 1 to 12 entries")
        return
    admitted: dict[str, dict[str, object]] = {}
    for index, value in enumerate(principals):
        _admit_principal(value, index, admitted, errors)
    expected = {"model_recommender", "trusted_human_approver", "response_broker"}
    if set(admitted) != expected:
        errors.append("principals: required authority set is invalid")
        return
    _validate_principal_authorities(admitted, errors)


def _validate_approval(contract: dict[str, object], errors: list[str]) -> None:
    policy = _object(contract.get("approval_policy"), APPROVAL_FIELDS, "approval_policy", errors)
    if policy is None:
        return
    if policy["minimum_distinct_human_approvers"] != 2:
        errors.append("approval_policy: exactly two or more distinct human approvals are required")
    age = policy["maximum_approval_age_seconds"]
    if isinstance(age, bool) or not isinstance(age, int) or not 1 <= age <= 300:
        errors.append("approval_policy.maximum_approval_age_seconds: must be 1 to 300")
    for field, expected in (
        ("model_identity_may_approve", False),
        ("free_text_is_authorization", False),
        ("approvers_must_be_distinct_from_requester", True),
        ("operator_trust_store_required", True),
        ("one_time_nonce_required", True),
    ):
        _required_bool(policy[field], expected, f"approval_policy.{field}", errors)
    bindings = policy["digest_binding_fields"]
    if not _unique_text_list(bindings) or set(bindings) != APPROVAL_BINDINGS:
        errors.append("approval_policy.digest_binding_fields: binding set is invalid")


def _validate_target(contract: dict[str, object], errors: list[str]) -> None:
    policy = _object(contract.get("target_policy"), TARGET_FIELDS, "target_policy", errors)
    if policy is None:
        return
    for field, expected in (
        ("exact_asset_id_required", True),
        ("model_may_select_target", False),
        ("wildcard_targets_allowed", False),
    ):
        _required_bool(policy[field], expected, f"target_policy.{field}", errors)
    if policy["inventory_authority"] != "operator_managed_asset_inventory":
        errors.append("target_policy.inventory_authority: is invalid")
    if policy["network_scope"] != "broker_egress_allowlist_only":
        errors.append("target_policy.network_scope: is invalid")
    bindings = policy["target_binding_fields"]
    if not _unique_text_list(bindings) or set(bindings) != TARGET_BINDINGS:
        errors.append("target_policy.target_binding_fields: binding set is invalid")


def _validate_action_contract(
    action: dict[str, object], label: str, errors: list[str]
) -> None:
    if action["capability_tier"] != "response_mutation":
        errors.append(f"{label}.capability_tier: is invalid")
    if action["risk"] not in {"high", "critical"}:
        errors.append(f"{label}.risk: must represent consequential action")
    _required_bool(action["reversible"], True, f"{label}.reversible", errors)
    if not _identifier(action["rollback_action_id"]):
        errors.append(f"{label}.rollback_action_id: is invalid")
    timeout = action["maximum_timeout_seconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 120:
        errors.append(f"{label}.maximum_timeout_seconds: must be 1 to 120")
    if not _unique_text_list(action["parameter_fields"]):
        errors.append(f"{label}.parameter_fields: is invalid")
    for field in (
        "initial_poc_allowed",
        "requires_pre_action_evidence",
        "requires_postcondition_verification",
    ):
        _required_bool(action[field], True, f"{label}.{field}", errors)


def _admit_action(
    value: object,
    index: int,
    identifiers: set[str],
    errors: list[str],
) -> None:
    label = f"action_catalog[{index}]"
    action = _object(value, ACTION_FIELDS, label, errors)
    if action is None:
        return
    identifier = action["id"]
    if not _identifier(identifier) or identifier in identifiers:
        errors.append(f"{label}.id: is invalid or duplicated")
    else:
        identifiers.add(str(identifier))
    _validate_action_contract(action, label, errors)


def _validate_actions(contract: dict[str, object], errors: list[str]) -> None:
    actions = contract.get("action_catalog")
    if not isinstance(actions, list) or not 1 <= len(actions) <= 16:
        errors.append("action_catalog: must contain 1 to 16 actions")
        return
    identifiers: set[str] = set()
    for index, value in enumerate(actions):
        _admit_action(value, index, identifiers, errors)
    if identifiers != REQUIRED_ACTIONS:
        errors.append("action_catalog: approved candidate action set is invalid")


def _validate_execution(contract: dict[str, object], errors: list[str]) -> None:
    policy = _object(contract.get("execution_policy"), EXECUTION_FIELDS, "execution_policy", errors)
    if policy is None:
        return
    for field, expected in (
        ("enabled", False),
        ("interactive_shell_allowed", False),
        ("unrestricted_ssh_allowed", False),
        ("arbitrary_command_allowed", False),
        ("model_direct_broker_access", False),
        ("code_owned_adapter_required", True),
        ("idempotency_key_required", True),
        ("refuse_non_reversible_actions", True),
        ("refuse_unknown_fields", True),
    ):
        _required_bool(policy[field], expected, f"execution_policy.{field}", errors)
    if policy["credential_delivery"] != "broker_held_short_lived_target_bound":
        errors.append("execution_policy.credential_delivery: is invalid")
    timeout = policy["maximum_timeout_seconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 120:
        errors.append("execution_policy.maximum_timeout_seconds: must be 1 to 120")


def _validate_evidence_and_audit(contract: dict[str, object], errors: list[str]) -> None:
    evidence = _object(contract.get("evidence_policy"), EVIDENCE_FIELDS, "evidence_policy", errors)
    if evidence is not None:
        for field, expected in (
            ("pre_action_evidence_seal_required", True),
            ("evidence_digest_binding_required", True),
            ("independent_postcondition_verification_required", True),
            ("endpoint_self_report_is_sufficient", False),
            ("rollback_verification_required", True),
            ("preserve_original_provenance", True),
        ):
            _required_bool(evidence[field], expected, f"evidence_policy.{field}", errors)
    audit = _object(contract.get("audit_policy"), AUDIT_FIELDS, "audit_policy", errors)
    if audit is None:
        return
    for field in (
        "append_only_receipt_required",
        "independent_receipt_store_required",
        "secret_values_forbidden",
        "raw_endpoint_output_forbidden",
    ):
        _required_bool(audit[field], True, f"audit_policy.{field}", errors)
    receipts = audit["receipt_fields"]
    if not _unique_text_list(receipts) or set(receipts) != RECEIPT_FIELDS:
        errors.append("audit_policy.receipt_fields: receipt set is invalid")


def _validate_threats(contract: dict[str, object], errors: list[str]) -> None:
    threats = contract.get("threat_model")
    if not isinstance(threats, list) or not 1 <= len(threats) <= 16:
        errors.append("threat_model: must contain 1 to 16 threats")
        return
    identifiers: set[str] = set()
    for index, value in enumerate(threats):
        label = f"threat_model[{index}]"
        threat = _object(value, THREAT_FIELDS, label, errors)
        if threat is None:
            continue
        identifier = threat["id"]
        if not _identifier(identifier) or identifier in identifiers:
            errors.append(f"{label}.id: is invalid or duplicated")
        else:
            identifiers.add(str(identifier))
        if not _unique_text_list(threat["controls"]):
            errors.append(f"{label}.controls: is invalid")
        if not _text(threat["fail_closed_result"]):
            errors.append(f"{label}.fail_closed_result: is invalid")
    if identifiers != REQUIRED_THREATS:
        errors.append("threat_model: required threat set is invalid")


def _validate_anchors(contract: dict[str, object], root: Path, errors: list[str]) -> None:
    anchors = contract.get("source_anchors")
    if not _unique_text_list(anchors) or not all(
        _source_anchor_valid(root, value) for value in anchors if isinstance(anchors, list)
    ):
        errors.append("source_anchors: must be unique existing repository files")


def validate_contract(contract: object, root: Path = ROOT) -> dict[str, object]:
    errors: list[str] = []
    if not isinstance(contract, dict):
        return {"errors": ["contract: must be an object"]}
    if set(contract) != ROOT_FIELDS:
        errors.append("contract: field set is invalid")
        return {"errors": errors}
    if contract["schema"] != SCHEMA:
        errors.append("schema: is invalid")
    if contract["status"] != "disabled":
        errors.append("status: endpoint response must remain disabled")
    if not _text(contract["purpose"]):
        errors.append("purpose: is invalid")
    if SENSITIVE_RE.search(json.dumps(contract, sort_keys=True)):
        errors.append("contract: sensitive credential or private-key material is forbidden")
    _validate_review(contract, errors)
    _validate_tiers(contract, errors)
    _validate_principals(contract, errors)
    _validate_approval(contract, errors)
    _validate_target(contract, errors)
    _validate_actions(contract, errors)
    _validate_execution(contract, errors)
    _validate_evidence_and_audit(contract, errors)
    _validate_threats(contract, errors)
    _validate_anchors(contract, Path(root), errors)
    return {"errors": sorted(set(errors))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        contract = load_contract(args.contract)
        result = validate_contract(contract, args.repo_root)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        contract = {}
        result = {"errors": [str(exc)]}
    errors = result["errors"]
    output = {
        "schema": RESULT_SCHEMA,
        "ok": not errors,
        "status": "disabled_contract_valid" if not errors else "invalid",
        "error_count": len(errors),
        "errors": errors,
        "action_count": len(contract.get("action_catalog", [])) if isinstance(contract, dict) else 0,
        "threat_count": len(contract.get("threat_model", [])) if isinstance(contract, dict) else 0,
    }
    print(json.dumps(output, sort_keys=True))
    return 0 if output["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
