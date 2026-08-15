#!/usr/bin/env python3
"""Secret-free cross-host change handoff and configuration-drift decisions."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any, Mapping


SCHEMA_VERSION = 1
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SENSITIVE_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----"
    r"|(?:token|secret|password|passwd|api[_-]?key|cookie)\s*[:=]\s*\S+",
    re.IGNORECASE,
)
PRIVATE_KEY_PATH_RE = re.compile(
    r"(?:^|/)(?:id_(?:rsa|dsa|ecdsa|ed25519)|private(?:[_-]?key)?)(?:\.|/|$)"
    r"|\.(?:key|pem|p12|pfx)$",
    re.IGNORECASE,
)

TARGETS = {"mac_studio", "relay", "security_onion"}
RISKS = {"low", "medium", "high", "critical"}
OPERATIONS = {
    "replace_managed_artifact",
    "reconcile_managed_account",
    "reconcile_managed_public_key",
    "reconcile_managed_service",
    "reload_managed_service",
}
ACK_STATUSES = {"applied", "already_applied", "rejected", "rolled_back"}
VERIFICATION_STATUSES = {"pass", "warn", "fail"}
ROOT_FIELDS = {"schema_version", "change_id", "request", "acknowledgement"}
REQUEST_FIELDS = {
    "target_system",
    "owner",
    "purpose",
    "prerequisites",
    "risk",
    "validation",
    "rollback",
    "write_authorized",
    "authorized_operations",
    "source_revision",
    "rollback_revision",
    "requested_at",
    "artifacts",
}
ARTIFACT_FIELDS = {
    "source",
    "destination",
    "sha256",
    "expected_current_sha256",
    "observed_current_sha256",
}
ACK_FIELDS = {
    "status",
    "request_sha256",
    "applied_version",
    "applied_at",
    "rollback_point",
    "artifacts",
    "verification",
}
ACK_ARTIFACT_FIELDS = {"destination", "sha256"}
VERIFICATION_FIELDS = {"check", "status", "evidence_sha256"}

SOURCE_PREFIXES = {
    "mac_studio": ("n8n/", "onion-sentinel-dashboard/", "operations/"),
    "relay": ("relay/", "n8n/bin/live_osquery_", "n8n/bin/ac_hunter_contract.py"),
    "security_onion": ("security-onion/", "n8n/bin/live_osquery_"),
}
DESTINATION_PREFIXES = {
    "mac_studio": ("stack/", "dashboard/", "launchd/"),
    "relay": ("/opt/so-alert-relay/", "/usr/local/", "/etc/"),
    "security_onion": ("/usr/local/", "/etc/", "/home/so-ai-relay/"),
}
PROTECTED_DESTINATION_PREFIXES = {
    "mac_studio": (
        "stack/.env",
        "stack/config/",
        "stack/alert_store_data/",
        "stack/logs/",
        "stack/pcap-evidence/",
        "stack/soc-alerts/agent-memory/",
    ),
    "relay": (
        "/etc/so-alert-relay/",
        "/opt/so-alert-relay/keys/",
        "/opt/so-alert-relay/state/",
    ),
    "security_onion": (
        "/etc/onion-sentinel/",
        "/home/so-ai-relay/.ssh/",
        "/nsm/",
    ),
}


class HandoffError(ValueError):
    """A handoff cannot be admitted without operator review."""


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise HandoffError(f"{label} must be an object")
    return value


def _exact_fields(value: Mapping[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise HandoffError(f"{label} contains unknown field: {unknown[0]}")
    missing = sorted(allowed - set(value))
    if missing:
        raise HandoffError(f"{label} is missing field: {missing[0]}")


def _text(value: Any, label: str, *, maximum: int = 240) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise HandoffError(f"{label} must be non-empty and at most {maximum} characters")
    if SENSITIVE_RE.search(value):
        raise HandoffError(f"{label} contains sensitive credential or private-key content")
    return value


def _identifier(value: Any, label: str) -> str:
    text = _text(value, label, maximum=96)
    if not IDENTIFIER_RE.fullmatch(text):
        raise HandoffError(f"{label} is not a safe identifier")
    return text


def _timestamp(value: Any, label: str) -> str:
    text = _text(value, label, maximum=20)
    if not TIMESTAMP_RE.fullmatch(text):
        raise HandoffError(f"{label} must be a UTC second timestamp")
    return text


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise HandoffError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _optional_sha256(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _sha256(value, label)


def _revision(value: Any, label: str) -> str:
    if not isinstance(value, str) or not REVISION_RE.fullmatch(value):
        raise HandoffError(f"{label} must be an exact lowercase Git commit")
    return value


def _text_list(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > 16:
        raise HandoffError(f"{label} must contain 1 to 16 entries")
    return tuple(_text(item, f"{label} entry") for item in value)


def _authorized_operations(request: Mapping[str, Any]) -> tuple[bool, list[str]]:
    write_authorized = request["write_authorized"]
    if not isinstance(write_authorized, bool):
        raise HandoffError("request write_authorized must be boolean")
    operations = request["authorized_operations"]
    if not isinstance(operations, list) or len(operations) != len(set(operations)):
        raise HandoffError("request authorized_operations must be a unique list")
    if any(operation not in OPERATIONS for operation in operations):
        raise HandoffError("request authorized_operations contains an unsupported operation")
    if write_authorized != bool(operations):
        raise HandoffError("request write authorization and operations disagree")
    return write_authorized, list(operations)


def _relative_source(value: Any, target: str) -> str:
    source = _text(value, "artifact source", maximum=240)
    path = PurePosixPath(source)
    if path.is_absolute() or not path.parts or ".." in path.parts or str(path) != source:
        raise HandoffError("artifact source path is unsafe")
    if PRIVATE_KEY_PATH_RE.search(source):
        raise HandoffError("artifact source references private key material")
    if not any(source.startswith(prefix) for prefix in SOURCE_PREFIXES[target]):
        raise HandoffError("artifact source is outside the target-system boundary")
    return source


def _destination(value: Any, target: str) -> str:
    destination = _text(value, "artifact destination", maximum=240)
    path = PurePosixPath(destination)
    if not path.parts or ".." in path.parts or str(path) != destination:
        raise HandoffError("artifact destination path is unsafe")
    if PRIVATE_KEY_PATH_RE.search(destination):
        raise HandoffError("artifact destination references private key material")
    if any(
        destination == prefix or destination.startswith(prefix)
        for prefix in PROTECTED_DESTINATION_PREFIXES[target]
    ):
        raise HandoffError("artifact destination is protected runtime configuration or state")
    if not any(destination.startswith(prefix) for prefix in DESTINATION_PREFIXES[target]):
        raise HandoffError("artifact destination is outside the target-system boundary")
    return destination


def _request_artifacts(value: Any, target: str, write_authorized: bool) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > 256:
        raise HandoffError("request artifacts must contain at most 256 entries")
    artifacts = []
    destinations: set[str] = set()
    for index, artifact_value in enumerate(value):
        artifact = _mapping(artifact_value, f"artifact {index}")
        _exact_fields(artifact, ARTIFACT_FIELDS, f"artifact {index}")
        destination = _destination(artifact["destination"], target)
        if destination in destinations:
            raise HandoffError("request contains duplicate artifact destination")
        destinations.add(destination)
        artifacts.append({
            "source": _relative_source(artifact["source"], target),
            "destination": destination,
            "sha256": _sha256(artifact["sha256"], f"artifact {index} sha256"),
            "expected_current_sha256": _optional_sha256(
                artifact["expected_current_sha256"],
                f"artifact {index} expected_current_sha256",
            ),
            "observed_current_sha256": _optional_sha256(
                artifact["observed_current_sha256"],
                f"artifact {index} observed_current_sha256",
            ),
        })
    if write_authorized and not artifacts:
        raise HandoffError("authorized request must identify at least one artifact")
    return artifacts


def _validate_request(request_value: Any) -> dict[str, Any]:
    request = _mapping(request_value, "request")
    _exact_fields(request, REQUEST_FIELDS, "request")
    target = request["target_system"]
    if target not in TARGETS:
        raise HandoffError("request target_system is unsupported")
    owner = _identifier(request["owner"], "request owner")
    purpose = _text(request["purpose"], "request purpose", maximum=512)
    prerequisites = _text_list(request["prerequisites"], "request prerequisites")
    risk = request["risk"]
    if risk not in RISKS:
        raise HandoffError("request risk is unsupported")
    validation = _text_list(request["validation"], "request validation")
    rollback = _text_list(request["rollback"], "request rollback")
    write_authorized, operations = _authorized_operations(request)
    source_revision = _revision(request["source_revision"], "request source_revision")
    rollback_revision = _revision(request["rollback_revision"], "request rollback_revision")
    requested_at = _timestamp(request["requested_at"], "request requested_at")
    artifacts = _request_artifacts(request["artifacts"], target, write_authorized)
    return {
        "target_system": target,
        "owner": owner,
        "purpose": purpose,
        "prerequisites": list(prerequisites),
        "risk": risk,
        "validation": list(validation),
        "rollback": list(rollback),
        "write_authorized": write_authorized,
        "authorized_operations": operations,
        "source_revision": source_revision,
        "rollback_revision": rollback_revision,
        "requested_at": requested_at,
        "artifacts": artifacts,
    }


def _ack_artifacts(value: Any, target: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > 256:
        raise HandoffError("acknowledgement artifacts must contain at most 256 entries")
    artifacts = []
    destinations: set[str] = set()
    for index, artifact_value in enumerate(value):
        artifact = _mapping(artifact_value, f"acknowledgement artifact {index}")
        _exact_fields(artifact, ACK_ARTIFACT_FIELDS, f"acknowledgement artifact {index}")
        destination = _destination(artifact["destination"], target)
        if destination in destinations:
            raise HandoffError("acknowledgement contains duplicate artifact destination")
        destinations.add(destination)
        artifacts.append({
            "destination": destination,
            "sha256": _sha256(artifact["sha256"], f"acknowledgement artifact {index} sha256"),
        })
    return artifacts


def _ack_verification(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value or len(value) > 32:
        raise HandoffError("acknowledgement verification must contain 1 to 32 entries")
    verification = []
    checks: set[str] = set()
    for index, verification_value_item in enumerate(value):
        item = _mapping(verification_value_item, f"verification {index}")
        _exact_fields(item, VERIFICATION_FIELDS, f"verification {index}")
        check = _identifier(item["check"], f"verification {index} check")
        if check in checks:
            raise HandoffError("acknowledgement contains duplicate verification check")
        checks.add(check)
        if item["status"] not in VERIFICATION_STATUSES:
            raise HandoffError("acknowledgement verification status is unsupported")
        verification.append({
            "check": check,
            "status": item["status"],
            "evidence_sha256": _sha256(
                item["evidence_sha256"], f"verification {index} evidence_sha256"
            ),
        })
    return verification


def _validate_ack_policy(
    status: str,
    request: Mapping[str, Any],
    applied_version: str,
    rollback_point: str,
) -> None:
    if status in {"applied", "already_applied"} and applied_version != request["source_revision"]:
        raise HandoffError("acknowledgement applied version differs from source revision")
    if status in {"applied", "already_applied"} and not request["write_authorized"]:
        raise HandoffError("acknowledgement claims an apply without write authorization")
    if rollback_point != request["rollback_revision"]:
        raise HandoffError("acknowledgement rollback point differs from request")


def _validate_acknowledgement(value: Any, request: Mapping[str, Any]) -> dict[str, Any] | None:
    if value is None:
        return None
    ack = _mapping(value, "acknowledgement")
    _exact_fields(ack, ACK_FIELDS, "acknowledgement")
    status = ack["status"]
    if status not in ACK_STATUSES:
        raise HandoffError("acknowledgement status is unsupported")
    request_sha = _sha256(ack["request_sha256"], "acknowledgement request_sha256")
    applied_version = _revision(ack["applied_version"], "acknowledgement applied_version")
    _timestamp(ack["applied_at"], "acknowledgement applied_at")
    rollback_point = _revision(ack["rollback_point"], "acknowledgement rollback_point")
    _validate_ack_policy(status, request, applied_version, rollback_point)
    return {
        "status": status,
        "request_sha256": request_sha,
        "applied_version": applied_version,
        "applied_at": ack["applied_at"],
        "rollback_point": rollback_point,
        "artifacts": _ack_artifacts(ack["artifacts"], request["target_system"]),
        "verification": _ack_verification(ack["verification"]),
    }


def validate_handoff(document_value: Any) -> dict[str, Any]:
    document = _mapping(document_value, "handoff")
    _exact_fields(document, ROOT_FIELDS, "handoff")
    if document["schema_version"] != SCHEMA_VERSION:
        raise HandoffError("handoff schema_version is unsupported")
    change_id = _identifier(document["change_id"], "handoff change_id")
    request = _validate_request(document["request"])
    normalized = {
        "schema_version": SCHEMA_VERSION,
        "change_id": change_id,
        "request": request,
        "acknowledgement": None,
    }
    acknowledgement = _validate_acknowledgement(document["acknowledgement"], request)
    normalized["acknowledgement"] = acknowledgement
    digest = _request_digest_normalized(normalized)
    if acknowledgement is not None and acknowledgement["request_sha256"] != digest:
        raise HandoffError("acknowledgement is not bound to this request")
    return normalized


def _request_digest_normalized(document: Mapping[str, Any]) -> str:
    payload = {
        "schema_version": document["schema_version"],
        "change_id": document["change_id"],
        "request": document["request"],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def request_digest(document_value: Any) -> str:
    return _request_digest_normalized(validate_handoff(document_value))


def _git(repo_root: Path, *args: str, maximum: int = 4096) -> bytes:
    completed = subprocess.run(
        ("git", "-C", str(repo_root), *args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", "replace").strip()[:256]
        raise HandoffError(f"Git source lookup failed: {detail}")
    if len(completed.stdout) > maximum:
        raise HandoffError("Git source lookup exceeded its byte limit")
    return completed.stdout


def _resolve_revision(repo_root: Path, revision: str) -> str:
    resolved = _git(repo_root, "rev-parse", "--verify", f"{revision}^{{commit}}", maximum=128)
    value = resolved.decode("ascii", "strict").strip()
    if value != revision:
        raise HandoffError("request revision is not the exact resolved commit")
    return value


def _git_file_sha256(repo_root: Path, revision: str, source: str) -> str:
    size_raw = _git(repo_root, "cat-file", "-s", f"{revision}:{source}", maximum=64)
    try:
        size = int(size_raw.decode("ascii", "strict").strip())
    except ValueError as exc:
        raise HandoffError("Git artifact size is invalid") from exc
    if size > MAX_ARTIFACT_BYTES:
        raise HandoffError("Git artifact exceeded its byte limit")
    data = _git(repo_root, "show", f"{revision}:{source}", maximum=MAX_ARTIFACT_BYTES)
    return hashlib.sha256(data).hexdigest()


def _validate_source_artifacts(repo_root: Path, request: Mapping[str, Any]) -> None:
    for artifact in request["artifacts"]:
        actual = _git_file_sha256(
            repo_root, request["source_revision"], artifact["source"]
        )
        if actual != artifact["sha256"]:
            raise HandoffError("request source artifact hash differs from Git source")


def _applied_decision(
    request: Mapping[str, Any], acknowledgement: Mapping[str, Any]
) -> tuple[str, int]:
    desired = {item["destination"]: item["sha256"] for item in request["artifacts"]}
    applied = {
        item["destination"]: item["sha256"] for item in acknowledgement["artifacts"]
    }
    paths = set(desired) | set(applied)
    drifted = len(paths) - sum(desired.get(path) == applied.get(path) for path in paths)
    if any(item["status"] != "pass" for item in acknowledgement["verification"]):
        return "verification_review_required", drifted
    return ("noop_already_applied" if drifted == 0 else "drift_review_required"), drifted


def _acknowledgement_decision(
    request: Mapping[str, Any], acknowledgement: Mapping[str, Any] | None
) -> tuple[str, str, int]:
    if acknowledgement is None:
        decision, drifted = _pending_decision(request)
        return decision, "pending", drifted
    status = acknowledgement["status"]
    if status in {"applied", "already_applied"}:
        decision, drifted = _applied_decision(request, acknowledgement)
        return decision, status, drifted
    if status == "rejected":
        return "request_rejected", status, 0
    return "rollback_acknowledged", status, 0


def _pending_decision(request: Mapping[str, Any]) -> tuple[str, int]:
    artifacts = request["artifacts"]
    drifted = sum(
        item["expected_current_sha256"] != item["observed_current_sha256"]
        for item in artifacts
    )
    if drifted:
        return "drift_review_required", drifted
    if artifacts and all(
        item["observed_current_sha256"] == item["sha256"] for item in artifacts
    ):
        return "noop_current_match", 0
    if request["write_authorized"]:
        return "apply_authorized", 0
    return "approval_required", 0


def build_handoff_plan(
    repo_root: Path,
    document_value: Any,
    *,
    prior_document: Any | None = None,
) -> dict[str, Any]:
    document = validate_handoff(document_value)
    request = document["request"]
    _resolve_revision(repo_root, request["source_revision"])
    _resolve_revision(repo_root, request["rollback_revision"])
    digest = _request_digest_normalized(document)
    idempotent_replay = False
    if prior_document is not None:
        prior = validate_handoff(prior_document)
        if prior["change_id"] != document["change_id"]:
            raise HandoffError("prior handoff identity does not match")
        if _request_digest_normalized(prior) != digest:
            raise HandoffError("handoff identity collision: request content changed")
        idempotent_replay = True
    _validate_source_artifacts(repo_root, request)
    acknowledgement = document["acknowledgement"]
    decision, acknowledgement_status, drifted = _acknowledgement_decision(
        request, acknowledgement
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "change_id": document["change_id"],
        "target_system": request["target_system"],
        "source_revision": request["source_revision"],
        "request_sha256": digest,
        "acknowledgement_status": acknowledgement_status,
        "decision": decision,
        "idempotent_replay": idempotent_replay,
        "artifact_counts": {"desired": len(request["artifacts"]), "drifted": drifted},
    }
