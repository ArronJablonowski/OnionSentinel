"""Controlled-evaluation compatibility policy for the scheduler facade."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, MutableMapping


RuntimeNamespace = MutableMapping[str, Any]


def controlled_evaluation_runtime(runtime: RuntimeNamespace, args: Any) -> Path | None:
    return runtime["validate_controlled_evaluation_runtime"](
        args,
        runtime["ControlledRuntimePolicy"](
            home=runtime["HOME"],
            release_environment_key=runtime["RUNTIME_RELEASE_ENV_KEY"],
            token_environment_key=runtime["CONTROLLED_EVALUATION_TOKEN_ENV"],
            release_pattern=runtime["CONTROLLED_RELEASE_ID_RE"],
            token_pattern=runtime["CONTROLLED_EVALUATION_TOKEN_RE"],
        ),
        runtime["ControlledRuntimeSources"](
            environment=runtime["os"].environ,
            effective_uid=runtime["os"].getuid,
            pin_tmpdir=runtime["pin_controlled_tmpdir"],
            validate_incident_evidence_route=runtime[
                "validate_controlled_incident_evidence_route"
            ],
            role_prompt_file=runtime["role_prompt_file"],
            role_second_opinion_prompt_file=runtime[
                "role_second_opinion_prompt_file"
            ],
            role_memory_file=runtime["role_memory_file"],
            isolation_error=runtime["ControlledEvaluationIsolationError"],
        ),
    )


def valid_controlled_stable_group_key(value: object, max_length: int) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return len(encoded) <= max_length


def controlled_canonical_digest(
    value: object,
    *,
    ensure_ascii: bool = True,
) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=ensure_ascii,
        ).encode("utf-8")
    ).hexdigest()


def consume_controlled_evaluation_token(
    runtime: RuntimeNamespace,
    enabled: bool,
) -> str:
    supplied = str(
        runtime["os"].environ.pop(
            runtime["CONTROLLED_EVALUATION_TOKEN_ENV"],
            "",
        )
        or ""
    ).strip()
    if enabled:
        if not runtime["CONTROLLED_EVALUATION_TOKEN_RE"].fullmatch(supplied):
            raise SystemExit(
                "controlled evaluation requires an exact ephemeral "
                "authorization token"
            )
        runtime["_CONTROLLED_EVALUATION_TOKEN"] = supplied
    else:
        runtime["_CONTROLLED_EVALUATION_TOKEN"] = ""
    return runtime["_CONTROLLED_EVALUATION_TOKEN"]


def alert_store_mutation_headers(
    runtime: RuntimeNamespace,
    *,
    user_agent: str = "",
) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if user_agent:
        headers["User-Agent"] = user_agent
    supplied_token = str(
        runtime["os"].environ.get(runtime["CONTROLLED_EVALUATION_TOKEN_ENV"])
        or ""
    ).strip()
    evaluation_token = (
        supplied_token
        if runtime["CONTROLLED_EVALUATION_TOKEN_RE"].fullmatch(supplied_token)
        else runtime["_CONTROLLED_EVALUATION_TOKEN"]
    )
    if (
        str(runtime["os"].environ.get("ONION_SENTINEL_EVALUATION_MODE") or "").strip()
        == "1"
        and runtime["CONTROLLED_EVALUATION_TOKEN_RE"].fullmatch(evaluation_token)
    ):
        headers[runtime["CONTROLLED_EVALUATION_TOKEN_HEADER"]] = evaluation_token
    return headers


def owner_private_directory(
    runtime: RuntimeNamespace,
    path: Path,
    runtime_root: Path,
) -> bool:
    return runtime["private_recovery_directory"](
        path,
        runtime_root,
        effective_uid=runtime["os"].getuid(),
    )


def load_owner_private_json(
    runtime: RuntimeNamespace,
    path: Path,
    runtime_root: Path,
    *,
    max_bytes: int,
) -> dict[str, Any]:
    return runtime["load_private_recovery_json"](
        path,
        runtime_root,
        max_bytes=max_bytes,
        effective_uid=runtime["os"].getuid(),
    )


def post_controlled_recovery_result(
    runtime: RuntimeNamespace,
    payload: dict[str, Any],
    alert_store_url: str,
    *,
    attempts: int,
) -> dict[str, Any]:
    return runtime["post_controlled_result"](
        runtime["ControlledResultClientSources"](
            mutation_headers=lambda user_agent: runtime[
                "alert_store_mutation_headers"
            ](user_agent=user_agent),
            open_url=runtime["urllib"].request.urlopen,
            read_bounded_json=runtime["read_bounded_json"],
            sleep=runtime["time"].sleep,
            transport_errors=(
                runtime["urllib"].error.URLError,
                TimeoutError,
                OSError,
                runtime["BoundedHttpError"],
            ),
        ),
        runtime["ControlledResultClientPolicy"](
            indeterminate_marker=runtime[
                "CONTROLLED_RESULT_SUBMISSION_INDETERMINATE"
            ],
            max_response_bytes=runtime["DEFAULT_MAX_CONTROL_RESPONSE_BYTES"],
        ),
        payload,
        alert_store_url,
        attempts=attempts,
    )


def validate_controlled_recovery_payload(
    runtime: RuntimeNamespace,
    payload: dict[str, Any],
    args: Any,
) -> dict[str, Any]:
    return runtime["validate_controlled_payload"](
        runtime["ControlledPayloadPolicy"](
            lease_token_pattern=runtime["CONTROLLED_LEASE_TOKEN_RE"],
            cohort_id_pattern=runtime["CONTROLLED_COHORT_ID_RE"],
            model_route_pattern=runtime["CONTROLLED_MODEL_ROUTE_RE"],
            analysis_id_pattern=runtime["CONTROLLED_ANALYSIS_ID_RE"],
        ),
        runtime["ControlledPayloadSources"](
            current_release_id=runtime["current_runtime_release_id"],
            incident_attempt_id=runtime["incident_reanalysis_attempt_id"],
            canonical_digest=runtime["controlled_canonical_digest"],
            storage_canonical_digest=runtime["controlled_storage_canonical_digest"],
            expected_accepted_fields=runtime[
                "controlled_expected_accepted_fields"
            ],
        ),
        payload,
        args,
    )


def settle_controlled_frozen_memory_artifacts(
    runtime: RuntimeNamespace,
    runtime_root: Path,
    recovery: dict[str, Any],
) -> None:
    runtime["settle_frozen_memory"](
        runtime_root,
        recovery,
        policy=runtime["FrozenMemoryPolicy"](),
        effective_uid=runtime["os"].getuid(),
    )


def build_controlled_recovery_policy(runtime: RuntimeNamespace) -> Any:
    return runtime["ControlledRecoveryPolicy"](
        max_spool_bytes=runtime["MAX_CONTROLLED_RESULT_SPOOL_BYTES"],
        indeterminate_submission_marker=runtime[
            "CONTROLLED_RESULT_SUBMISSION_INDETERMINATE"
        ],
    )


def recover_controlled_evaluation_spool(
    runtime: RuntimeNamespace,
    args: Any,
    runtime_root: Path,
) -> bool:
    return runtime["replay_controlled_result_spool"](
        runtime["controlled_recovery_sources"](),
        runtime["controlled_recovery_policy"](),
        args,
        runtime_root,
    )


def controlled_recovery_spool_pending(
    runtime: RuntimeNamespace,
    runtime_root: Path,
) -> bool:
    return runtime["controlled_spool_pending"](
        runtime_root,
        effective_uid=runtime["os"].getuid,
    )


def controlled_recovery_terminal_success(
    runtime: RuntimeNamespace,
    args: Any,
    recovery: dict[str, Any],
) -> bool:
    return runtime["prove_controlled_terminal_success"](
        runtime["controlled_terminal_proof_sources"](),
        args.db,
        recovery,
    )


def current_runtime_release_id(
    runtime: RuntimeNamespace,
    *,
    environ: object | None = None,
    env_path: Path | None = None,
) -> str:
    return runtime["load_runtime_release_id"](
        runtime["ControlledReleasePolicy"](
            environment_key=runtime["RUNTIME_RELEASE_ENV_KEY"],
            default_env_path=runtime["DEFAULT_RUNTIME_ENV_PATH"],
            max_env_bytes=runtime["MAX_RUNTIME_ENV_BYTES"],
            release_pattern=runtime["CONTROLLED_RELEASE_ID_RE"],
        ),
        environ=runtime["os"].environ if environ is None else environ,
        env_path=env_path,
    )


def require_controlled_release_attestation(
    runtime: RuntimeNamespace,
    claimed_payload: dict[str, object],
) -> str:
    return runtime["attest_controlled_release"](
        runtime["ControlledReleasePolicy"](
            environment_key=runtime["RUNTIME_RELEASE_ENV_KEY"],
            default_env_path=runtime["DEFAULT_RUNTIME_ENV_PATH"],
            max_env_bytes=runtime["MAX_RUNTIME_ENV_BYTES"],
            release_pattern=runtime["CONTROLLED_RELEASE_ID_RE"],
        ),
        claimed_payload,
        runtime["current_runtime_release_id"](),
        runtime["ControlledClaimRejected"],
    )
