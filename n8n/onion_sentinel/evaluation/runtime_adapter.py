"""Concrete bindings for controlled-evaluation runtime policy.

The evaluation policy modules remain independent of the legacy executable.
This adapter projects one runner invocation into those policy objects while
resolving mutable runner callables and constants at invocation time.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, MutableMapping


def isolation_policy(bindings: MutableMapping[str, Any], module: Any) -> Any:
    """Build owner-private runtime-isolation policy from live bindings."""
    b = bindings
    return module.Policy(
        home=b["HOME"],
        mode_environment_key=b["CONTROLLED_EVALUATION_MODE_ENV"],
        runtime_environment_key=b["CONTROLLED_EVALUATION_RUNTIME_DIR_ENV"],
        token_environment_key=b["CONTROLLED_EVALUATION_TOKEN_ENV"],
        token_pattern=b["CONTROLLED_EVALUATION_TOKEN_RE"],
    )


def isolation_dependencies(
    bindings: MutableMapping[str, Any], module: Any,
) -> Any:
    """Build runtime-isolation ports from live runner callables."""
    b = bindings
    return module.Dependencies(
        environment=b["os"].environ,
        owner_id=b["os"].getuid,
        pin_tmpdir=b["pin_controlled_tmpdir"],
        validate_incident_route=b[
            "validate_controlled_incident_evidence_route"
        ],
        isolation_error=b["ControlledEvaluationIsolationError"],
    )


def resolve_runtime(
    bindings: MutableMapping[str, Any], module: Any, runtime: Any,
) -> tuple[bool, Path | None]:
    """Resolve a controlled runtime and publish its pinned temp directory."""
    b = bindings
    b["_CONTROLLED_EVALUATION_TMPDIR"] = None
    result = module.resolve(
        runtime,
        policy=isolation_policy(b, module),
        dependencies=isolation_dependencies(b, module),
    )
    b["_CONTROLLED_EVALUATION_TMPDIR"] = result.tmpdir
    return result.enabled, result.root


def output_directory(out_dir: Path, runtime_root: Path) -> Path:
    """Keep direct controlled output within its canonical runtime root."""
    candidate = out_dir.expanduser()
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(runtime_root)
    except (OSError, ValueError) as exc:
        raise SystemExit(
            "controlled evaluation out_dir must stay inside its runtime "
            "directory"
        ) from exc
    if not candidate.is_absolute() or resolved != candidate:
        raise SystemExit(
            "controlled evaluation out_dir must stay inside its runtime "
            "directory"
        )
    return resolved


def consume_token(
    bindings: MutableMapping[str, Any], enabled: bool,
) -> str:
    """Consume the ephemeral mutation credential before any model child."""
    b = bindings
    supplied = str(
        b["os"].environ.pop(b["CONTROLLED_EVALUATION_TOKEN_ENV"], "") or ""
    ).strip()
    if enabled:
        if not b["CONTROLLED_EVALUATION_TOKEN_RE"].fullmatch(supplied):
            raise SystemExit(
                "controlled evaluation requires an exact ephemeral "
                "authorization token"
            )
        b["_CONTROLLED_EVALUATION_TOKEN"] = supplied
    else:
        b["_CONTROLLED_EVALUATION_TOKEN"] = ""
    return b["_CONTROLLED_EVALUATION_TOKEN"]


def result_policy(bindings: MutableMapping[str, Any], module: Any) -> Any:
    """Build durable result-identity policy from live bindings."""
    b = bindings
    return module.Policy(
        result_environment=b["CONTROLLED_RESULT_ENVIRONMENT"],
        release_environment_key="ONION_SENTINEL_RELEASE_ID",
        model_route_pattern=b["CONTROLLED_MODEL_ROUTE_RE"],
        job_roles={
            "ai_analysis": "soc-analyst",
            "incident_response_analysis": "incident-responder",
        },
        maximum_settings_bytes=b["DEFAULT_MAX_SETTINGS_BYTES"],
    )


def result_dependencies(
    bindings: MutableMapping[str, Any], module: Any,
) -> Any:
    """Build result-identity ports without admitting credential stores."""
    b = bindings
    return module.Dependencies(
        environment=b["os"].environ,
        enabled_routes=b["enabled_agent_model_routes"],
    )


def result_identity(
    bindings: MutableMapping[str, Any],
    module: Any,
    enabled: bool,
    *,
    reanalysis_attempt_id: str,
) -> dict[str, Any] | None:
    """Consume and validate the server-owned durable lease identity."""
    return module.identity(
        enabled,
        reanalysis_attempt_id=reanalysis_attempt_id,
        policy=result_policy(bindings, module),
        dependencies=result_dependencies(bindings, module),
    )


def claim_digest(identity: dict[str, Any]) -> str:
    """Hash lease lineage without retaining the bearer token separately."""
    return hashlib.sha256(
        json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def require_routes(
    bindings: MutableMapping[str, Any],
    module: Any,
    identity: dict[str, Any] | None,
    args: Any,
    settings: dict[str, Any],
    agent_role: str,
) -> None:
    """Recheck frozen routes before any Relay or model invocation."""
    b = bindings
    settings_path = Path(
        getattr(args, "ai_settings_file", b["DEFAULT_AI_SETTINGS_FILE"])
    )
    module.require_routes(
        identity,
        settings_path,
        settings,
        agent_role,
        policy=result_policy(b, module),
        dependencies=result_dependencies(b, module),
    )


def require_result_routes(
    identity: dict[str, Any] | None,
    response: dict[str, Any],
    *,
    gate_error: type[Exception],
) -> None:
    """Require the frozen primary and reviewer routes in the result."""
    if identity is None:
        return
    assigned_route = identity["expected_assigned_route"]
    reviewer_route = identity["expected_reviewer_route"]
    second_opinion = response.get("_second_opinion")
    reviewer_response = (
        second_opinion.get("response")
        if isinstance(second_opinion, dict)
        else None
    )
    if (
        response.get("_analysis_model_route") != assigned_route
        or not isinstance(second_opinion, dict)
        or second_opinion.get("status") != "completed"
        or second_opinion.get("model_route") != reviewer_route
        or not isinstance(reviewer_response, dict)
        or reviewer_response.get("_analysis_model_route") != reviewer_route
    ):
        raise gate_error(
            "controlled evaluation result does not attest both frozen routes"
        )


def apply_memory_freeze(
    allowed: bool, reason: str, *, freeze_enabled: bool,
) -> tuple[bool, str]:
    """Disable only memory persistence during a controlled evaluation."""
    if freeze_enabled:
        return False, "controlled harness evaluation froze memory writeback"
    return allowed, reason
