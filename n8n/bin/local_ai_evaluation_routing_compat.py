"""Legacy controlled-evaluation and model-routing compatibility delegates."""
from __future__ import annotations

def _evaluation_runtime_isolation():
    _provider_routing()
    from onion_sentinel.evaluation import runtime_isolation
    return runtime_isolation


def _evaluation_runtime_adapter():
    _provider_routing()
    from onion_sentinel.evaluation import runtime_adapter
    return runtime_adapter


def _evaluation_reviewer_gate():
    _provider_routing()
    from onion_sentinel.evaluation import reviewer_gate
    return reviewer_gate


def _evaluation_reviewer_gate_dependencies():
    module = _evaluation_reviewer_gate()
    return module.Dependencies(
        route_identity=model_route_identity,
        route_is_hosted=model_route_is_hosted,
        build_review_package=independent_reviewer_package,
        validate_reviewer=validate_reviewer_response,
        validate_response=validate_response,
        validation_errors=(ReviewerValidationError, SystemExit, TypeError, ValueError),
        gate_error=ControlledEvaluationReviewerGateError,
    )


def _evaluation_runtime_isolation_policy():
    return _evaluation_runtime_adapter().isolation_policy(
        globals(), _evaluation_runtime_isolation()
    )


def _evaluation_runtime_isolation_dependencies():
    return _evaluation_runtime_adapter().isolation_dependencies(
        globals(), _evaluation_runtime_isolation()
    )


def _evaluation_result_identity():
    _provider_routing()
    from onion_sentinel.evaluation import result_identity
    return result_identity


def _evaluation_result_identity_policy():
    return _evaluation_runtime_adapter().result_policy(
        globals(), _evaluation_result_identity()
    )


def _evaluation_result_identity_dependencies():
    return _evaluation_runtime_adapter().result_dependencies(
        globals(), _evaluation_result_identity()
    )


def controlled_evaluation_runtime(
    runtime: argparse.Namespace | str,
) -> tuple[bool, Path | None]:
    """Resolve an owner-only spool root for one controlled evaluation."""
    return _evaluation_runtime_adapter().resolve_runtime(
        globals(), _evaluation_runtime_isolation(), runtime
    )


def controlled_evaluation_output_dir(
    out_dir: Path,
    runtime_root: Path,
) -> Path:
    """Keep direct controlled output inside its owner-only evaluation root."""
    return _evaluation_runtime_adapter().output_directory(out_dir, runtime_root)


def consume_controlled_evaluation_token(enabled: bool) -> str:
    """Remove the mutation credential before invoking any model subprocess."""
    return _evaluation_runtime_adapter().consume_token(globals(), enabled)


def controlled_evaluation_result_identity(
    enabled: bool,
    *,
    reanalysis_attempt_id: str,
) -> dict[str, Any] | None:
    """Compatibility delegate for server-owned durable lease identity."""
    return _evaluation_runtime_adapter().result_identity(
        globals(),
        _evaluation_result_identity(),
        enabled,
        reanalysis_attempt_id=reanalysis_attempt_id,
    )


def controlled_evaluation_claim_digest(identity: dict[str, Any]) -> str:
    """Hash lease lineage without persisting the bearer token itself."""
    return _evaluation_runtime_adapter().claim_digest(identity)


def require_controlled_evaluation_routes(
    identity: dict[str, Any] | None,
    args: argparse.Namespace,
    settings: dict[str, Any],
    agent_role: str,
) -> None:
    """Compatibility delegate for frozen controlled route admission."""
    _evaluation_runtime_adapter().require_routes(
        globals(),
        _evaluation_result_identity(),
        identity,
        args,
        settings,
        agent_role,
    )


def require_controlled_evaluation_result_routes(
    identity: dict[str, Any] | None,
    response: dict[str, Any],
) -> None:
    """Reject a controlled result unless both frozen routes actually ran."""
    _evaluation_runtime_adapter().require_result_routes(
        identity,
        response,
        gate_error=ControlledEvaluationReviewerGateError,
    )


def apply_evaluation_memory_freeze(
    allowed: bool,
    reason: str,
    *,
    freeze_enabled: bool,
) -> tuple[bool, str]:
    """Disable only memory persistence during a controlled evaluation run."""
    return _evaluation_runtime_adapter().apply_memory_freeze(
        allowed, reason, freeze_enabled=freeze_enabled
    )


def parse_cli_harness_route(
    route: str,
    provider: str,
) -> tuple[str, str] | None:
    return _provider_routing().parse_cli_harness_route(route, provider)


def openclaw_model_uses_ollama_runtime(model: str) -> bool:
    return _provider_routing().openclaw_model_uses_ollama_runtime(model)


def validate_isolated_openclaw_route(
    model: str,
    settings: dict[str, Any],
) -> None:
    return _openclaw_provider().validate_route(
        model,
        settings,
        model_pattern=CLI_HARNESS_MODEL_PATTERN,
        uses_ollama_runtime=openclaw_model_uses_ollama_runtime,
        provider_prefix=OPENCLAW_OLLAMA_PROVIDER_PREFIX,
        supported_urls=OPENCLAW_SUPPORTED_OLLAMA_URLS,
        default_url=DEFAULT_OLLAMA_URL,
    )


def model_route_is_hosted(route: str, settings: dict[str, Any]) -> bool:
    """Return the evidence boundary for an exact configured route."""
    normalized = canonical_model_route(route, enabled_agent_model_routes(settings))
    if normalized.startswith(("codex-cli:", "hermes-agent:")):
        return True
    if parse_cli_harness_route(normalized, "openclaw"):
        # OpenClaw is a third-party harness boundary even when its selected
        # provider happens to be a host-local Ollama runtime. Evidence
        # redaction therefore never depends on the model provider prefix.
        return True
    return False


def enabled_agent_model_routes(settings: dict[str, Any]) -> list[str]:
    return _provider_routing().enabled_agent_model_routes(settings)


def canonical_model_route(value: Any, routes: list[str] | None = None) -> str:
    return _provider_routing().canonical_model_route(value, routes)


def parse_codex_cli_route(route: str) -> tuple[str, str] | None:
    return _provider_routing().parse_codex_cli_route(route)


def assigned_model_metadata(
    settings: dict[str, Any],
    agent_role: str,
) -> tuple[str, str, str]:
    return _provider_routing().assigned_model_metadata(settings, agent_role)


def model_route_metadata(
    settings: dict[str, Any],
    route: str,
) -> tuple[str, str, str, str]:
    return _provider_routing().model_route_metadata(settings, route)


def attest_model_route_response(
    settings: dict[str, Any],
    route: str,
    response: dict[str, Any],
) -> dict[str, Any]:
    return _provider_registry().attest_response(
        settings,
        route,
        response,
        route_metadata=model_route_metadata,
    )


def current_analysis_phase_record(
    current_record: dict[str, Any],
    settings: dict[str, Any],
    *,
    phase: str,
    model_route: str = "",
    trigger_reason: str = "",
) -> dict[str, Any]:
    """Return live-only execution metadata without changing primary log fields."""
    return _reporting_runtime_adapter().phase_record(
        globals(), current_record, settings, phase=phase,
        model_route=model_route, trigger_reason=trigger_reason,
    )


def publish_current_analysis_phase(
    current_record: dict[str, Any],
    settings: dict[str, Any],
    *,
    phase: str,
    model_route: str = "",
    trigger_reason: str = "",
    active_record_path: Path | None = None,
) -> dict[str, Any]:
    """Atomically publish one transient phase for this analysis run."""
    return _reporting_runtime_adapter().publish_phase(
        globals(), current_record, settings, phase=phase,
        model_route=model_route, trigger_reason=trigger_reason,
        active_record_path=active_record_path,
    )


def notify_analysis_phase(
    callback: Callable[[str, str, str], None] | None,
    phase: str,
    model_route: str = "",
    trigger_reason: str = "",
) -> None:
    """Publish optional live status without allowing telemetry to fail analysis."""
    _reporting_runtime_adapter().notify_phase(
        callback, phase, model_route, trigger_reason
    )


def normalize_agent_models(value: Any, routes: list[str]) -> dict[str, str]:
    """Give every agent one valid assignment, falling back deterministically.

    A disabled or removed route must never survive into execution. The first
    enabled route is intentionally used as a predictable fail-safe so roster
    maintenance cannot leave an agent without an analysis backend.
    """
    return _provider_settings_runtime_adapter().normalize_agent_models(
        globals(), value, routes)


def normalize_agent_second_opinion_models(
    value: Any,
    routes: list[str],
    primary_assignments: dict[str, str],
) -> dict[str, str]:
    """Keep optional secondary routes enabled, distinct, and fail-closed."""
    return _provider_settings_runtime_adapter().normalize_agent_second_opinion_models(
        globals(), value, routes, primary_assignments)


def normalize_agent_adjudicator_models(
    value: Any,
    routes: list[str],
    primary_assignments: dict[str, str],
    reviewer_assignments: dict[str, str],
    settings: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Keep adjudicators optional, enabled, and independent of both positions."""
    return _provider_settings_runtime_adapter().normalize_agent_adjudicator_models(
        globals(), value, routes, primary_assignments,
        reviewer_assignments, settings)


def apply_model_roster(settings: dict[str, Any], raw: dict[str, Any]) -> dict[str, Any]:
    """Migrate legacy single-model settings and derive the compatibility mode."""
    return _provider_settings_runtime_adapter().apply_model_roster(
        globals(), settings, raw)


def normalize_codex_cli_settings(settings: dict[str, Any], raw: dict[str, Any]) -> None:
    """Normalize the fixed Codex adapter without accepting shell fragments."""
    _provider_settings_runtime_adapter().normalize_codex_cli_settings(
        globals(), settings, raw)


def _normalize_harness_executable(value: Any, basename: str) -> str:
    """Validate an exact executable path without accepting flags or shell text."""
    return _provider_settings_runtime_adapter().normalize_harness_executable(
        globals(), value, basename)


def normalize_cli_harness_settings(
    settings: dict[str, Any],
    raw: dict[str, Any],
) -> None:
    """Normalize the two optional, independently enabled agent harnesses."""
    _provider_settings_runtime_adapter().normalize_cli_harness_settings(
        globals(), settings, raw)


def load_ai_settings(path: Path) -> dict[str, Any]:
    """Load model routing settings written by the SOC Settings page."""
    return _provider_settings_runtime_adapter().load_ai_settings(globals(), path)


def resolve_codex_cli(settings: dict[str, Any]) -> str:
    """Resolve only the operator-approved Codex executable."""
    return _provider_settings_runtime_adapter().resolve_codex_cli(
        globals(), settings)


def resolve_cli_harness(
    settings: dict[str, Any],
    *,
    setting_key: str,
    basename: str,
    label: str,
) -> str:
    """Resolve only the operator-approved exact third-party executable."""
    return _provider_settings_runtime_adapter().resolve_cli_harness(
        globals(), settings, setting_key=setting_key,
        basename=basename, label=label)


def effective_ai_settings(args: argparse.Namespace) -> dict[str, Any]:
    """Merge settings file, environment defaults, and explicit CLI overrides."""
    return _provider_settings_runtime_adapter().effective_ai_settings(
        globals(), args)


def extract_json_object(text: str) -> dict[str, Any]:
    """Compatibility delegate for fail-closed provider output parsing."""
    return _provider_artifacts().parse_model_output_object(text)

__all__ = tuple(
    name for name, value in globals().items()
    if getattr(value, "__module__", None) == __name__
)
