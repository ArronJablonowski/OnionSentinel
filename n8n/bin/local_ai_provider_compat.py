"""Legacy model-provider transport and routing compatibility delegates."""
from __future__ import annotations

def _ollama_request(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    task: str,
    *,
    system_prompt_file: Path | None = None,
) -> dict[str, Any]:
    return _provider_execution_adapter().ollama_request(
        globals(), prompt_package, args, settings, task,
        system_prompt_file=system_prompt_file,
    )


def _unload_ollama_model(
    settings: dict[str, Any],
    model: str,
    *,
    timeout: float,
) -> None:
    _provider_execution_adapter().unload_ollama_model(
        globals(), settings, model, timeout=timeout
    )


def _ollama_chat_for_model_unlocked(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    model: str,
    *,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return _provider_execution_adapter().ollama_chat_unlocked(
        globals(), prompt_package, args, settings, model,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def _ollama_chat_for_model(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    model: str,
    *,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return _provider_execution_adapter().ollama_chat(
        globals(), prompt_package, args, settings, model,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def summarize_codex_cli_failure(stderr: str, returncode: int) -> str:
    return _codex_provider().summarize_failure(stderr, returncode)




def response_output_json_schema(template: dict[str, Any]) -> dict[str, Any]:
    return _provider_execution_adapter().response_schema(globals(), template)


def canonical_cli_system_prompt_file(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    *,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> Path:
    return _provider_execution_adapter().canonical_system_prompt_file(
        globals(), prompt_package, args,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def load_canonical_cli_system_prompt(path: Path, agent_role: str) -> str:
    return _provider_execution_adapter().load_canonical_system_prompt(
        globals(), path, agent_role
    )


def cli_analysis_payload(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    *,
    hosted: bool,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return _provider_execution_adapter().cli_analysis_payload(
        globals(), prompt_package, args,
        hosted=hosted,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def prepare_codex_cli_transport(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    *,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> tuple[dict[str, Any], str]:
    return _provider_execution_adapter().prepare_codex_transport(
        globals(), prompt_package, args,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def cloud_cli_chat(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    *,
    model: str | None = None,
    reasoning_effort: str | None = None,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return _provider_execution_adapter().codex_chat(
        globals(), prompt_package, args, settings,
        model=model,
        reasoning_effort=reasoning_effort,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def sanitized_cli_harness_env(
    executable: str,
    *,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    return _provider_execution_adapter().sanitized_cli_environment(
        globals(), executable, extra=extra
    )


def summarize_cli_harness_failure(
    label: str,
    stderr: str,
    returncode: int,
) -> str:
    return _provider_execution_adapter().summarize_cli_failure(
        globals(), label, stderr, returncode
    )


def _load_bounded_regular_json(
    path: Path,
    *,
    max_bytes: int,
    label: str,
    required_mode: int | None = None,
) -> dict[str, Any]:
    """Compatibility delegate for descriptor-verified provider artifacts."""
    return _provider_execution_adapter().load_bounded_json(
        globals(), path, max_bytes=max_bytes, label=label,
        required_mode=required_mode,
    )


def _load_dedicated_hermes_auth(path: Path) -> dict[str, Any]:
    return _provider_execution_adapter().load_hermes_auth(globals(), path)


def _write_dedicated_hermes_auth(
    path: Path,
    auth_store: dict[str, Any],
) -> None:
    _provider_execution_adapter().write_hermes_auth(globals(), path, auth_store)


def _verified_hermes_usage(
    path: Path,
    *,
    expected_model: str,
) -> dict[str, Any]:
    return _provider_execution_adapter().verify_hermes_usage(
        globals(), path, expected_model=expected_model
    )


def hermes_agent_chat(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    *,
    model: str,
    reasoning_effort: str,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return _provider_execution_adapter().hermes_chat(
        globals(), prompt_package, args, settings,
        model=model,
        reasoning_effort=reasoning_effort,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def _openclaw_infer_unlocked(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    *,
    model: str,
    reasoning_effort: str,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return _provider_execution_adapter().openclaw_infer_unlocked(
        globals(), prompt_package, args, settings,
        model=model,
        reasoning_effort=reasoning_effort,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def openclaw_infer_chat(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    *,
    model: str,
    reasoning_effort: str,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return _provider_execution_adapter().openclaw_chat(
        globals(), prompt_package, args, settings,
        model=model,
        reasoning_effort=reasoning_effort,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def analyze_model_route(
    route: str,
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    *,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return _provider_execution_adapter().dispatch(
        globals(), route, prompt_package, args, settings,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def model_route_identity(
    route: Any,
    settings: dict[str, Any] | None = None,
) -> str:
    return _provider_routing().model_route_identity(route, settings)

__all__ = tuple(
    name for name, value in globals().items()
    if getattr(value, "__module__", None) == __name__
)

