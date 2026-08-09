"""Concrete provider-execution bindings for the legacy AI runner.

Provider modules own transport and identity policy.  This adapter supplies the
runner's live I/O, locking, credential-artifact, prompt, and dispatch ports at
invocation time so compatibility patches remain effective without duplicating
provider behavior in the executable wrapper.
"""

from __future__ import annotations

from typing import Any, Mapping


def ollama_request(
    b: Mapping[str, Any], prompt_package: dict[str, Any], args: Any,
    settings: dict[str, Any], task: str, *, system_prompt_file: Any = None,
) -> dict[str, Any]:
    return b["_ollama_provider"]().request(
        prompt_package, args, settings, task,
        system_prompt_file=system_prompt_file,
        load_system_prompt=b["load_system_prompt"],
        read_bounded_json=b["read_bounded_json"],
        extract_json_object=b["extract_json_object"],
        urlopen=b["urllib"].request.urlopen,
        request_factory=b["urllib"].request.Request,
        transport_errors=(b["urllib"].error.URLError, b["BoundedHttpError"]),
        fallback_model=b["FALLBACK_OLLAMA_MODEL"],
        default_url=b["DEFAULT_OLLAMA_URL"],
    )


def unload_ollama_model(
    b: Mapping[str, Any], settings: dict[str, Any], model: str, *, timeout: float,
) -> None:
    b["_ollama_provider"]().unload_model(
        settings, model, timeout=timeout,
        urlopen=b["urllib"].request.urlopen,
        request_factory=b["urllib"].request.Request,
        default_url=b["DEFAULT_OLLAMA_URL"],
    )


def ollama_chat_unlocked(
    b: Mapping[str, Any], prompt_package: dict[str, Any], args: Any,
    settings: dict[str, Any], model: str, *, system_prompt_file: Any = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return b["_ollama_provider"]().unlocked_chat(
        prompt_package, args, settings, model,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        safe_copy=b["model_safe_copy"],
        request_call=b["_ollama_request"],
    )


def ollama_chat(
    b: Mapping[str, Any], prompt_package: dict[str, Any], args: Any,
    settings: dict[str, Any], model: str, *, system_prompt_file: Any = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return b["_ollama_provider"]().locked_chat(
        prompt_package, args, settings, model,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        lock_path=b["DEFAULT_OLLAMA_INFERENCE_LOCK"],
        flock=b["fcntl"].flock,
        lock_exclusive=b["fcntl"].LOCK_EX,
        lock_unlock=b["fcntl"].LOCK_UN,
        unlocked_call=b["_ollama_chat_for_model_unlocked"],
        unload_call=b["_unload_ollama_model"],
    )


def response_schema(
    b: Mapping[str, Any], template: dict[str, Any],
) -> dict[str, Any]:
    return b["_codex_provider"]().response_schema(
        template,
        structured_enums=b["STRUCTURED_ENUMS"],
        boolean_keys=b["STRUCTURED_BOOLEAN_KEYS"],
    )


def canonical_system_prompt_file(
    b: Mapping[str, Any], prompt_package: dict[str, Any], args: Any, *,
    system_prompt_file: Any = None, independent_review: bool = False,
) -> Any:
    return b["_codex_provider"]().canonical_system_prompt_file(
        prompt_package, args,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        roles=b["CYBER_SECURITY_AGENT_ROLES"],
        default_settings_file=b["DEFAULT_AI_SETTINGS_FILE"],
        default_system_prompt_file=b["DEFAULT_SYSTEM_PROMPT_FILE"],
        role_prompt_resolver=b["role_prompt_file"],
        reviewer_prompt_resolver=b["role_second_opinion_prompt_file"],
    )


def load_canonical_system_prompt(
    b: Mapping[str, Any], path: Any, agent_role: str,
) -> str:
    return b["_codex_provider"]().load_canonical_system_prompt(
        path, agent_role, b["DEFAULT_MAX_SYSTEM_PROMPT_BYTES"]
    )


def cli_analysis_payload(
    b: Mapping[str, Any], prompt_package: dict[str, Any], args: Any, *,
    hosted: bool, system_prompt_file: Any = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return b["_codex_provider"]().analysis_payload(
        prompt_package, args, hosted=hosted,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        roles=b["CYBER_SECURITY_AGENT_ROLES"],
        canonical_prompt_file=b["canonical_cli_system_prompt_file"],
        load_canonical_prompt=b["load_canonical_cli_system_prompt"],
        load_legacy_prompt=b["load_system_prompt"],
        safe_copy=b["model_safe_copy"],
    )


def prepare_codex_transport(
    b: Mapping[str, Any], prompt_package: dict[str, Any], args: Any, *,
    system_prompt_file: Any = None, independent_review: bool = False,
) -> tuple[dict[str, Any], str]:
    return b["_codex_provider"]().prepare_transport(
        prompt_package, args,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        build_payload=b["cli_analysis_payload"],
        prompt_json_bytes=b["_investigation_prompt_json_bytes"],
        max_package_bytes=b["CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES"],
        max_stdin_bytes=b["CODEX_CLI_MAX_STDIN_BYTES"],
    )


def codex_chat(
    b: Mapping[str, Any], prompt_package: dict[str, Any], args: Any,
    settings: dict[str, Any], *, model: str | None = None,
    reasoning_effort: str | None = None, system_prompt_file: Any = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return b["_codex_provider"]().chat(
        prompt_package, args, settings, model=model,
        reasoning_effort=reasoning_effort,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        resolve_executable=b["resolve_codex_cli"],
        model_pattern=b["CODEX_CLI_MODEL_PATTERN"],
        reasoning_efforts=b["CODEX_CLI_REASONING_EFFORTS"],
        prepare=b["prepare_codex_cli_transport"],
        schema_builder=b["response_output_json_schema"],
        run_command=b["run_bounded_command"],
        sanitized_env=b["sanitized_cli_harness_env"],
        process_error=b["BoundedProcessError"],
        summarize=b["summarize_codex_cli_failure"],
        read_bytes=b["read_bytes_bounded"],
        extract_json=b["extract_json_object"],
        max_stderr_bytes=b["DEFAULT_CLOUD_MAX_STDERR_BYTES"],
        controlled_tmpdir=b["_CONTROLLED_EVALUATION_TMPDIR"],
    )


def sanitized_cli_environment(
    b: Mapping[str, Any], executable: str, *,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    return b["_cli_common_provider"]().sanitized_environment(
        executable, extra=extra
    )


def summarize_cli_failure(
    b: Mapping[str, Any], label: str, stderr: str, returncode: int,
) -> str:
    return b["_cli_common_provider"]().summarize_harness_failure(
        label, stderr, returncode
    )


def load_bounded_json(
    b: Mapping[str, Any], path: Any, *, max_bytes: int, label: str,
    required_mode: int | None = None,
) -> dict[str, Any]:
    return b["_provider_artifacts"]().read_json_object(
        path, max_bytes=max_bytes, label=label, required_mode=required_mode,
        error_type=b["RuntimeArtifactError"],
    )


def load_hermes_auth(
    b: Mapping[str, Any], path: Any,
) -> dict[str, Any]:
    return b["_hermes_provider"]().load_auth(
        path, read_json=b["_load_bounded_regular_json"],
        error_type=b["RuntimeArtifactError"],
        max_bytes=b["HERMES_MAX_AUTH_BYTES"],
    )


def write_hermes_auth(
    b: Mapping[str, Any], path: Any, auth_store: dict[str, Any],
) -> None:
    b["_hermes_provider"]().write_auth(
        path, auth_store, error_type=b["RuntimeArtifactError"]
    )


def verify_hermes_usage(
    b: Mapping[str, Any], path: Any, *, expected_model: str,
) -> dict[str, Any]:
    return b["_hermes_provider"]().verified_usage(
        path, expected_model=expected_model,
        read_json=b["_load_bounded_regular_json"],
        error_type=b["RuntimeArtifactError"],
        max_bytes=b["HERMES_MAX_USAGE_BYTES"],
    )


def hermes_chat(
    b: Mapping[str, Any], prompt_package: dict[str, Any], args: Any,
    settings: dict[str, Any], *, model: str, reasoning_effort: str,
    system_prompt_file: Any = None, independent_review: bool = False,
) -> dict[str, Any]:
    return b["_hermes_provider"]().chat(
        prompt_package, args, settings, model=model,
        reasoning_effort=reasoning_effort,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        boolean_setting=b["boolean_setting"],
        model_catalog=b["CODEX_CLI_MODEL_CATALOG"],
        required_effort=b["HERMES_AGENT_REASONING_EFFORT"],
        resolve_executable=lambda configured: b["resolve_cli_harness"](
            configured, setting_key="hermes_agent_path", basename="hermes",
            label="Hermes Agent",
        ),
        build_payload=b["cli_analysis_payload"],
        auth_file=b["DEFAULT_HERMES_AUTH_FILE"],
        load_dedicated_auth=b["_load_dedicated_hermes_auth"],
        write_dedicated_auth=b["_write_dedicated_hermes_auth"],
        atomic_write_json=b["atomic_write_json"],
        run_command=b["run_bounded_command"],
        sanitized_env=b["sanitized_cli_harness_env"],
        process_error=b["BoundedProcessError"],
        artifact_error=b["RuntimeArtifactError"],
        summarize_failure=b["summarize_cli_harness_failure"],
        verify_usage=b["_verified_hermes_usage"],
        extract_json=b["extract_json_object"],
        max_prompt_bytes=b["HERMES_MAX_PROMPT_ARGUMENT_BYTES"],
        max_stderr_bytes=b["DEFAULT_CLOUD_MAX_STDERR_BYTES"],
        flock=b["fcntl"].flock,
        lock_exclusive=b["fcntl"].LOCK_EX,
        lock_unlock=b["fcntl"].LOCK_UN,
    )


def openclaw_infer_unlocked(
    b: Mapping[str, Any], prompt_package: dict[str, Any], args: Any,
    settings: dict[str, Any], *, model: str, reasoning_effort: str,
    system_prompt_file: Any = None, independent_review: bool = False,
) -> dict[str, Any]:
    return b["_openclaw_provider"]().infer_unlocked(
        prompt_package, args, settings, model=model,
        reasoning_effort=reasoning_effort,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        validate=b["validate_isolated_openclaw_route"],
        resolve_executable=lambda configured: b["resolve_cli_harness"](
            configured, setting_key="openclaw_path", basename="openclaw",
            label="OpenClaw",
        ),
        build_payload=b["cli_analysis_payload"],
        atomic_write_json=b["atomic_write_json"],
        run_command=b["run_bounded_command"],
        sanitized_env=b["sanitized_cli_harness_env"],
        process_error=b["BoundedProcessError"],
        summarize_failure=b["summarize_cli_harness_failure"],
        extract_json=b["extract_json_object"],
        max_prompt_bytes=b["OPENCLAW_MAX_PROMPT_ARGUMENT_BYTES"],
        max_stderr_bytes=b["DEFAULT_CLOUD_MAX_STDERR_BYTES"],
    )


def openclaw_chat(
    b: Mapping[str, Any], prompt_package: dict[str, Any], args: Any,
    settings: dict[str, Any], *, model: str, reasoning_effort: str,
    system_prompt_file: Any = None, independent_review: bool = False,
) -> dict[str, Any]:
    return b["_openclaw_provider"]().locked_chat(
        prompt_package, args, settings, model=model,
        reasoning_effort=reasoning_effort,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        boolean_setting=b["boolean_setting"],
        model_pattern=b["CLI_HARNESS_MODEL_PATTERN"],
        reasoning_efforts=b["CODEX_CLI_REASONING_EFFORTS"],
        validate=b["validate_isolated_openclaw_route"],
        lock_path=b["DEFAULT_OLLAMA_INFERENCE_LOCK"],
        flock=b["fcntl"].flock,
        lock_exclusive=b["fcntl"].LOCK_EX,
        lock_unlock=b["fcntl"].LOCK_UN,
        infer=b["_openclaw_infer_unlocked"],
        unload=b["_unload_ollama_model"],
    )


def dispatch(
    b: Mapping[str, Any], route: str, prompt_package: dict[str, Any],
    args: Any, settings: dict[str, Any], *, system_prompt_file: Any = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return b["_provider_registry"]().dispatch(
        route, prompt_package, args, settings,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        enabled_routes=b["enabled_agent_model_routes"],
        canonicalize=b["canonical_model_route"],
        is_hosted=b["model_route_is_hosted"],
        synchronize_hosted=b["synchronize_hosted_investigation_contract"],
        parse_codex=b["parse_codex_cli_route"],
        parse_harness=b["parse_cli_harness_route"],
        codex_adapter=b["cloud_cli_chat"],
        hermes_adapter=b["hermes_agent_chat"],
        openclaw_adapter=b["openclaw_infer_chat"],
        ollama_adapter=b["_ollama_chat_for_model"],
        attest=b["attest_model_route_response"],
    )
