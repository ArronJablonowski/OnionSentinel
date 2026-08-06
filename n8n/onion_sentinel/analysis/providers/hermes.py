"""Credential-isolated, one-shot Hermes provider adapter."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any, Callable


def _provider_credentials(
    raw: dict[str, Any],
    error_type: type[Exception],
) -> tuple[dict[str, Any] | None, list[dict[str, Any]] | None]:
    providers = raw.get("providers")
    provider_state = providers.get("openai-codex") if isinstance(providers, dict) else None
    credential_pool = raw.get("credential_pool")
    pool_entries = (
        credential_pool.get("openai-codex")
        if isinstance(credential_pool, dict)
        else None
    )
    if isinstance(pool_entries, list) and any(
        not isinstance(entry, dict)
        or (
            entry.get("provider") is not None
            and str(entry.get("provider")).strip() != "openai-codex"
        )
        for entry in pool_entries
    ):
        raise error_type("dedicated Hermes openai-codex credential pool is invalid")
    return (
        provider_state if isinstance(provider_state, dict) and provider_state else None,
        pool_entries if isinstance(pool_entries, list) and pool_entries else None,
    )


def filtered_auth_store(
    raw: dict[str, Any],
    *,
    error_type: type[Exception],
    require_credentials: bool = True,
) -> dict[str, Any]:
    """Keep only the dedicated OpenAI Codex provider and credential pool."""
    provider_state, pool_entries = _provider_credentials(raw, error_type)
    has_provider = provider_state is not None
    has_pool = pool_entries is not None
    if require_credentials and not (has_provider or has_pool):
        raise error_type(
            "dedicated Hermes auth store does not contain openai-codex credentials"
        )
    raw_version = raw.get("version")
    version = (
        raw_version
        if isinstance(raw_version, int)
        and not isinstance(raw_version, bool)
        and raw_version > 0
        else 1
    )
    filtered: dict[str, Any] = {
        "version": version,
        "active_provider": "openai-codex",
        "providers": {},
    }
    if has_provider:
        filtered["providers"]["openai-codex"] = provider_state
    if has_pool:
        filtered["credential_pool"] = {"openai-codex": pool_entries}
    return filtered


def load_auth(
    path: Path,
    *,
    read_json: Callable[..., dict[str, Any]],
    error_type: type[Exception],
    max_bytes: int,
) -> dict[str, Any]:
    """Read only the explicit Onion Sentinel Hermes credential store."""
    return filtered_auth_store(
        read_json(
            path,
            max_bytes=max_bytes,
            label="dedicated Hermes authentication",
            required_mode=0o600,
        ),
        error_type=error_type,
    )


def write_auth(
    path: Path,
    auth_store: dict[str, Any],
    *,
    error_type: type[Exception],
) -> None:
    """Atomically persist a filtered, owner-only Hermes credential store."""
    if path.is_symlink():
        raise error_type("dedicated Hermes authentication path must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink():
        raise error_type(
            "dedicated Hermes authentication directory must not be a symlink"
        )
    path.parent.chmod(0o700)
    filtered = filtered_auth_store(auth_store, error_type=error_type)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(json.dumps(filtered, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
        try:
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except OSError:
            pass
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def verified_usage(
    path: Path,
    *,
    expected_model: str,
    read_json: Callable[..., dict[str, Any]],
    error_type: type[Exception],
    max_bytes: int,
) -> dict[str, Any]:
    """Require Hermes' bounded usage sidecar to attest the exact invocation."""
    try:
        usage = read_json(
            path,
            max_bytes=max_bytes,
            label="Hermes Agent usage provenance artifact",
        )
    except error_type as exc:
        raise SystemExit(
            "Hermes Agent returned an invalid usage provenance artifact"
        ) from exc
    if usage.get("completed") is not True or usage.get("failed") is not False:
        raise SystemExit(
            "Hermes Agent usage provenance did not attest a completed invocation"
        )
    provider = str(usage.get("provider") or "").strip()
    observed_model = str(usage.get("model") or "").strip()
    if provider != "openai-codex" or observed_model != expected_model:
        raise SystemExit(
            "Hermes Agent executed a different provider/model than the assigned route"
        )
    return usage


def _isolated_paths(work_dir: Path) -> dict[str, Path]:
    hermes_home = work_dir / "hermes-home"
    isolated_home = hermes_home / "home"
    paths = {
        "hermes_home": hermes_home,
        "home": isolated_home,
        "codex_home": isolated_home / ".codex",
        "xdg_config": work_dir / "xdg-config",
        "xdg_cache": work_dir / "xdg-cache",
        "xdg_data": work_dir / "xdg-data",
        "xdg_state": work_dir / "xdg-state",
        "xdg_runtime": work_dir / "xdg-runtime",
        "tmp": work_dir / "tmp",
    }
    for directory in paths.values():
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
    return paths


def _write_config(path: Path, model: str) -> None:
    path.write_text(
        "model:\n"
        f"  provider: openai-codex\n  default: {model}\n"
        "context:\n"
        "  engine: compressor\n"
        "memory:\n"
        "  memory_enabled: false\n"
        "  user_profile_enabled: false\n"
        "compression:\n"
        "  enabled: false\n"
        "terminal:\n"
        "  home_mode: profile\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def _environment(
    executable: str,
    paths: dict[str, Path],
    sanitized_env: Callable[..., dict[str, str]],
) -> dict[str, str]:
    return sanitized_env(
        executable,
        extra={
            "HOME": str(paths["home"]),
            "CODEX_HOME": str(paths["codex_home"]),
            "HERMES_HOME": str(paths["hermes_home"]),
            "HERMES_REAL_HOME": str(paths["home"]),
            "XDG_CONFIG_HOME": str(paths["xdg_config"]),
            "XDG_CACHE_HOME": str(paths["xdg_cache"]),
            "XDG_DATA_HOME": str(paths["xdg_data"]),
            "XDG_STATE_HOME": str(paths["xdg_state"]),
            "XDG_RUNTIME_DIR": str(paths["xdg_runtime"]),
            "TMPDIR": str(paths["tmp"]),
            "PYTHON_DOTENV_DISABLED": "1",
        },
    )


def _invoke_isolated(
    serialized: str,
    args: Any,
    model: str,
    executable: str,
    dedicated_auth: dict[str, Any],
    *,
    atomic_write_json: Callable[[Path, Any], None],
    run_command: Callable[..., Any],
    sanitized_env: Callable[..., dict[str, str]],
    load_dedicated_auth: Callable[[Path], dict[str, Any]],
    write_dedicated_auth: Callable[[Path, dict[str, Any]], None],
    auth_file: Path,
    process_error: type[BaseException],
    artifact_error: type[Exception],
    summarize_failure: Callable[[str, str, int], str],
    verify_usage: Callable[..., dict[str, Any]],
    extract_json: Callable[[str], dict[str, Any]],
    max_stderr_bytes: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="onion-sentinel-hermes-") as name:
        work_dir = Path(name)
        paths = _isolated_paths(work_dir)
        isolated_auth = paths["hermes_home"] / "auth.json"
        atomic_write_json(isolated_auth, dedicated_auth)
        isolated_auth.chmod(0o600)
        _write_config(paths["hermes_home"] / "config.yaml", model)
        usage_path = work_dir / "usage.json"
        command = [
            executable, "--oneshot", serialized, "--model", model,
            "--provider", "openai-codex", "--toolsets", "context_engine",
            "--safe-mode", "--usage-file", str(usage_path),
        ]
        process = None
        invocation_error: BaseException | None = None
        try:
            process = run_command(
                command,
                timeout_seconds=args.timeout,
                max_stdout_bytes=args.max_response_bytes,
                max_stderr_bytes=max_stderr_bytes,
                cwd=work_dir,
                env=_environment(executable, paths, sanitized_env),
            )
        except BaseException as exc:
            invocation_error = exc
        try:
            write_dedicated_auth(auth_file, load_dedicated_auth(isolated_auth))
        except (OSError, artifact_error) as exc:
            raise SystemExit(
                "Hermes Agent credential rotation could not be persisted to its "
                "dedicated auth store"
            ) from exc
        if isinstance(invocation_error, FileNotFoundError):
            raise SystemExit(f"Hermes Agent executable was not found: {executable}") from invocation_error
        if isinstance(invocation_error, process_error):
            raise SystemExit(f"Hermes Agent analysis failed: {invocation_error}") from invocation_error
        if invocation_error is not None:
            raise invocation_error
        if process is None:
            raise SystemExit("Hermes Agent analysis failed before execution completed")
        if process.returncode != 0:
            detail = summarize_failure("Hermes Agent", process.stderr, process.returncode)
            raise SystemExit(f"Hermes Agent analysis failed: {detail}")
        usage = verify_usage(usage_path, expected_model=model)
        return extract_json(process.stdout), usage


def _validate_assignment(
    settings: dict[str, Any],
    model: str,
    reasoning_effort: str,
    *,
    boolean_setting: Callable[[Any], bool],
    model_catalog: tuple[str, ...],
    required_effort: str,
) -> None:
    if not boolean_setting(settings.get("hermes_agent_enabled")):
        raise SystemExit("Hermes Agent is disabled in AI Analysis Model Selection")
    if (
        model != str(settings.get("hermes_agent_model") or "")
        or reasoning_effort
        != str(settings.get("hermes_agent_reasoning_effort") or "").lower()
    ):
        raise SystemExit("Hermes Agent route is not the enabled configured route")
    if model not in model_catalog:
        raise SystemExit("Hermes Agent model is not supported")
    if reasoning_effort != required_effort:
        raise SystemExit("Hermes Agent one-shot runtime supports medium reasoning effort only")


def _serialized_payload(
    prompt_package: dict[str, Any],
    args: Any,
    reasoning_effort: str,
    *,
    system_prompt_file: Path | None,
    independent_review: bool,
    build_payload: Callable[..., dict[str, Any]],
    max_prompt_bytes: int,
) -> str:
    payload = build_payload(
        prompt_package,
        args,
        hosted=True,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )
    payload["reasoning_effort"] = reasoning_effort
    serialized = json.dumps(payload, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > max_prompt_bytes:
        raise SystemExit(
            "Hermes Agent analysis request exceeds the installed CLI's safe prompt argument limit"
        )
    return serialized


def _open_auth_lock(auth_file: Path) -> Any:
    auth_parent = auth_file.parent
    if auth_parent.is_symlink():
        raise SystemExit(
            "Hermes Agent dedicated authentication directory must not be a symlink"
        )
    auth_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    auth_parent.chmod(0o700)
    auth_lock = auth_file.with_name("auth.lock")
    if auth_lock.is_symlink():
        raise SystemExit(
            "Hermes Agent dedicated authentication lock must not be a symlink"
        )
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(auth_lock, flags, 0o600)
        os.fchmod(descriptor, 0o600)
    except OSError as exc:
        raise SystemExit(
            "Hermes Agent dedicated authentication lock is unavailable"
        ) from exc
    return os.fdopen(descriptor, "a+", encoding="utf-8")


def chat(
    prompt_package: dict[str, Any],
    args: Any,
    settings: dict[str, Any],
    *,
    model: str,
    reasoning_effort: str,
    system_prompt_file: Path | None,
    independent_review: bool,
    boolean_setting: Callable[[Any], bool],
    model_catalog: tuple[str, ...],
    required_effort: str,
    resolve_executable: Callable[[dict[str, Any]], str],
    build_payload: Callable[..., dict[str, Any]],
    auth_file: Path,
    load_dedicated_auth: Callable[[Path], dict[str, Any]],
    write_dedicated_auth: Callable[[Path, dict[str, Any]], None],
    atomic_write_json: Callable[[Path, Any], None],
    run_command: Callable[..., Any],
    sanitized_env: Callable[..., dict[str, str]],
    process_error: type[BaseException],
    artifact_error: type[Exception],
    summarize_failure: Callable[[str, str, int], str],
    verify_usage: Callable[..., dict[str, Any]],
    extract_json: Callable[[str], dict[str, Any]],
    max_prompt_bytes: int,
    max_stderr_bytes: int,
    flock: Callable[[Any, int], Any],
    lock_exclusive: int,
    lock_unlock: int,
) -> dict[str, Any]:
    """Run Hermes as an isolated, tool-empty, one-shot Codex harness."""
    _validate_assignment(
        settings,
        model,
        reasoning_effort,
        boolean_setting=boolean_setting,
        model_catalog=model_catalog,
        required_effort=required_effort,
    )
    executable = resolve_executable(settings)
    serialized = _serialized_payload(
        prompt_package,
        args,
        reasoning_effort,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        build_payload=build_payload,
        max_prompt_bytes=max_prompt_bytes,
    )
    with _open_auth_lock(auth_file) as handle:
        flock(handle, lock_exclusive)
        try:
            try:
                dedicated_auth = load_dedicated_auth(auth_file)
            except artifact_error as exc:
                raise SystemExit(
                    "Hermes Agent dedicated authentication is unavailable at "
                    f"{auth_file}; provision the isolated openai-codex login "
                    "described in the runtime roadmap"
                ) from exc
            response, usage = _invoke_isolated(
                serialized,
                args,
                model,
                executable,
                dedicated_auth,
                atomic_write_json=atomic_write_json,
                run_command=run_command,
                sanitized_env=sanitized_env,
                load_dedicated_auth=load_dedicated_auth,
                write_dedicated_auth=write_dedicated_auth,
                auth_file=auth_file,
                process_error=process_error,
                artifact_error=artifact_error,
                summarize_failure=summarize_failure,
                verify_usage=verify_usage,
                extract_json=extract_json,
                max_stderr_bytes=max_stderr_bytes,
            )
        finally:
            flock(handle, lock_unlock)
    response.update({
        "_analysis_model": str(usage["model"]),
        "_analysis_model_path": "hermes-agent",
        "_analysis_provider": str(usage["provider"]),
        "_analysis_harness": "hermes-agent",
    })
    return response
