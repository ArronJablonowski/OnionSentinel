"""Isolated, credential-free OpenClaw adapter for loopback Ollama routes."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
from typing import Any, Callable


def validate_route(
    model: str,
    settings: dict[str, Any],
    *,
    model_pattern: Any,
    uses_ollama_runtime: Callable[[str], bool],
    provider_prefix: str,
    supported_urls: frozenset[str],
    default_url: str,
) -> None:
    """Admit only credential-free loopback Ollama into isolated OpenClaw."""
    if (
        not model_pattern.fullmatch(model)
        or not uses_ollama_runtime(model)
        or len(model) <= len(provider_prefix)
    ):
        raise SystemExit(
            "OpenClaw currently supports explicit ollama/<model> routes only; "
            "hosted OpenClaw credentials are not admitted into the isolated runtime"
        )
    ollama_url = str(settings.get("ollama_url") or default_url).strip().rstrip("/")
    if ollama_url not in supported_urls:
        raise SystemExit(
            "OpenClaw's isolated runtime supports only the loopback Ollama "
            "endpoint http://127.0.0.1:11434"
        )


def output_text(envelope: dict[str, Any]) -> str:
    """Extract only text outputs from OpenClaw's documented JSON envelope."""
    outputs = envelope.get("outputs")
    if isinstance(outputs, list):
        texts = [_output_item_text(item) for item in outputs if isinstance(item, dict)]
        if any(texts):
            return "\n".join(text for text in texts if text)
    for key in ("text", "output", "response"):
        if isinstance(envelope.get(key), str) and envelope[key].strip():
            return envelope[key]
    raise SystemExit("OpenClaw completed without a text model output")


def _output_item_text(item: dict[str, Any]) -> str:
    if item.get("text") is None:
        return ""
    return str(item.get("text") or "")


def verified_observation(
    envelope: dict[str, Any],
    expected_model: str,
) -> tuple[str, str]:
    """Verify and return OpenClaw's observed provider/model identity."""
    provider = str(envelope.get("provider") or "").strip()
    observed_model = str(envelope.get("model") or "").strip()
    if not provider or not observed_model:
        raise SystemExit("OpenClaw response omitted observed provider/model provenance")
    observed_name = _observed_ollama_model_name(observed_model)
    expected_provider, separator, expected_name = expected_model.partition("/")
    if (
        provider.lower() != "ollama"
        or separator != "/"
        or expected_provider.lower() != "ollama"
        or not expected_name
        or observed_name.lower() != expected_name.lower()
    ):
        raise SystemExit(
            "OpenClaw executed a different provider/model than the assigned route"
        )
    return "ollama", f"ollama/{observed_name}"


def _observed_ollama_model_name(observed_model: str) -> str:
    observed_prefix, separator, observed_name = observed_model.partition("/")
    if not separator:
        return observed_model
    if observed_prefix.lower() != "ollama":
        raise SystemExit(
            "OpenClaw executed a different provider/model than the assigned route"
        )
    return observed_name


def _isolated_paths(work_dir: Path) -> dict[str, Path]:
    home = work_dir / "home"
    state = work_dir / "state"
    paths = {
        "home": home,
        "codex_home": home / ".codex",
        "state": state,
        "oauth": state / "oauth",
        "agent": state / "agents" / "main" / "agent",
        "workspace": work_dir / "workspace",
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


def _environment(
    executable: str,
    paths: dict[str, Path],
    config_path: Path,
    sanitized_env: Callable[..., dict[str, str]],
) -> dict[str, str]:
    return sanitized_env(
        executable,
        extra={
            "HOME": str(paths["home"]),
            "CODEX_HOME": str(paths["codex_home"]),
            "OPENCLAW_HOME": str(paths["home"]),
            "OPENCLAW_STATE_DIR": str(paths["state"]),
            "OPENCLAW_CONFIG_PATH": str(config_path),
            "OPENCLAW_OAUTH_DIR": str(paths["oauth"]),
            "OPENCLAW_AGENT_DIR": str(paths["agent"]),
            "OPENCLAW_WORKSPACE_DIR": str(paths["workspace"]),
            "XDG_CONFIG_HOME": str(paths["xdg_config"]),
            "XDG_CACHE_HOME": str(paths["xdg_cache"]),
            "XDG_DATA_HOME": str(paths["xdg_data"]),
            "XDG_STATE_HOME": str(paths["xdg_state"]),
            "XDG_RUNTIME_DIR": str(paths["xdg_runtime"]),
            "TMPDIR": str(paths["tmp"]),
            "OPENCLAW_OFFLINE": "1",
            "OLLAMA_API_KEY": "ollama-local",
            "HTTP_PROXY": "",
            "HTTPS_PROXY": "",
            "http_proxy": "",
            "https_proxy": "",
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "no_proxy": "127.0.0.1,localhost,::1",
        },
    )


def _run_isolated_inference(
    executable: str, model: str, reasoning_effort: str, serialized: str,
    args: Any, atomic_write_json: Callable[[Path, Any], None],
    run_command: Callable[..., Any], sanitized_env: Callable[..., dict[str, str]],
    process_error: type[BaseException], max_stderr_bytes: int,
) -> Any:
    with tempfile.TemporaryDirectory(prefix="onion-sentinel-openclaw-") as name:
        work_dir = Path(name)
        paths = _isolated_paths(work_dir)
        config_path = paths["state"] / "openclaw.json"
        atomic_write_json(config_path, {})
        config_path.chmod(0o600)
        command = [
            executable, "infer", "model", "run", "--local", "--model", model,
            "--thinking", reasoning_effort, "--prompt", serialized, "--json",
        ]
        try:
            return run_command(
                command,
                timeout_seconds=args.timeout,
                max_stdout_bytes=args.max_response_bytes,
                max_stderr_bytes=max_stderr_bytes,
                cwd=work_dir,
                env=_environment(executable, paths, config_path, sanitized_env),
            )
        except FileNotFoundError as exc:
            raise SystemExit(f"OpenClaw executable was not found: {executable}") from exc
        except process_error as exc:
            raise SystemExit(f"OpenClaw analysis failed: {exc}") from exc


def _decode_inference_response(
    process: Any, model: str, summarize_failure: Callable[[str, str, int], str],
    extract_json: Callable[[str], dict[str, Any]],
) -> dict[str, Any]:
    if process.returncode != 0:
        detail = summarize_failure("OpenClaw", process.stderr, process.returncode)
        raise SystemExit(f"OpenClaw analysis failed: {detail}")
    try:
        envelope = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit("OpenClaw returned an invalid JSON execution envelope") from exc
    if not isinstance(envelope, dict) or envelope.get("ok") is not True:
        raise SystemExit("OpenClaw reported an unsuccessful model invocation")
    provider, observed_model = verified_observation(envelope, model)
    response = extract_json(output_text(envelope))
    response.update({
        "_analysis_model": observed_model,
        "_analysis_model_path": "openclaw",
        "_analysis_provider": provider,
        "_analysis_harness": "openclaw",
    })
    return response


def infer_unlocked(
    prompt_package: dict[str, Any],
    args: Any,
    settings: dict[str, Any],
    *,
    model: str,
    reasoning_effort: str,
    system_prompt_file: Path | None,
    independent_review: bool,
    validate: Callable[[str, dict[str, Any]], None],
    resolve_executable: Callable[[dict[str, Any]], str],
    build_payload: Callable[..., dict[str, Any]],
    atomic_write_json: Callable[[Path, Any], None],
    run_command: Callable[..., Any],
    sanitized_env: Callable[..., dict[str, str]],
    process_error: type[BaseException],
    summarize_failure: Callable[[str, str, int], str],
    extract_json: Callable[[str], dict[str, Any]],
    max_prompt_bytes: int,
    max_stderr_bytes: int,
) -> dict[str, Any]:
    """Run one stateless, fixed-argv OpenClaw inference."""
    validate(model, settings)
    executable = resolve_executable(settings)
    payload = build_payload(
        prompt_package,
        args,
        hosted=True,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )
    serialized = json.dumps(payload, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > max_prompt_bytes:
        raise SystemExit(
            "OpenClaw analysis request exceeds the installed CLI's safe prompt argument limit"
        )
    process = _run_isolated_inference(
        executable, model, reasoning_effort, serialized, args, atomic_write_json,
        run_command, sanitized_env, process_error, max_stderr_bytes,
    )
    return _decode_inference_response(process, model, summarize_failure, extract_json)


def locked_chat(
    prompt_package: dict[str, Any],
    args: Any,
    settings: dict[str, Any],
    *,
    model: str,
    reasoning_effort: str,
    system_prompt_file: Path | None,
    independent_review: bool,
    boolean_setting: Callable[[Any], bool],
    model_pattern: Any,
    reasoning_efforts: frozenset[str],
    validate: Callable[[str, dict[str, Any]], None],
    lock_path: Path,
    flock: Callable[[Any, int], Any],
    lock_exclusive: int,
    lock_unlock: int,
    infer: Callable[..., dict[str, Any]],
    unload: Callable[..., None],
) -> dict[str, Any]:
    """Validate assignment, serialize local inference, and always unload."""
    if not boolean_setting(settings.get("openclaw_enabled")):
        raise SystemExit("OpenClaw is disabled in AI Analysis Model Selection")
    if (
        model != str(settings.get("openclaw_model") or "")
        or reasoning_effort
        != str(settings.get("openclaw_reasoning_effort") or "").lower()
    ):
        raise SystemExit("OpenClaw route is not the enabled configured route")
    if not model_pattern.fullmatch(model):
        raise SystemExit("OpenClaw model is invalid")
    if reasoning_effort not in reasoning_efforts:
        raise SystemExit("OpenClaw reasoning effort is invalid")
    validate(model, settings)
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with lock_path.open("a+", encoding="utf-8") as handle:
        lock_path.chmod(0o600)
        flock(handle, lock_exclusive)
        try:
            return infer(
                prompt_package,
                args,
                settings,
                model=model,
                reasoning_effort=reasoning_effort,
                system_prompt_file=system_prompt_file,
                independent_review=independent_review,
            )
        finally:
            try:
                unload(
                    settings,
                    model.split("/", 1)[1],
                    timeout=float(getattr(args, "timeout", 30) or 30),
                )
            finally:
                flock(handle, lock_unlock)
