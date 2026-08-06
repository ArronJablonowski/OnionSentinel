"""Exact provider dispatch with no implicit fallback."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable


def attest_response(
    settings: dict[str, Any],
    route: str,
    response: dict[str, Any],
    *,
    route_metadata: Callable[
        [dict[str, Any], str], tuple[str, str, str, str]
    ],
) -> dict[str, Any]:
    """Bind collector-observed adapter identity to one configured route."""
    canonical, expected_model, expected_path, expected_provider = route_metadata(
        settings, route
    )
    observed = {
        "model": str(response.get("_analysis_model") or ""),
        "model_path": str(response.get("_analysis_model_path") or ""),
        "provider": str(response.get("_analysis_provider") or ""),
    }
    expected = {
        "model": expected_model,
        "model_path": expected_path,
        "provider": expected_provider,
    }
    mismatches = [
        key for key in expected if not expected[key] or observed[key] != expected[key]
    ]
    if mismatches:
        raise SystemExit(
            "Model adapter identity does not match the configured route: "
            + ", ".join(mismatches)
        )
    response["_analysis_model_route"] = canonical
    return response


def dispatch(
    route: str,
    prompt_package: dict[str, Any],
    args: Any,
    settings: dict[str, Any],
    *,
    system_prompt_file: Path | None,
    independent_review: bool,
    enabled_routes: Callable[[dict[str, Any]], list[str]],
    canonicalize: Callable[[str, list[str]], str],
    is_hosted: Callable[[str, dict[str, Any]], bool],
    synchronize_hosted: Callable[[dict[str, Any]], None],
    parse_codex: Callable[[str], tuple[str, str] | None],
    parse_harness: Callable[[str, str], tuple[str, str] | None],
    codex_adapter: Callable[..., dict[str, Any]],
    hermes_adapter: Callable[..., dict[str, Any]],
    openclaw_adapter: Callable[..., dict[str, Any]],
    ollama_adapter: Callable[..., dict[str, Any]],
    attest: Callable[[dict[str, Any], str, dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """Invoke exactly one enabled adapter or fail closed."""
    admitted = enabled_routes(settings)
    if route in {"gpt-cli", "codex-cli"}:
        route = canonicalize(route, admitted)
    if route not in admitted:
        raise SystemExit(
            f"Configured analysis model route is not enabled: {route or 'none'}"
        )
    if is_hosted(route, settings):
        synchronize_hosted(prompt_package)
    common = {
        "system_prompt_file": system_prompt_file,
        "independent_review": independent_review,
    }
    if route in {"gpt-cli", "codex-cli"}:
        response = codex_adapter(prompt_package, args, settings, **common)
    elif route.startswith("codex-cli:"):
        parsed = parse_codex(route)
        if not parsed:
            raise SystemExit("Configured Codex CLI route is invalid")
        response = codex_adapter(
            prompt_package,
            args,
            settings,
            model=parsed[0],
            reasoning_effort=parsed[1],
            **common,
        )
    elif route.startswith("hermes-agent:"):
        parsed = parse_harness(route, "hermes-agent")
        if not parsed:
            raise SystemExit("Configured Hermes Agent route is invalid")
        response = hermes_adapter(
            prompt_package,
            args,
            settings,
            model=parsed[0],
            reasoning_effort=parsed[1],
            **common,
        )
    elif route.startswith("openclaw:"):
        parsed = parse_harness(route, "openclaw")
        if not parsed:
            raise SystemExit("Configured OpenClaw route is invalid")
        response = openclaw_adapter(
            prompt_package,
            args,
            settings,
            model=parsed[0],
            reasoning_effort=parsed[1],
            **common,
        )
    elif route.startswith("ollama:"):
        model = route.removeprefix("ollama:").strip()
        if not model:
            raise SystemExit("Configured Ollama route has an empty model name")
        response = ollama_adapter(
            prompt_package,
            args,
            settings,
            model,
            **common,
        )
    else:
        raise SystemExit(
            f"Unsupported or disabled analysis model route: {route or 'none'}"
        )
    return attest(settings, route, response)
