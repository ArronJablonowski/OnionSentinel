"""Ollama discovery and compatibility catalog for SOC model settings."""
from __future__ import annotations

import concurrent.futures
import json
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from urllib import request as urllib_request


OLLAMA_LIST_COMMANDS = (
    ("/opt/homebrew/bin/ollama", "ls"),
    ("/usr/local/bin/ollama", "ls"),
    ("ollama", "ls"),
)


@dataclass(frozen=True)
class OllamaMetadataSources:
    cache_get_or_compute: Callable[[object, Callable[[], dict]], dict]
    open_url: Callable
    read_json: Callable[..., object]
    max_bytes: int
    min_context_tokens: int


@dataclass(frozen=True)
class OllamaCatalogSources:
    read_settings: Callable[[], dict]
    default_settings: Callable[[], dict]
    list_models: Callable[[], list[str]]
    normalize_models: Callable[[object], list[str]]
    compatibility: Callable[[str, str], dict]
    clear_cache: Callable[[], None]
    max_workers: int = 6


def list_ollama_models(
    *,
    run: Callable[..., object],
    env: dict,
    commands: Sequence[Sequence[str]] = OLLAMA_LIST_COMMANDS,
) -> list[str]:
    """Return deduplicated installed model names from the first working CLI."""
    output = ""
    for command in commands:
        try:
            proc = run(
                list(command),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                env=env,
            )
        except Exception:
            continue
        if proc.returncode == 0 and proc.stdout.strip():
            output = proc.stdout
            break
    models = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("name"):
            continue
        name = stripped.split()[0].strip()
        if name and name not in models:
            models.append(name)
    return models


def ollama_context_length(model_info: object) -> int:
    """Return the largest valid declared context window."""
    if not isinstance(model_info, dict):
        return 0
    lengths = []
    for key, value in model_info.items():
        if not str(key).endswith(".context_length"):
            continue
        try:
            lengths.append(max(0, int(value)))
        except (TypeError, ValueError, OverflowError):
            continue
    return max(lengths, default=0)


def classify_ollama_model_compatibility(
    model: str,
    metadata: object,
    *,
    min_context_tokens: int,
) -> dict:
    """Assess only capabilities required by the bounded SOC exchange."""
    del model  # Retained for stable diagnostics/caller compatibility.
    if not isinstance(metadata, dict):
        return {
            "compatible": False,
            "status": "unverified",
            "reasons": [
                "Ollama did not return capability metadata for this model."
            ],
            "capabilities": [],
            "context_length": 0,
        }
    capabilities = (
        sorted({
            str(item).strip().lower()
            for item in metadata.get("capabilities", [])
            if str(item).strip()
        })
        if isinstance(metadata.get("capabilities"), list)
        else []
    )
    context_length = ollama_context_length(metadata.get("model_info"))
    reasons = _ollama_incompatibility_reasons(
        capabilities,
        str(metadata.get("template") or "").strip(),
        context_length,
        min_context_tokens,
    )
    return {
        "compatible": not reasons,
        "status": "compatible" if not reasons else "incompatible",
        "reasons": reasons,
        "capabilities": capabilities,
        "context_length": context_length,
    }


def _ollama_incompatibility_reasons(
    capabilities: list[str],
    template: str,
    context_length: int,
    min_context_tokens: int,
) -> list[str]:
    reasons = []
    if "completion" not in capabilities:
        if "image" in capabilities:
            reasons.append(
                "Image-generation only: this model cannot return the text and "
                "JSON analysis required by Onion Sentinel."
            )
        elif "embedding" in capabilities:
            reasons.append(
                "Embedding-only: this model cannot generate the text and JSON "
                "analysis required by Onion Sentinel."
            )
        else:
            reasons.append(
                "No text-completion capability was reported, so the model "
                "cannot produce an Onion Sentinel analysis."
            )
    if not template:
        reasons.append(
            "No chat template was reported, so the model cannot accept the "
            "system and analyst messages used by Onion Sentinel."
        )
    if context_length and context_length < min_context_tokens:
        reasons.append(
            f"The {context_length:,}-token context window is below Onion "
            f"Sentinel's {min_context_tokens:,}-token operational minimum."
        )
    return reasons


def load_ollama_model_compatibility(
    sources: OllamaMetadataSources,
    model: str,
    ollama_url: str,
) -> dict:
    """Read bounded model metadata through a cache keyed by URL and model."""
    cache_key = (ollama_url.rstrip("/"), model)

    def compute() -> dict:
        request = urllib_request.Request(
            cache_key[0] + "/api/show",
            data=json.dumps({"model": model}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with sources.open_url(request, timeout=4) as response:
                metadata = sources.read_json(
                    response, max_bytes=sources.max_bytes
                )
        except Exception:
            metadata = None
        return classify_ollama_model_compatibility(
            model,
            metadata,
            min_context_tokens=sources.min_context_tokens,
        )

    return sources.cache_get_or_compute(cache_key, compute)


def _unavailable_model() -> dict:
    return {
        "compatible": False,
        "status": "unavailable",
        "reasons": [
            "This model is configured but is not installed locally, so Onion "
            "Sentinel cannot run it."
        ],
        "capabilities": [],
        "context_length": 0,
    }


def compose_ollama_models_response(
    sources: OllamaCatalogSources,
    *,
    force_refresh: bool = False,
) -> dict:
    settings = (
        sources.read_settings().get("settings")
        or sources.default_settings()
    )
    installed_models = sources.list_models()
    enabled_models = sources.normalize_models(
        settings.get("enabled_ollama_models")
    )
    models = list(installed_models)
    models.extend(model for model in enabled_models if model not in models)
    if force_refresh:
        sources.clear_cache()
    ollama_url = str(
        settings.get("ollama_url") or "http://127.0.0.1:11434"
    ).rstrip("/")
    installed_set = set(installed_models)

    def assess(model: str) -> tuple[str, dict]:
        if model not in installed_set:
            return model, _unavailable_model()
        return model, sources.compatibility(model, ollama_url)

    compatibility = {}
    if models:
        workers = min(max(1, sources.max_workers), len(models))
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=workers
        ) as executor:
            for model, assessment in executor.map(assess, models):
                compatibility[model] = assessment
    selected = (
        enabled_models[0]
        if enabled_models
        else str(settings.get("ollama_model") or "").strip()
    )
    return {
        "ok": True,
        "models": models,
        "installed_models": installed_models,
        "enabled_models": enabled_models,
        "compatibility": compatibility,
        "selected": selected,
        "command": "ollama ls",
    }
