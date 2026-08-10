"""Late-bound Settings, prompt, model-routing, and catalog orchestration."""
from __future__ import annotations

from typing import Any


def read_prompt_file(runtime: Any, path: Any, label: str) -> dict:
    return runtime.read_agent_prompt_file(path, label)


def read_soc_analyst_prompt(runtime: Any) -> dict:
    return runtime.read_prompt_file(runtime.SOC_ANALYST_PROMPT_FILE, "SOC Analyst")


def read_siem_engineer_prompt(runtime: Any) -> dict:
    return runtime.read_prompt_file(runtime.SIEM_ENGINEER_PROMPT_FILE, "SIEM Engineer")


def read_threat_hunter_prompt(runtime: Any) -> dict:
    return runtime.read_prompt_file(runtime.THREAT_HUNTER_PROMPT_FILE, "Threat Hunter")


def read_cyber_threat_intel_prompt(runtime: Any) -> dict:
    return runtime.read_prompt_file(
        runtime.CYBER_THREAT_INTEL_PROMPT_FILE, "Cyber Threat Intel"
    )


def read_incident_responder_prompt(runtime: Any) -> dict:
    return runtime.read_prompt_file(
        runtime.INCIDENT_RESPONDER_PROMPT_FILE, "Incident Responder"
    )


def read_settings_prompt(runtime: Any, api_path: str) -> dict:
    return runtime.read_allowlisted_prompt(api_path, runtime.SOC_SETTINGS_PROMPT_FILES)


def agent_memory_files(runtime: Any) -> dict[str, tuple[str, Any]]:
    return {
        "soc-analyst": ("SOC Analyst Memory", runtime.SOC_ANALYST_MEMORY_FILE),
        "incident-responder": (
            "Incident Responder Memory", runtime.INCIDENT_RESPONDER_MEMORY_FILE,
        ),
        "siem-engineer": ("SIEM Engineer Memory", runtime.SIEM_ENGINEER_MEMORY_FILE),
        "cyber-threat-intel": (
            "Cyber Threat Intel Memory", runtime.CYBER_THREAT_INTEL_MEMORY_FILE,
        ),
        "threat-hunter": ("Threat Hunter Memory", runtime.THREAT_HUNTER_MEMORY_FILE),
        "shared": ("Shared Agent Memory", runtime.SHARED_AGENT_MEMORY_FILE),
    }


def read_agent_memory(runtime: Any, memory_key: object) -> tuple[int, dict]:
    return runtime.read_allowlisted_agent_memory(
        runtime.AgentMemorySources(
            directory=runtime.AGENT_MEMORY_DIR,
            files=runtime.agent_memory_files(),
            max_bytes=runtime.AGENT_MEMORY_VIEW_MAX_BYTES,
        ),
        memory_key,
    )


def save_prompt_file(
    runtime: Any, prompt: object, path: Any, label: str
) -> tuple[bool, dict]:
    return runtime.save_agent_prompt_file(
        prompt, path, label, max_bytes=runtime.SOC_ANALYST_PROMPT_MAX_BYTES
    )


def save_soc_analyst_prompt(runtime: Any, prompt: object) -> tuple[bool, dict]:
    return runtime.save_prompt_file(
        prompt, runtime.SOC_ANALYST_PROMPT_FILE, "SOC Analyst"
    )


def save_siem_engineer_prompt(runtime: Any, prompt: object) -> tuple[bool, dict]:
    return runtime.save_prompt_file(
        prompt, runtime.SIEM_ENGINEER_PROMPT_FILE, "SIEM Engineer"
    )


def save_threat_hunter_prompt(runtime: Any, prompt: object) -> tuple[bool, dict]:
    return runtime.save_prompt_file(
        prompt, runtime.THREAT_HUNTER_PROMPT_FILE, "Threat Hunter"
    )


def save_cyber_threat_intel_prompt(
    runtime: Any, prompt: object
) -> tuple[bool, dict]:
    return runtime.save_prompt_file(
        prompt, runtime.CYBER_THREAT_INTEL_PROMPT_FILE, "Cyber Threat Intel"
    )


def save_incident_responder_prompt(
    runtime: Any, prompt: object
) -> tuple[bool, dict]:
    return runtime.save_prompt_file(
        prompt, runtime.INCIDENT_RESPONDER_PROMPT_FILE, "Incident Responder"
    )


def save_settings_prompt(
    runtime: Any, api_path: str, prompt: object
) -> tuple[bool, dict]:
    return runtime.save_allowlisted_prompt(
        api_path,
        prompt,
        runtime.SOC_SETTINGS_PROMPT_FILES,
        max_bytes=runtime.SOC_ANALYST_PROMPT_MAX_BYTES,
    )


def normalize_soc_ai_settings(
    runtime: Any, payload: dict | None
) -> tuple[bool, dict]:
    policy = runtime.SocAiSettingsNormalizationPolicy(
        defaults=runtime.default_soc_ai_settings,
        maxmind_databases=runtime.MAXMIND_GEOIP_DATABASE_SETTINGS,
        codex_efforts=runtime.CODEX_CLI_REASONING_EFFORTS,
        hermes_effort=runtime.HERMES_AGENT_REASONING_EFFORT,
        codex_catalog=runtime.CODEX_CLI_MODEL_CATALOG,
        severity_thresholds=runtime.SOC_ANALYSIS_SEVERITY_THRESHOLDS,
        openclaw_ollama_urls=runtime.OPENCLAW_SUPPORTED_OLLAMA_URLS,
        normalized_model_list=runtime._normalized_model_list,
        boolean_setting=runtime._boolean_setting,
        derive_model_mode=runtime._derive_model_mode,
        valid_cli_path=runtime._valid_cli_executable_path,
        valid_provider_model=runtime._valid_provider_model,
        valid_openclaw_model=runtime._valid_openclaw_model,
        normalize_codex_models=runtime._normalize_codex_cli_models,
        enabled_routes=runtime._enabled_agent_model_routes,
        normalize_primary_models=runtime._normalize_agent_models,
        normalize_reviewer_models=runtime._normalize_agent_second_opinion_models,
        normalize_adjudicator_models=runtime._normalize_agent_adjudicator_models,
    )
    return runtime.normalize_ai_settings(payload, policy)


def maxmind_geoip_database_status(
    runtime: Any, settings: dict, database_type: str = "city"
) -> dict:
    if database_type not in runtime.MAXMIND_GEOIP_DATABASE_SETTINGS:
        raise ValueError(f"Unsupported MaxMind database type: {database_type}")
    setting_key, default_path = runtime.MAXMIND_GEOIP_DATABASE_SETTINGS[database_type]
    configured = str(settings.get(setting_key) or "").strip()
    if database_type == "city" and not configured:
        configured = str(settings.get("maxmind_geoip_db_path") or "").strip()
    configured = configured or default_path
    path = runtime.Path(configured).expanduser()
    status = {
        "database_type": database_type,
        "setting_key": setting_key,
        "state": "missing",
        "configured_path": configured,
        "filename": path.name,
    }
    try:
        stat = path.stat()
    except FileNotFoundError:
        return status
    except OSError:
        status["state"] = "unreadable"
        return status
    if not path.is_file() or not runtime.os.access(path, runtime.os.R_OK):
        status["state"] = "unreadable"
        return status
    status.update({
        "state": "ready",
        "size_bytes": stat.st_size,
        "modified_at": runtime.dt.datetime.fromtimestamp(stat.st_mtime)
        .astimezone()
        .isoformat()
        .replace("T", "  "),
    })
    return status


def maxmind_geoip_databases_status(runtime: Any, settings: dict) -> dict:
    return {
        database_type: runtime.maxmind_geoip_database_status(settings, database_type)
        for database_type in runtime.MAXMIND_GEOIP_DATABASE_SETTINGS
    }


def enabled_model_routes_for_settings(runtime: Any, settings: dict) -> list[str]:
    return runtime._enabled_agent_model_routes(
        settings["enabled_ollama_models"],
        settings["codex_cli_models"],
        hermes_agent_enabled=settings["hermes_agent_enabled"],
        hermes_agent_model=settings["hermes_agent_model"],
        hermes_agent_reasoning_effort=settings["hermes_agent_reasoning_effort"],
        openclaw_enabled=settings["openclaw_enabled"],
        openclaw_model=settings["openclaw_model"],
        openclaw_reasoning_effort=settings["openclaw_reasoning_effort"],
    )


def soc_ai_settings_store_sources(runtime: Any):
    return runtime.AiSettingsStoreSources(
        path=runtime.SOC_AI_SETTINGS_FILE,
        lock=runtime.SOC_AI_SETTINGS_LOCK,
        normalize=runtime.normalize_soc_ai_settings,
        readiness=runtime._enabled_cli_harnesses_ready,
        enabled_routes=runtime._enabled_model_routes_for_settings,
        route_identity=runtime._model_route_identity,
        geoip_databases=runtime.maxmind_geoip_databases_status,
        geoip_city=lambda settings: runtime.maxmind_geoip_database_status(
            settings, "city"
        ),
        roles=runtime.CYBER_SECURITY_AGENT_ROLES,
    )


def read_soc_ai_settings(runtime: Any) -> dict:
    return runtime.read_persisted_soc_ai_settings(
        runtime.soc_ai_settings_store_sources()
    )


def list_ollama_models(runtime: Any) -> list[str]:
    return runtime.discover_ollama_models(
        run=runtime.subprocess.run, env=runtime.ADMIN_COMMAND_ENV
    )


def ollama_context_length(runtime: Any, model_info: object) -> int:
    return runtime.ollama_context_length(model_info)


def classify_ollama_model_compatibility(
    runtime: Any, model: str, metadata: object
) -> dict:
    return runtime.classify_ollama_compatibility(
        model, metadata, min_context_tokens=runtime.OLLAMA_MODEL_MIN_CONTEXT_TOKENS
    )


def ollama_model_compatibility(
    runtime: Any, model: str, ollama_url: str
) -> dict:
    return runtime.load_ollama_model_compatibility(
        runtime.OllamaMetadataSources(
            cache_get_or_compute=runtime.OLLAMA_MODEL_COMPATIBILITY_CACHE.get_or_compute,
            open_url=runtime.urllib_request.urlopen,
            read_json=runtime.read_bounded_json,
            max_bytes=runtime.OLLAMA_MODEL_SHOW_MAX_BYTES,
            min_context_tokens=runtime.OLLAMA_MODEL_MIN_CONTEXT_TOKENS,
        ),
        model,
        ollama_url,
    )


def ollama_catalog_sources(runtime: Any):
    return runtime.OllamaCatalogSources(
        read_settings=runtime.read_soc_ai_settings,
        default_settings=runtime.default_soc_ai_settings,
        list_models=runtime.list_ollama_models,
        normalize_models=runtime._normalized_model_list,
        compatibility=runtime.ollama_model_compatibility,
        clear_cache=runtime.OLLAMA_MODEL_COMPATIBILITY_CACHE.clear,
    )


def ollama_models_response(runtime: Any, force_refresh: bool = False) -> dict:
    return runtime.compose_ollama_models_response(
        runtime.ollama_catalog_sources(), force_refresh=force_refresh
    )


def write_soc_ai_settings(
    runtime: Any, normalized: dict
) -> tuple[bool, dict]:
    return runtime.write_persisted_soc_ai_settings(
        runtime.soc_ai_settings_store_sources(), normalized
    )


def resolve_cli_harness_for_settings(
    runtime: Any, configured: object, basename: str
):
    return runtime.resolve_cli_harness(
        configured, basename, home=runtime.HOME, discover=runtime.shutil.which
    )


def hermes_auth_readiness_error(runtime: Any) -> str:
    return runtime.hermes_auth_readiness_error(
        runtime.DEFAULT_HERMES_AUTH_FILE, runtime.HERMES_AUTH_MAX_BYTES
    )


def enabled_cli_harnesses_ready(
    runtime: Any, settings: dict
) -> tuple[bool, str]:
    return runtime.enabled_cli_harnesses_ready(
        settings,
        boolean_setting=runtime._boolean_setting,
        resolve=runtime._resolve_cli_harness_for_settings,
        hermes_auth_error=runtime._hermes_auth_readiness_error,
    )


def save_soc_ai_settings(runtime: Any, payload: object) -> tuple[bool, dict]:
    return runtime.save_persisted_soc_ai_settings(
        runtime.soc_ai_settings_store_sources(), payload
    )


def save_soc_agent_model(runtime: Any, payload: object) -> tuple[bool, dict]:
    return runtime.save_persisted_soc_agent_model(
        runtime.soc_ai_settings_store_sources(), payload
    )
