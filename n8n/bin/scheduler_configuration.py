"""Scheduler CLI defaults, queue SQL, and model-routing policy."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping


RuntimeNamespace = Mapping[str, Any]


def alert_time_sql(alias: str = "") -> str:
    """Return the newest usable alert timestamp expression."""
    prefix = f"{alias}." if alias else ""
    return (
        f"COALESCE(NULLIF({prefix}last_seen, ''), "
        f"NULLIF({prefix}timestamp, ''), NULLIF({prefix}first_seen, ''))"
    )


def alert_group_key_sql() -> str:
    """Return SQL for the same duplicate-group key used by the dashboard."""
    return (
        "COALESCE(NULLIF(suppression_key, ''), "
        "COALESCE(triage_level, '') || '|' || "
        "COALESCE(rule_name, '') || '|' || "
        "COALESCE(source_ip, '') || '|' || "
        "COALESCE(destination_ip, '') || '|' || "
        "COALESCE(NULLIF(filter_status, ''), 'accepted'))"
    )


def severity_priority_sql(
    levels: tuple[str, ...],
    column: str = "triage_level",
) -> str:
    """Return SQL that drains each severity bucket before moving lower."""
    cases = "\n            ".join(
        f"WHEN '{level}' THEN {index}"
        for index, level in enumerate(levels, start=1)
    )
    return (
        f"CASE {column}\n            {cases}\n            "
        f"ELSE {len(levels) + 1}\n          END"
    )


def build_cli_defaults(runtime: RuntimeNamespace) -> Any:
    return runtime["SchedulerCliDefaults"](
        db=runtime["DEFAULT_DB"],
        harness_db=runtime["DEFAULT_HARNESS_DB"],
        prompt_dir=runtime["DEFAULT_PROMPT_DIR"],
        analysis_dir=runtime["DEFAULT_ANALYSIS_DIR"],
        pcap_analysis_dir=runtime["DEFAULT_PCAP_ANALYSIS_DIR"],
        rollup_dir=runtime["DEFAULT_ROLLUP_DIR"],
        agent_memory_dir=runtime["DEFAULT_AGENT_MEMORY_DIR"],
        shared_memory_file=runtime["DEFAULT_SHARED_MEMORY_FILE"],
        asset_inventory_file=runtime["DEFAULT_ASSET_INVENTORY_FILE"],
        incident_evidence_dir=runtime["DEFAULT_INCIDENT_EVIDENCE_DIR"],
        incident_evidence_config=runtime["DEFAULT_INCIDENT_EVIDENCE_CONFIG"],
        investigation_pivot_dir=runtime["DEFAULT_INVESTIGATION_PIVOT_DIR"],
        live_osquery_config=runtime["DEFAULT_LIVE_OSQUERY_CONFIG"],
        disagreement_adjudicator_prompt=runtime[
            "DEFAULT_DISAGREEMENT_ADJUDICATOR_PROMPT"
        ],
        ai_settings=runtime["DEFAULT_AI_SETTINGS"],
        investigation_harness_policy=runtime[
            "DEFAULT_INVESTIGATION_HARNESS_POLICY"
        ],
        detection_playbooks=runtime["DEFAULT_DETECTION_PLAYBOOKS"],
        investigation_skills=runtime["DEFAULT_INVESTIGATION_SKILLS"],
        lock=runtime["DEFAULT_LOCK"],
        drain=runtime["DEFAULT_DRAIN"],
        wake=runtime["DEFAULT_WAKE"],
        levels=runtime["DEFAULT_LEVELS"],
        model=runtime["DEFAULT_MODEL"],
        max_prompt_bytes=runtime["DEFAULT_MAX_PROMPT_BYTES"],
        portal_wake=runtime["DEFAULT_DASHBOARD_WAKE"],
        alert_store_url=runtime["os"].environ.get(
            "ALERT_STORE_URL",
            "http://127.0.0.1:8787",
        ),
    )


def parse_args(runtime: RuntimeNamespace) -> Any:
    return runtime["parse_scheduler_args"](
        build_cli_defaults(runtime),
        runtime["SchedulerCliPolicy"](
            controlled_alert_id=runtime["CONTROLLED_ALERT_ID_RE"],
            controlled_dispatch_id=runtime["CONTROLLED_DISPATCH_ID_RE"],
            stable_group_key_valid=runtime[
                "valid_controlled_stable_group_key"
            ],
            stable_group_key_max_bytes=runtime[
                "CONTROLLED_STABLE_GROUP_KEY_MAX_LENGTH"
            ],
        ),
    )


def build_settings_policy(runtime: RuntimeNamespace) -> Any:
    return runtime["SchedulerSettingsPolicy"](
        max_bytes=runtime["MAX_AI_SETTINGS_BYTES"],
        agent_roles=runtime["AGENT_ROLES"],
        codex_models=runtime["CODEX_CLI_MODEL_CATALOG"],
        codex_efforts=runtime["CODEX_CLI_REASONING_EFFORTS"],
    )


def cli_agent_roles(runtime: RuntimeNamespace, settings_path: Path) -> set[str]:
    return runtime["discover_cli_agent_roles"](
        settings_path,
        build_settings_policy(runtime),
    )


def role_uses_codex_cli(
    runtime: RuntimeNamespace,
    args: Any,
    *,
    agent_role: str = "",
) -> bool:
    role = str(agent_role or "").strip()
    settings_path = Path(
        getattr(args, "ai_settings_file", runtime["DEFAULT_AI_SETTINGS"])
    )
    return runtime["role_uses_codex_cli"](
        settings_path,
        build_settings_policy(runtime),
        role,
    )


def effective_prompt_package_limit(
    runtime: RuntimeNamespace,
    args: Any,
    *,
    agent_role: str = "",
    initial: bool = False,
) -> int:
    configured = int(
        getattr(args, "max_prompt_bytes", runtime["DEFAULT_MAX_PROMPT_BYTES"])
        or runtime["DEFAULT_MAX_PROMPT_BYTES"]
    )
    if role_uses_codex_cli(runtime, args, agent_role=agent_role):
        ceiling = (
            runtime["CODEX_CLI_INITIAL_PROMPT_PACKAGE_BYTES"]
            if initial
            else runtime["CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES"]
        )
        return min(configured, ceiling)
    return configured


def configured_analysis_levels(
    runtime: RuntimeNamespace,
    settings_path: Path,
    configured_levels: str,
) -> list[str]:
    return runtime["apply_analysis_level_floor"](
        settings_path,
        build_settings_policy(runtime),
        configured_levels,
        runtime["SEVERITY_PRIORITY"],
    )


def configured_incident_levels(
    runtime: RuntimeNamespace,
    settings_path: Path,
) -> list[str]:
    return runtime["apply_incident_level_floor"](
        settings_path,
        build_settings_policy(runtime),
        runtime["SEVERITY_PRIORITY"],
    )


def provider_lane_sql(runtime: RuntimeNamespace, args: Any) -> tuple[str, list[object]]:
    provider_lane = str(getattr(args, "provider_lane", "any") or "any")
    cli_roles = sorted(
        cli_agent_roles(
            runtime,
            Path(
                getattr(
                    args,
                    "ai_settings_file",
                    runtime["DEFAULT_AI_SETTINGS"],
                )
            ),
        )
    )
    return runtime["provider_lane_predicate"](provider_lane, cli_roles)
