#!/usr/bin/env python3
"""Build and invoke one bounded scheduler analysis child."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Callable, Mapping


CONTROLLED_RESULT_ENVIRONMENT = {
    "job_id": "ONION_SENTINEL_EVALUATION_JOB_ID",
    "job_type": "ONION_SENTINEL_EVALUATION_JOB_TYPE",
    "lease_token": "ONION_SENTINEL_EVALUATION_LEASE_TOKEN",
    "cohort_id": "ONION_SENTINEL_EVALUATION_COHORT_ID",
    "dispatch_id": "ONION_SENTINEL_EVALUATION_DISPATCH_ID",
    "representative_alert_id": (
        "ONION_SENTINEL_EVALUATION_REPRESENTATIVE_ALERT_ID"
    ),
    "stable_group_id": "ONION_SENTINEL_EVALUATION_STABLE_GROUP_ID",
    "stable_group_key": "ONION_SENTINEL_EVALUATION_STABLE_GROUP_KEY",
    "agent_role": "ONION_SENTINEL_EVALUATION_AGENT_ROLE",
    "reanalysis_attempt_id": (
        "ONION_SENTINEL_EVALUATION_REANALYSIS_ATTEMPT_ID"
    ),
    "release_id": "ONION_SENTINEL_EVALUATION_RELEASE_ID",
    "expected_assigned_route": (
        "ONION_SENTINEL_EVALUATION_EXPECTED_ASSIGNED_ROUTE"
    ),
    "expected_reviewer_route": (
        "ONION_SENTINEL_EVALUATION_EXPECTED_REVIEWER_ROUTE"
    ),
    "reviewer_required": "ONION_SENTINEL_EVALUATION_REVIEWER_REQUIRED",
}


@dataclass(frozen=True)
class RunnerInvocationDefaults:
    """Paths and bounds owned by the scheduler entry point."""

    python_executable: str
    runner_path: Path
    prompt_dir: Path
    harness_policy: Path
    disagreement_prompt: Path
    live_osquery_config: Path
    incident_evidence_config: Path
    investigation_pivot_dir: Path
    max_stdout_bytes: int
    max_stderr_bytes: int
    token_environment_key: str
    token_pattern: re.Pattern[str]
    watchdog_multiplier: int = 5
    watchdog_grace_seconds: int = 300
    progress_interval_seconds: float = 60


@dataclass(frozen=True)
class RunnerInvocationSources:
    """Mutable scheduler collaborators resolved by the compatibility facade."""

    effective_prompt_limit: Callable[..., int]
    role_prompt_file: Callable[[Path, str], Path]
    role_second_opinion_prompt_file: Callable[[Path, str], Path]
    run_command: Callable[..., Any]
    environment_snapshot: Callable[[], Mapping[str, str]]
    fallback_evaluation_token: Callable[[], str]


def _base_command(
    defaults: RunnerInvocationDefaults,
    sources: RunnerInvocationSources,
    prompt_path: Path,
    args: Any,
    agent_role: str,
) -> list[str]:
    settings_path = Path(args.ai_settings_file)
    return [
        defaults.python_executable,
        str(defaults.runner_path),
        "--prompt-package",
        str(prompt_path),
        "--prompt-dir",
        str(getattr(args, "prompt_dir", defaults.prompt_dir)),
        "--out-dir",
        str(args.analysis_dir),
        "--timeout",
        str(args.timeout),
        "--max-prompt-bytes",
        str(sources.effective_prompt_limit(args, agent_role=agent_role)),
        "--alert-store-url",
        args.alert_store_url,
        "--ai-settings-file",
        str(settings_path),
        "--investigation-harness-policy",
        str(
            getattr(
                args,
                "investigation_harness_policy",
                defaults.harness_policy,
            )
        ),
    ]


def _policy_path_arguments(
    defaults: RunnerInvocationDefaults,
    sources: RunnerInvocationSources,
    args: Any,
    agent_role: str,
) -> list[str]:
    settings_directory = Path(args.ai_settings_file).parent
    return [
        "--system-prompt-file",
        str(sources.role_prompt_file(settings_directory, agent_role)),
        "--second-opinion-prompt-file",
        str(
            sources.role_second_opinion_prompt_file(
                settings_directory,
                agent_role,
            )
        ),
        "--disagreement-adjudicator-prompt-file",
        str(
            getattr(
                args,
                "disagreement_adjudicator_prompt_file",
                defaults.disagreement_prompt,
            )
        ),
        "--live-osquery-config",
        str(getattr(args, "live_osquery_config", defaults.live_osquery_config)),
        "--incident-evidence-config",
        str(
            getattr(
                args,
                "incident_evidence_config",
                defaults.incident_evidence_config,
            )
        ),
        "--investigation-pivot-dir",
        str(
            getattr(
                args,
                "investigation_pivot_dir",
                defaults.investigation_pivot_dir,
            )
        ),
    ]


def analysis_command(
    defaults: RunnerInvocationDefaults,
    sources: RunnerInvocationSources,
    prompt_path: Path,
    args: Any,
    *,
    reanalysis_attempt_id: str = "",
    agent_role: str = "",
) -> list[str]:
    """Return the canonical runner argv for one scheduler job."""
    effective_role = str(agent_role or "soc-analyst")
    command = _base_command(defaults, sources, prompt_path, args, effective_role)
    command.extend(
        _policy_path_arguments(defaults, sources, args, effective_role)
    )
    if args.model:
        command.extend(["--model", args.model])
    if reanalysis_attempt_id:
        command.extend(["--reanalysis-attempt-id", reanalysis_attempt_id])
    return command


def controlled_child_environment(
    defaults: RunnerInvocationDefaults,
    sources: RunnerInvocationSources,
    identity: Mapping[str, object] | None,
) -> dict[str, str] | None:
    """Project frozen job identity only for controlled evaluation children."""
    if not identity:
        return None
    parent_environment = dict(sources.environment_snapshot())
    supplied_token = str(
        parent_environment.get(defaults.token_environment_key) or ""
    ).strip()
    token = supplied_token or sources.fallback_evaluation_token()
    if defaults.token_pattern.fullmatch(token):
        parent_environment[defaults.token_environment_key] = token
    parent_environment["TMPDIR"] = str(parent_environment["TMPDIR"])
    for field, environment_key in CONTROLLED_RESULT_ENVIRONMENT.items():
        value = identity.get(field)
        parent_environment[environment_key] = (
            "1" if field == "reviewer_required" and value is True
            else str(value or "")
        )
    return parent_environment


def invoke_analysis_runner(
    defaults: RunnerInvocationDefaults,
    sources: RunnerInvocationSources,
    prompt_path: Path,
    args: Any,
    *,
    progress_callback: Callable[..., Any] | None = None,
    reanalysis_attempt_id: str = "",
    agent_role: str = "",
    controlled_result_identity: Mapping[str, object] | None = None,
) -> Any:
    """Run one analysis child with the scheduler's bounded watchdog policy."""
    command = analysis_command(
        defaults,
        sources,
        prompt_path,
        args,
        reanalysis_attempt_id=reanalysis_attempt_id,
        agent_role=agent_role,
    )
    child_environment = controlled_child_environment(
        defaults,
        sources,
        controlled_result_identity,
    )
    return sources.run_command(
        command,
        timeout_seconds=(
            (args.timeout * defaults.watchdog_multiplier)
            + defaults.watchdog_grace_seconds
        ),
        max_stdout_bytes=defaults.max_stdout_bytes,
        max_stderr_bytes=defaults.max_stderr_bytes,
        env=child_environment,
        progress_callback=progress_callback,
        progress_interval_seconds=defaults.progress_interval_seconds,
    )
