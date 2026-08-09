"""Bounded prompt-package preparation for scheduler analysis work."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PromptBuilderDefaults:
    builder_path: Path
    python_executable: str
    database: Path
    rollup_dir: Path
    agent_memory_dir: Path
    shared_memory_file: Path
    pcap_analysis_dir: Path
    prior_analysis_dir: Path
    asset_inventory_file: Path
    detection_playbooks: Path
    investigation_skills: Path
    timeout_seconds: float
    max_stdout_bytes: int
    max_stderr_bytes: int


@dataclass(frozen=True)
class PromptBuilderSources:
    initial_prompt_limit: Callable[..., int]
    role_prompt_file: Callable[[Path, str], Path]
    role_second_opinion_prompt_file: Callable[[Path, str], Path]
    role_memory_file: Callable[[Path, str], Path]
    run_command: Callable[..., Any]
    emit_stderr: Callable[[str], None]


def _bounded_int(
    value: object,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _prompt_paths(
    defaults: PromptBuilderDefaults,
    sources: PromptBuilderSources,
    args: Any,
    agent_role: str,
) -> list[str]:
    config_dir = Path(args.ai_settings_file).parent
    return [
        "--system-prompt-file",
        str(sources.role_prompt_file(config_dir, agent_role)),
        "--second-opinion-prompt-file",
        str(sources.role_second_opinion_prompt_file(config_dir, agent_role)),
        "--agent-memory-file",
        str(
            sources.role_memory_file(
                getattr(args, "agent_memory_dir", defaults.agent_memory_dir),
                agent_role,
            )
        ),
        "--shared-memory-file",
        str(
            getattr(args, "shared_memory_file", defaults.shared_memory_file)
        ),
        "--pcap-analysis-dir",
        str(getattr(args, "pcap_analysis_dir", defaults.pcap_analysis_dir)),
        "--analysis-dir",
        str(getattr(args, "prior_analysis_dir", defaults.prior_analysis_dir)),
        "--asset-inventory-file",
        str(
            getattr(
                args, "asset_inventory_file", defaults.asset_inventory_file
            )
        ),
        "--detection-playbooks",
        str(
            getattr(
                args, "detection_playbooks", defaults.detection_playbooks
            )
        ),
        "--investigation-skills",
        str(
            getattr(
                args, "investigation_skills", defaults.investigation_skills
            )
        ),
    ]


def _builder_command(
    defaults: PromptBuilderDefaults,
    sources: PromptBuilderSources,
    alert_id: str,
    args: Any,
    payload: dict[str, object],
    incident_evidence_path: Path | None,
    agent_role: str,
    prompt_limit: int,
) -> list[str]:
    related_limit = _bounded_int(
        payload.get("related_limit"), args.related_limit, 1, 500
    )
    pcap_limit = _bounded_int(payload.get("pcap_analysis_limit"), 8, 1, 25)
    command = [
        defaults.python_executable,
        str(defaults.builder_path),
        "--db",
        str(getattr(args, "db", defaults.database)),
        "--alert-id",
        alert_id,
        "--out-dir",
        str(args.prompt_dir),
        "--rollup-dir",
        str(getattr(args, "rollup_dir", defaults.rollup_dir)),
        "--related-limit",
        str(related_limit),
        "--correlation-limit",
        str(args.correlation_limit),
        "--correlation-min-score",
        str(args.correlation_min_score),
        "--pcap-analysis-limit",
        str(pcap_limit),
        "--max-package-bytes",
        str(prompt_limit),
        "--agent-role",
        agent_role,
        *_prompt_paths(defaults, sources, args, agent_role),
    ]
    if incident_evidence_path is not None:
        command.extend(
            ["--incident-evidence-file", str(incident_evidence_path)]
        )
    if payload.get("manual_reanalysis") is True:
        command.append("--blind-reanalysis")
    if args.include_tests:
        command.append("--include-tests")
    return command


def _raise_builder_failure(
    sources: PromptBuilderSources,
    process: Any,
) -> None:
    stderr = str(process.stderr or "")
    if stderr:
        sources.emit_stderr(stderr)
    stderr_lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    detail = stderr_lines[-1][:700] if stderr_lines else ""
    suffix = f": {detail}" if detail else ""
    raise RuntimeError(f"prompt builder failed rc={process.returncode}{suffix}")


def _validated_prompt_path(
    process: Any,
    prompt_dir: Path,
    prompt_limit: int,
) -> Path:
    output_lines = [
        line.strip() for line in process.stdout.splitlines() if line.strip()
    ]
    if not output_lines:
        raise RuntimeError("prompt builder returned no output path")
    prompt_path = Path(output_lines[-1])
    if not prompt_path.exists():
        raise RuntimeError(
            f"prompt builder did not create a prompt package: {prompt_path}"
        )
    try:
        prompt_path.resolve().relative_to(prompt_dir.resolve())
    except ValueError as exc:
        raise RuntimeError(
            "prompt builder returned a path outside the configured prompt directory"
        ) from exc
    if prompt_path.stat().st_size > prompt_limit:
        raise RuntimeError(
            f"prompt package exceeded the {prompt_limit}-byte worker limit"
        )
    return prompt_path


def build_prompt_package(
    defaults: PromptBuilderDefaults,
    sources: PromptBuilderSources,
    alert_id: str,
    args: Any,
    job_payload: dict[str, object] | None = None,
    incident_evidence_path: Path | None = None,
) -> Path:
    """Build and validate one bounded prompt package."""
    payload = job_payload or {}
    agent_role = str(payload.get("agent_role") or "soc-analyst")
    prompt_limit = sources.initial_prompt_limit(
        args, agent_role=agent_role
    )
    command = _builder_command(
        defaults,
        sources,
        alert_id,
        args,
        payload,
        incident_evidence_path,
        agent_role,
        prompt_limit,
    )
    process = sources.run_command(
        command,
        timeout_seconds=defaults.timeout_seconds,
        max_stdout_bytes=defaults.max_stdout_bytes,
        max_stderr_bytes=defaults.max_stderr_bytes,
    )
    if process.returncode != 0:
        _raise_builder_failure(sources, process)
    return _validated_prompt_path(process, args.prompt_dir, prompt_limit)
