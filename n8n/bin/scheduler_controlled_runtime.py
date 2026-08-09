"""Fail-closed admission for one frozen controlled scheduler worker."""
from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from re import Pattern
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class ControlledRuntimePolicy:
    home: Path
    release_environment_key: str
    token_environment_key: str
    release_pattern: Pattern[str]
    token_pattern: Pattern[str]


@dataclass(frozen=True)
class ControlledRuntimeSources:
    environment: Mapping[str, str]
    effective_uid: Callable[[], int]
    pin_tmpdir: Callable[[Path], None]
    validate_incident_evidence_route: Callable[..., None]
    role_prompt_file: Callable[[Path, str], Path]
    role_second_opinion_prompt_file: Callable[[Path, str], Path]
    role_memory_file: Callable[[Path, str], Path]
    isolation_error: type[BaseException]


def _owner_private_path(
    sources: ControlledRuntimeSources,
    candidate: Path,
    runtime_root: Path,
    *,
    label: str,
    kind: str,
    inside_runtime: bool = True,
) -> Path:
    candidate = candidate.expanduser()
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        if inside_runtime:
            resolved.relative_to(runtime_root)
    except (FileNotFoundError, OSError, ValueError) as error:
        location = " inside the evaluation runtime" if inside_runtime else ""
        raise SystemExit(
            f"controlled evaluation {label} must be a canonical "
            f"owner-private {kind}{location}"
        ) from error
    expected_kind = candidate.is_file() if kind == "file" else candidate.is_dir()
    unsafe = any(
        (
            not candidate.is_absolute(),
            resolved != candidate,
            candidate.is_symlink(),
            not expected_kind,
            metadata.st_uid != sources.effective_uid(),
            bool(stat.S_IMODE(metadata.st_mode) & 0o077),
        )
    )
    if unsafe:
        location = " inside the evaluation runtime" if inside_runtime else ""
        raise SystemExit(
            f"controlled evaluation {label} must be a canonical "
            f"owner-private {kind}{location}"
        )
    return resolved


def _owner_private_mutable_file(
    sources: ControlledRuntimeSources,
    candidate: Path,
    runtime_root: Path,
    *,
    label: str,
) -> None:
    candidate = candidate.expanduser()
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(runtime_root)
    except (OSError, ValueError) as error:
        raise SystemExit(
            f"controlled evaluation {label} must stay inside its runtime directory"
        ) from error
    if not candidate.is_absolute() or resolved != candidate:
        raise SystemExit(
            f"controlled evaluation {label} must stay inside its runtime directory"
        )
    if candidate.exists():
        _owner_private_path(
            sources, candidate, runtime_root, label=label, kind="file"
        )
        return
    _owner_private_path(
        sources,
        candidate.parent,
        runtime_root,
        label=f"{label} parent",
        kind="directory",
    )


def _canonical_runtime_root(
    policy: ControlledRuntimePolicy,
    sources: ControlledRuntimeSources,
) -> tuple[Path, object]:
    raw_root = str(
        sources.environment.get("ONION_SENTINEL_EVALUATION_RUNTIME_DIR") or ""
    ).strip()
    try:
        root = Path(raw_root)
        metadata = root.lstat()
        resolved = root.resolve(strict=True)
        expected_parent = (
            policy.home / "n8n-local" / "harness-evaluations"
        ).resolve(strict=True)
        resolved.relative_to(expected_parent)
    except (FileNotFoundError, OSError, ValueError) as error:
        raise SystemExit(
            f"controlled evaluation runtime directory is unsafe: {error}"
        ) from error
    if (
        not raw_root
        or not root.is_absolute()
        or resolved != root
        or root.is_symlink()
        or not root.is_dir()
        or metadata.st_uid != sources.effective_uid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise SystemExit(
            "controlled evaluation requires one exact frozen job, an "
            "owner-only runtime, frozen memory, a loopback alert store, "
            "an exact release ID, and an ephemeral authorization token"
        )
    return resolved, metadata


def _safe_loopback_origin(args: Any) -> bool:
    try:
        origin = urlparse(args.alert_store_url)
        port = origin.port
    except ValueError as error:
        raise SystemExit(
            "controlled evaluation alert-store origin is unsafe"
        ) from error
    return all(
        (
            origin.scheme == "http",
            origin.hostname == "127.0.0.1",
            port in range(1, 65536),
            port != 8787,
            origin.username is None,
            origin.password is None,
            origin.path in {"", "/"},
            not origin.params,
            not origin.query,
            not origin.fragment,
        )
    )


def _validate_frozen_identity(
    args: Any,
    policy: ControlledRuntimePolicy,
    sources: ControlledRuntimeSources,
) -> None:
    environment = sources.environment
    controlled_identity = (
        args.only_group_id,
        args.only_alert_id,
        args.only_stable_group_key,
        args.only_dispatch_id,
    )
    if (
        str(environment.get("ONION_SENTINEL_EVALUATION_FREEZE_MEMORY") or "").strip()
        != "1"
        or not policy.release_pattern.fullmatch(
            str(environment.get(policy.release_environment_key) or "")
        )
        or not policy.token_pattern.fullmatch(
            str(environment.get(policy.token_environment_key) or "").strip()
        )
        or not all(controlled_identity)
        or args.max_per_run != 1
        or not _safe_loopback_origin(args)
    ):
        raise SystemExit(
            "controlled evaluation requires one exact frozen job, an "
            "owner-only runtime, frozen memory, a loopback alert store, "
            "an exact release ID, and an ephemeral authorization token"
        )


def _validate_context_directories(
    args: Any,
    sources: ControlledRuntimeSources,
    runtime_root: Path,
) -> None:
    directories = {
        "prompt directory": args.prompt_dir,
        "analysis output directory": args.analysis_dir,
        "prior-analysis directory": args.prior_analysis_dir,
        "PCAP analysis directory": args.pcap_analysis_dir,
        "rollup directory": args.rollup_dir,
        "agent-memory directory": args.agent_memory_dir,
        "incident-evidence directory": args.incident_evidence_dir,
        "investigation-pivot directory": args.investigation_pivot_dir,
    }
    for label, candidate in directories.items():
        _owner_private_path(
            sources, candidate, runtime_root, label=label, kind="directory"
        )
    if args.analysis_dir.resolve() == args.prior_analysis_dir.resolve():
        raise SystemExit(
            "controlled evaluation prior analysis must be frozen separately "
            "from analysis output"
        )


def _runtime_read_files(
    args: Any,
    sources: ControlledRuntimeSources,
) -> dict[str, Path]:
    config_dir = args.ai_settings_file.parent
    return {
        "clone database": args.db,
        "AI settings": args.ai_settings_file,
        "harness policy": args.investigation_harness_policy,
        "detection playbooks": args.detection_playbooks,
        "investigation skills": args.investigation_skills,
        "shared memory": args.shared_memory_file,
        "asset inventory": args.asset_inventory_file,
        "live OSQuery config": args.live_osquery_config,
        "disagreement prompt": args.disagreement_adjudicator_prompt_file,
        "SOC Analyst prompt": sources.role_prompt_file(config_dir, "soc-analyst"),
        "SOC Analyst reviewer prompt": sources.role_second_opinion_prompt_file(
            config_dir, "soc-analyst"
        ),
        "Incident Responder prompt": sources.role_prompt_file(
            config_dir, "incident-responder"
        ),
        "Incident Responder reviewer prompt": (
            sources.role_second_opinion_prompt_file(config_dir, "incident-responder")
        ),
        "SOC Analyst frozen memory": sources.role_memory_file(
            args.agent_memory_dir, "soc-analyst"
        ),
        "Incident Responder frozen memory": sources.role_memory_file(
            args.agent_memory_dir, "incident-responder"
        ),
    }


def _validate_runtime_files(
    args: Any,
    policy: ControlledRuntimePolicy,
    sources: ControlledRuntimeSources,
    runtime_root: Path,
) -> None:
    for label, candidate in _runtime_read_files(args, sources).items():
        _owner_private_path(
            sources, candidate, runtime_root, label=label, kind="file"
        )
    try:
        sources.validate_incident_evidence_route(
            args.incident_evidence_config,
            runtime_root,
            expected_home=policy.home,
        )
    except sources.isolation_error as error:
        raise SystemExit(f"controlled evaluation {error}") from error
    try:
        osquery = json.loads(args.live_osquery_config.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit(
            "controlled evaluation live OSQuery config is invalid"
        ) from error
    if not isinstance(osquery, dict) or osquery.get("enabled") is not False:
        raise SystemExit(
            "controlled evaluation requires live OSQuery to be explicitly disabled"
        )


def validate_controlled_evaluation_runtime(
    args: Any,
    policy: ControlledRuntimePolicy,
    sources: ControlledRuntimeSources,
) -> Path | None:
    """Validate the one-member, owner-only evaluation worker boundary."""
    mode = str(
        sources.environment.get("ONION_SENTINEL_EVALUATION_MODE") or ""
    ).strip()
    if mode not in {"", "0", "1"}:
        raise SystemExit("ONION_SENTINEL_EVALUATION_MODE must be unset, 0, or 1")
    if mode != "1":
        return None
    if str(getattr(args, "model", "") or "").strip():
        raise SystemExit(
            "controlled evaluation forbids --model and SOC_AI_MODEL overrides"
        )
    runtime_root, _ = _canonical_runtime_root(policy, sources)
    _validate_frozen_identity(args, policy, sources)
    try:
        sources.pin_tmpdir(runtime_root)
    except sources.isolation_error as error:
        raise SystemExit(f"controlled evaluation {error}") from error
    _validate_context_directories(args, sources, runtime_root)
    _validate_runtime_files(args, policy, sources, runtime_root)
    for label, candidate in {
        "lock file": args.lock_file,
        "worker wake file": args.wake_file,
        "dashboard wake file": args.portal_wake_file,
    }.items():
        _owner_private_mutable_file(
            sources, candidate, runtime_root, label=label
        )
    return runtime_root
