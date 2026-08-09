"""Fail-closed filesystem and transport admission for controlled evaluations."""

from __future__ import annotations

import json
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Type
from urllib.parse import urlparse


@dataclass(frozen=True)
class Policy:
    home: Path
    mode_environment_key: str
    runtime_environment_key: str
    token_environment_key: str
    token_pattern: Any
    production_alert_store_port: int = 8787


@dataclass(frozen=True)
class Dependencies:
    environment: Mapping[str, str]
    owner_id: Callable[[], int]
    pin_tmpdir: Callable[[Path], Path]
    validate_incident_route: Callable[..., None]
    isolation_error: Type[Exception]


@dataclass(frozen=True)
class Result:
    enabled: bool
    root: Path | None
    tmpdir: Path | None


def _mode(policy: Policy, dependencies: Dependencies) -> bool:
    value = str(
        dependencies.environment.get(policy.mode_environment_key) or ""
    ).strip()
    if value not in {"", "0", "1"}:
        raise SystemExit(
            f"{policy.mode_environment_key} must be unset, 0, or 1"
        )
    return value == "1"


def _reject_runtime_overrides(runtime_args: Any) -> None:
    if runtime_args is None:
        return
    if str(getattr(runtime_args, "model", "") or "").strip():
        raise SystemExit(
            "controlled evaluation forbids --model and SOC_AI_MODEL overrides"
        )
    if bool(getattr(runtime_args, "generate_prompt", False)):
        raise SystemExit(
            "controlled evaluation forbids --generate-prompt; use the frozen prompt"
        )


def _require_token(policy: Policy, dependencies: Dependencies) -> None:
    token = str(
        dependencies.environment.get(policy.token_environment_key) or ""
    ).strip()
    if not policy.token_pattern.fullmatch(token):
        raise SystemExit(
            "controlled evaluation requires an exact ephemeral authorization token"
        )


def _validate_alert_store_origin(value: str, policy: Policy) -> None:
    try:
        origin = urlparse(str(value or ""))
        port = origin.port
    except ValueError as exc:
        raise SystemExit(
            "controlled evaluation alert-store origin is unsafe"
        ) from exc
    safe = (
        origin.scheme == "http"
        and origin.hostname == "127.0.0.1"
        and port is not None
        and port >= 1
        and port != policy.production_alert_store_port
        and origin.username is None
        and origin.password is None
        and origin.path in {"", "/"}
        and not origin.params
        and not origin.query
        and not origin.fragment
    )
    if not safe:
        raise SystemExit(
            "controlled evaluation requires one alternate loopback alert-store origin"
        )


def _runtime_root(policy: Policy, dependencies: Dependencies) -> Path:
    raw = str(
        dependencies.environment.get(policy.runtime_environment_key) or ""
    ).strip()
    if not raw:
        raise SystemExit("controlled evaluation runtime directory is required")
    root = Path(raw).expanduser()
    try:
        metadata = root.lstat()
        resolved = root.resolve(strict=True)
        expected_parent = (
            policy.home / "n8n-local" / "harness-evaluations"
        ).resolve(strict=True)
        resolved.relative_to(expected_parent)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise SystemExit(
            f"controlled evaluation runtime directory is unsafe: {exc}"
        ) from exc
    if (
        not root.is_absolute()
        or resolved != root
        or root.is_symlink()
        or not root.is_dir()
        or metadata.st_uid != dependencies.owner_id()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise SystemExit(
            "controlled evaluation runtime directory must be owner-only"
        )
    return resolved


def _pin_tmpdir(root: Path, dependencies: Dependencies) -> Path:
    try:
        return dependencies.pin_tmpdir(root)
    except dependencies.isolation_error as exc:
        raise SystemExit(f"controlled evaluation {exc}") from exc


def _owner_private_path(
    candidate: Path,
    root: Path,
    *,
    label: str,
    kind: str,
    dependencies: Dependencies,
) -> Path:
    candidate = candidate.expanduser()
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise SystemExit(
            f"controlled evaluation {label} must be a canonical owner-private "
            f"{kind} inside the evaluation runtime"
        ) from exc
    expected_kind = candidate.is_file() if kind == "file" else candidate.is_dir()
    if (
        not candidate.is_absolute()
        or resolved != candidate
        or candidate.is_symlink()
        or not expected_kind
        or metadata.st_uid != dependencies.owner_id()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise SystemExit(
            f"controlled evaluation {label} must be a canonical owner-private "
            f"{kind} inside the evaluation runtime"
        )
    return resolved


def _validate_directories(
    runtime_args: Any,
    root: Path,
    dependencies: Dependencies,
) -> None:
    for label, candidate in {
        "prompt directory": runtime_args.prompt_dir,
        "analysis output directory": runtime_args.out_dir,
        "investigation-pivot directory": runtime_args.investigation_pivot_dir,
    }.items():
        _owner_private_path(
            candidate, root, label=label, kind="directory",
            dependencies=dependencies,
        )


def _runtime_files(runtime_args: Any) -> dict[str, Any]:
    files = {
        "prompt package": runtime_args.prompt_package,
        "AI settings": runtime_args.ai_settings_file,
        "harness policy": runtime_args.investigation_harness_policy,
        "primary system prompt": runtime_args.system_prompt_file,
        "reviewer system prompt": runtime_args.second_opinion_prompt_file,
        "disagreement prompt": runtime_args.disagreement_adjudicator_prompt_file,
        "live OSQuery config": runtime_args.live_osquery_config,
    }
    if runtime_args.response_json is not None:
        files["saved response"] = runtime_args.response_json
    return files


def _validate_files(
    runtime_args: Any,
    root: Path,
    dependencies: Dependencies,
) -> None:
    for label, candidate in _runtime_files(runtime_args).items():
        if candidate is None:
            raise SystemExit(
                f"controlled evaluation requires an explicit {label}"
            )
        _owner_private_path(
            candidate, root, label=label, kind="file",
            dependencies=dependencies,
        )


def _validate_incident_route(
    runtime_args: Any,
    root: Path,
    policy: Policy,
    dependencies: Dependencies,
) -> None:
    try:
        dependencies.validate_incident_route(
            runtime_args.incident_evidence_config,
            root,
            expected_home=policy.home,
        )
    except dependencies.isolation_error as exc:
        raise SystemExit(f"controlled evaluation {exc}") from exc


def _require_disabled_live_osquery(runtime_args: Any) -> None:
    try:
        document = json.loads(
            runtime_args.live_osquery_config.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(
            "controlled evaluation live OSQuery config is invalid"
        ) from exc
    if not isinstance(document, dict) or document.get("enabled") is not False:
        raise SystemExit(
            "controlled evaluation requires live OSQuery to be explicitly disabled"
        )


def resolve(
    runtime: Any,
    *,
    policy: Policy,
    dependencies: Dependencies,
) -> Result:
    """Admit one exact owner-private controlled evaluation runtime."""
    if not _mode(policy, dependencies):
        return Result(enabled=False, root=None, tmpdir=None)
    runtime_args = None if isinstance(runtime, str) else runtime
    alert_store_url = (
        runtime if isinstance(runtime, str) else str(runtime.alert_store_url or "")
    )
    _reject_runtime_overrides(runtime_args)
    _require_token(policy, dependencies)
    _validate_alert_store_origin(alert_store_url, policy)
    root = _runtime_root(policy, dependencies)
    tmpdir = _pin_tmpdir(root, dependencies)
    if runtime_args is not None:
        _validate_directories(runtime_args, root, dependencies)
        _validate_files(runtime_args, root, dependencies)
        _validate_incident_route(runtime_args, root, policy, dependencies)
        _require_disabled_live_osquery(runtime_args)
    return Result(enabled=True, root=root, tmpdir=tmpdir)
