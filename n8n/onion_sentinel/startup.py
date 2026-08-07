"""Prompt loading and pre-inference attestation for the AI pipeline."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .pipeline import RuntimeContext, RuntimePathDefaults, RuntimePaths, Stage


@dataclass(frozen=True)
class BootstrapPolicy:
    freeze_memory_env: str
    path_defaults: RuntimePathDefaults


@dataclass(frozen=True)
class BootstrapPorts:
    controlled_runtime: Callable[[Any], tuple[bool, Path | None]]
    controlled_output_dir: Callable[[Path, Path], Path]
    consume_token: Callable[[bool], None]
    result_identity: Callable[[bool, str], dict[str, Any] | None]
    boolean_setting: Callable[[Any], bool]
    flush_queue: Callable[[str, bool], tuple[int, int, int]]
    emit: Callable[[dict[str, Any]], None]


@dataclass(frozen=True)
class BootstrapResult:
    controlled: bool
    runtime_dir: Path | None
    runtime_paths: RuntimePaths
    memory_frozen: bool
    controlled_identity: dict[str, Any] | None
    exit_code: int | None = None


def bootstrap(
    args: Any,
    *,
    environment: Mapping[str, str],
    policy: BootstrapPolicy,
    ports: BootstrapPorts,
) -> BootstrapResult:
    controlled, runtime_dir = ports.controlled_runtime(args)
    freeze_value = environment.get(policy.freeze_memory_env)
    if controlled and str(freeze_value or "").strip() != "1":
        raise SystemExit(
            f"controlled evaluation requires {policy.freeze_memory_env}=1"
        )
    if runtime_dir is not None:
        args.out_dir = ports.controlled_output_dir(args.out_dir, runtime_dir)
    ports.consume_token(controlled)
    identity = ports.result_identity(
        controlled, str(getattr(args, "reanalysis_attempt_id", "") or "")
    )
    if runtime_dir is not None:
        args.investigation_harness_db = runtime_dir / "investigation-harness.sqlite3"
    paths = RuntimePaths.resolve(runtime_dir, policy.path_defaults)
    memory_frozen = ports.boolean_setting(freeze_value)
    exit_code: int | None = None
    if bool(getattr(args, "flush_index_only", False)):
        if controlled:
            raise SystemExit(
                "global analysis-index flush is disabled in controlled evaluation mode"
            )
        completed, failed, quarantined = ports.flush_queue(
            str(args.alert_store_url), not memory_frozen
        )
        ports.emit({
            "ok": failed == 0,
            "published": completed,
            "quarantined": quarantined,
            "remaining_failures": failed,
        })
        exit_code = 0 if failed == 0 else 1
    return BootstrapResult(
        controlled, runtime_dir, paths, memory_frozen, identity, exit_code
    )


def reconcile_deferred_results(
    *,
    controlled: bool,
    memory_frozen: bool,
    alert_store_url: str,
    flush_queue: Callable[[str, bool], tuple[int, int, int]],
) -> None:
    """Drain prior durable results before permitting another model call."""
    failures = 0
    if not controlled:
        _, failures, _ = flush_queue(alert_store_url, not memory_frozen)
    if failures:
        raise RuntimeError(
            "a deferred analysis index could not be reconciled; "
            "refusing to invoke another model until the ordered spool "
            "can reach alert-store"
        )


@dataclass(frozen=True)
class PromptAttestationPolicy:
    package_type: str
    allowed_roles: frozenset[str]
    default_settings_file: Path
    default_live_osquery_file: Path
    controlled_identity: dict[str, Any] | None


@dataclass(frozen=True)
class PromptAttestationPorts:
    generate_prompt: Callable[[Any], Path]
    latest_prompt: Callable[[Path], Path]
    load_json: Callable[[Path, int], dict[str, Any]]
    role_prompt_file: Callable[[Path, str], Path]
    role_review_file: Callable[[Path, str], Path]
    validate_incident_evidence: Callable[[Any], None]
    effective_settings: Callable[[Any], dict[str, Any]]
    require_controlled_routes: Callable[[dict[str, Any] | None, Any, dict[str, Any], str], None]
    prepare_live_osquery: Callable[[dict[str, Any], str, Path], Any]
    prepare_enrichment: Callable[[dict[str, Any], str, str], Any]
    attach_evidence_contract: Callable[[dict[str, Any]], None]


@dataclass(frozen=True)
class AttestedPrompt:
    prompt_path: Path
    prompt_package: dict[str, Any]
    agent_role: str
    settings: dict[str, Any]
    live_osquery_config: Any
    enrichment_config: Any


def load_and_attest(
    context: RuntimeContext,
    args: Any,
    *,
    policy: PromptAttestationPolicy,
    ports: PromptAttestationPorts,
) -> AttestedPrompt:
    prompt_path = context.prompt_path
    if bool(getattr(args, "generate_prompt", False)):
        prompt_path = ports.generate_prompt(args)
    if prompt_path is None:
        prompt_path = ports.latest_prompt(Path(args.prompt_dir))
    package = ports.load_json(prompt_path, int(args.max_prompt_bytes))
    context.prompt_path = prompt_path
    context.prompt_package = dict(package)
    context.advance(Stage.LOAD, "prompt package loaded")

    if package.get("package_type") != policy.package_type:
        raise SystemExit(f"unexpected prompt package type in {prompt_path}")
    role = str(package.get("agent_role") or "soc-analyst").strip().lower()
    if role not in policy.allowed_roles:
        raise SystemExit(
            f"unexpected cyber-security agent role in {prompt_path}: {role}"
        )
    settings_path = Path(
        getattr(args, "ai_settings_file", policy.default_settings_file)
        or policy.default_settings_file
    )
    _attest_prompt_paths(package, settings_path.parent, role, ports)
    if role == "incident-responder":
        ports.validate_incident_evidence(package.get("incident_response_evidence"))

    settings = ports.effective_settings(args)
    ports.require_controlled_routes(policy.controlled_identity, args, settings, role)
    context.settings = dict(settings)
    context.advance(Stage.ATTEST, "prompt role, evidence, and model routes attested")
    live_config_path = Path(
        getattr(args, "live_osquery_config", policy.default_live_osquery_file)
        or policy.default_live_osquery_file
    )
    live_osquery = ports.prepare_live_osquery(package, role, live_config_path)
    enrichment = ports.prepare_enrichment(package, role, str(args.alert_store_url))
    ports.attach_evidence_contract(package)
    return AttestedPrompt(
        prompt_path, package, role, settings, live_osquery, enrichment
    )


def _attest_prompt_paths(
    package: dict[str, Any],
    config_dir: Path,
    role: str,
    ports: PromptAttestationPorts,
) -> None:
    expected = {
        "system_prompt_file": ports.role_prompt_file(config_dir, role),
        "second_opinion_system_prompt_file": ports.role_review_file(
            config_dir, role
        ),
    }
    for field, expected_path in expected.items():
        declared = str(package.get(field) or "").strip()
        if declared and Path(declared).expanduser() != expected_path.expanduser():
            raise SystemExit(
                f"prompt package {field} does not match the canonical "
                f"{role} runtime path"
            )
