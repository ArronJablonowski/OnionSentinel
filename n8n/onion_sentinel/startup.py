"""Prompt loading and pre-inference attestation for the AI pipeline."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .pipeline import RuntimeContext, Stage


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
