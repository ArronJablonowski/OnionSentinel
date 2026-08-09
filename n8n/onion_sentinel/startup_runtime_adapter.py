"""Legacy runtime bindings for prompt creation and startup attestation."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Mapping


def latest_prompt(prompt_dir: Path) -> Path:
    files = sorted(prompt_dir.glob("*-ai-prompt.json"))
    if not files:
        raise SystemExit(f"no prompt packages found in {prompt_dir}")
    return files[-1]


def generate_prompt(bindings: Mapping[str, Any], args: Any) -> Path:
    """Run the bounded prompt builder and admit only its existing output."""
    b = bindings
    builder = b["BIN_DIR"] / "build-ai-investigation-prompt.py"
    if not builder.exists():
        raise SystemExit(f"prompt builder not found: {builder}")
    command = [
        sys.executable,
        str(builder),
        "--levels",
        args.levels,
        "--hours",
        str(args.hours),
        "--related-limit",
        str(args.related_limit),
        "--correlation-limit",
        str(args.correlation_limit),
        "--correlation-min-score",
        str(args.correlation_min_score),
        "--max-package-bytes",
        str(args.max_prompt_bytes),
        "--out-dir",
        str(args.prompt_dir),
    ]
    try:
        process = b["run_bounded_command"](
            command,
            timeout_seconds=min(max(30, args.timeout), 300),
            max_stdout_bytes=16 * 1024,
            max_stderr_bytes=256 * 1024,
        )
    except b["BoundedProcessError"] as exc:
        raise SystemExit(
            f"prompt builder exceeded its runtime contract: {exc}"
        ) from exc
    if process.returncode != 0:
        if process.stderr:
            print(process.stderr, file=sys.stderr, end="")
        raise SystemExit(f"prompt builder failed with rc={process.returncode}")
    path_text = (
        process.stdout.strip().splitlines()[-1]
        if process.stdout.strip()
        else ""
    )
    prompt_path = Path(path_text)
    if not prompt_path.exists():
        raise SystemExit(
            f"prompt builder did not return a valid path: {path_text}"
        )
    return prompt_path


def load_and_attest(
    bindings: Mapping[str, Any],
    module: Any,
    context: Any,
    args: Any,
    controlled_identity: dict[str, Any] | None,
) -> Any:
    """Bind package prompt attestation to legacy validation callables."""
    b = bindings
    return module.load_and_attest(
        context,
        args,
        policy=module.PromptAttestationPolicy(
            package_type="soc-ai-investigation-prompt",
            allowed_roles=frozenset(b["CYBER_SECURITY_AGENT_ROLES"]),
            default_settings_file=b["DEFAULT_AI_SETTINGS_FILE"],
            default_live_osquery_file=b["DEFAULT_LIVE_OSQUERY_CONFIG_FILE"],
            controlled_identity=controlled_identity,
        ),
        ports=module.PromptAttestationPorts(
            generate_prompt=b["generate_prompt"],
            latest_prompt=b["latest_prompt"],
            load_json=b["load_json"],
            role_prompt_file=b["role_prompt_file"],
            role_review_file=b["role_second_opinion_prompt_file"],
            validate_incident_evidence=b["validate_incident_evidence_artifact"],
            effective_settings=b["effective_ai_settings"],
            require_controlled_routes=b["require_controlled_evaluation_routes"],
            prepare_live_osquery=b["prepare_live_osquery_context"],
            prepare_enrichment=b["prepare_investigation_enrichment_context"],
            attach_evidence_contract=b["attach_evidence_reference_contract"],
        ),
    )
