"""Command-line contract for the automatic AI analysis scheduler."""
from __future__ import annotations

import argparse
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SchedulerCliDefaults:
    db: Path
    harness_db: Path
    prompt_dir: Path
    analysis_dir: Path
    pcap_analysis_dir: Path
    rollup_dir: Path
    agent_memory_dir: Path
    shared_memory_file: Path
    asset_inventory_file: Path
    incident_evidence_dir: Path
    incident_evidence_config: Path
    investigation_pivot_dir: Path
    live_osquery_config: Path
    disagreement_adjudicator_prompt: Path
    ai_settings: Path
    investigation_harness_policy: Path
    detection_playbooks: Path
    investigation_skills: Path
    lock: Path
    drain: Path
    wake: Path
    levels: str
    model: str
    max_prompt_bytes: int
    portal_wake: Path
    alert_store_url: str


@dataclass(frozen=True)
class SchedulerCliPolicy:
    controlled_alert_id: re.Pattern[str]
    controlled_dispatch_id: re.Pattern[str]
    stable_group_key_valid: Callable[[object], bool]
    stable_group_key_max_bytes: int


def _add_runtime_paths(
    parser: argparse.ArgumentParser,
    defaults: SchedulerCliDefaults,
) -> None:
    parser.add_argument("--db", type=Path, default=defaults.db, help="Path to alert-store SQLite DB")
    parser.add_argument(
        "--harness-db", type=Path, default=defaults.harness_db,
        help="Path to the investigation-harness SQLite DB used for crash reconciliation",
    )
    parser.add_argument("--prompt-dir", type=Path, default=defaults.prompt_dir, help="Prompt package directory")
    parser.add_argument("--analysis-dir", type=Path, default=defaults.analysis_dir, help="AI analysis output directory")
    parser.add_argument(
        "--prior-analysis-dir", type=Path, default=defaults.analysis_dir,
        help="Frozen prior AI analysis directory used as prompt context",
    )
    parser.add_argument("--pcap-analysis-dir", type=Path, default=defaults.pcap_analysis_dir, help="Parsed PCAP evidence directory")
    parser.add_argument("--rollup-dir", type=Path, default=defaults.rollup_dir, help="Frozen daily-rollup context directory")
    parser.add_argument("--agent-memory-dir", type=Path, default=defaults.agent_memory_dir, help="Frozen role-specific agent-memory directory")
    parser.add_argument("--shared-memory-file", type=Path, default=defaults.shared_memory_file, help="Frozen shared agent-memory file")
    parser.add_argument("--asset-inventory-file", type=Path, default=defaults.asset_inventory_file, help="Frozen asset inventory export")
    parser.add_argument("--incident-evidence-dir", type=Path, default=defaults.incident_evidence_dir, help="Restricted Security Onion incident evidence directory")
    parser.add_argument("--incident-evidence-config", type=Path, default=defaults.incident_evidence_config, help="Restricted relay evidence transport config")
    parser.add_argument(
        "--investigation-pivot-dir", type=Path,
        default=defaults.investigation_pivot_dir,
        help="Directory for restricted dynamic-investigation pivot artifacts",
    )
    parser.add_argument(
        "--live-osquery-config", type=Path, default=defaults.live_osquery_config,
        help="Live OSQuery capability configuration",
    )
    parser.add_argument(
        "--disagreement-adjudicator-prompt-file", type=Path,
        default=defaults.disagreement_adjudicator_prompt,
        help="Bounded disagreement-adjudicator system prompt",
    )
    parser.add_argument("--ai-settings-file", type=Path, default=defaults.ai_settings, help="AI model routing settings JSON")
    parser.add_argument(
        "--investigation-harness-policy", type=Path,
        default=defaults.investigation_harness_policy,
        help="Versioned Onion Sentinel investigation harness policy",
    )
    parser.add_argument(
        "--detection-playbooks", type=Path, default=defaults.detection_playbooks,
        help="Deterministic detection validation playbooks",
    )
    parser.add_argument(
        "--investigation-skills", type=Path, default=defaults.investigation_skills,
        help="Versioned read-only investigation skill registry",
    )


def _add_scheduler_execution_policy(
    parser: argparse.ArgumentParser,
    defaults: SchedulerCliDefaults,
) -> None:
    parser.add_argument(
        "--provider-lane", choices=("any", "ollama", "cli"), default="any",
        help="Only claim jobs assigned to this inference provider",
    )
    parser.add_argument("--lock-file", type=Path, default=defaults.lock, help="Non-overlap lock file")
    parser.add_argument(
        "--drain-file", type=Path, default=defaults.drain,
        help=(
            "Owner-only regular-file maintenance marker; when present, finish "
            "the current durable job and claim no additional work"
        ),
    )
    parser.add_argument("--wake-file", type=Path, default=defaults.wake, help="Consumable launchd wake marker")
    parser.add_argument("--levels", default=defaults.levels, help="Comma-separated triage levels to analyze")
    parser.add_argument("--hours", type=int, default=87600, help="Lookback window for eligible alerts")
    parser.add_argument(
        "--max-per-run", type=int, default=0,
        help="Maximum unique alert groups to analyze per scheduler run; 0 drains the queue until no eligible alerts remain",
    )


def _add_controlled_identity_policy(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--only-group-id", default="",
        help=(
            "Process only one exact 20-hex stable detection group. Controlled "
            "runs must also supply --only-alert-id, --only-stable-group-key, "
            "and --only-dispatch-id."
        ),
    )
    parser.add_argument(
        "--only-alert-id", default="",
        help=(
            "Require the claimed durable payload to contain this exact bounded "
            "Security Onion/Elastic alert ID. Requires --only-group-id and "
            "--only-stable-group-key and --only-dispatch-id."
        ),
    )
    parser.add_argument(
        "--only-stable-group-key", default="",
        help=(
            "Require the claimed durable payload to contain this exact bounded "
            "stable group key. Requires every other --only-* identity field."
        ),
    )
    parser.add_argument(
        "--only-dispatch-id", default="",
        help=(
            "Require the claimed durable payload to contain this exact "
            "64-character lowercase SHA-256 dispatch ID. Requires "
            "--only-group-id, --only-alert-id, and --only-stable-group-key."
        ),
    )


def _add_analysis_policy(
    parser: argparse.ArgumentParser,
    defaults: SchedulerCliDefaults,
) -> None:
    parser.add_argument("--related-limit", type=int, default=8, help="Related alert count passed to prompt builder")
    parser.add_argument("--correlation-limit", type=int, default=8, help="Scored correlation candidates passed to prompt builder")
    parser.add_argument("--correlation-min-score", type=int, default=15, help="Minimum deterministic correlation score")
    parser.add_argument("--model", default=defaults.model, help="Optional Ollama model override; defaults to Settings page AI model routing config")
    parser.add_argument("--timeout", type=int, default=600, help="Ollama request timeout in seconds")
    parser.add_argument(
        "--max-prompt-bytes", type=int, default=defaults.max_prompt_bytes,
        help="Hard byte ceiling for each generated AI prompt package",
    )


def _add_scheduler_output_policy(
    parser: argparse.ArgumentParser,
    defaults: SchedulerCliDefaults,
) -> None:
    parser.add_argument("--portal-wake-file", type=Path, default=defaults.portal_wake, help="Wake file for the independent dashboard refresh worker")
    parser.add_argument("--no-portal-refresh", action="store_true", help="Do not signal the independent dashboard refresh worker")
    parser.add_argument("--alert-store-url", default=defaults.alert_store_url, help="Alert-store URL for durable AI job status")
    parser.add_argument("--include-tests", action="store_true", help="Allow test/validation alert IDs")
    parser.add_argument("--dry-run", action="store_true", help="Print the selected alert without calling Ollama")


def _add_scheduler_policy(
    parser: argparse.ArgumentParser,
    defaults: SchedulerCliDefaults,
) -> None:
    _add_scheduler_execution_policy(parser, defaults)
    _add_controlled_identity_policy(parser)
    _add_analysis_policy(parser, defaults)
    _add_scheduler_output_policy(parser, defaults)


def _validate_numeric_args(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
) -> None:
    if args.hours <= 0:
        parser.error("--hours must be positive")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.max_prompt_bytes < 256 * 1024:
        parser.error("--max-prompt-bytes must be at least 262144")
    if args.max_per_run < 0:
        parser.error("--max-per-run must be zero or positive")


def _normalize_controlled_identity(args: argparse.Namespace) -> None:
    args.only_group_id = str(args.only_group_id or "").strip().lower()
    args.only_alert_id = str(args.only_alert_id or "").strip()
    args.only_stable_group_key = str(args.only_stable_group_key or "")
    args.only_dispatch_id = str(args.only_dispatch_id or "").strip()


def _validate_controlled_identity_completeness(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
) -> None:
    controlled_identity = (
        bool(args.only_group_id), bool(args.only_alert_id),
        bool(args.only_stable_group_key), bool(args.only_dispatch_id),
    )
    if any(controlled_identity) and not all(controlled_identity):
        parser.error(
            "--only-group-id, --only-alert-id, --only-stable-group-key, "
            "and --only-dispatch-id must be supplied together"
        )


def _validate_controlled_group_id(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
) -> None:
    if args.only_group_id and not re.fullmatch(r"[a-f0-9]{20}", args.only_group_id):
        parser.error("--only-group-id must be one exact 20-hex stable group id")


def _validate_controlled_alert_id(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    policy: SchedulerCliPolicy,
) -> None:
    if args.only_alert_id and not policy.controlled_alert_id.fullmatch(args.only_alert_id):
        parser.error("--only-alert-id must be one bounded Security Onion/Elastic alert ID")


def _validate_controlled_stable_group_key(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    policy: SchedulerCliPolicy,
) -> None:
    if args.only_stable_group_key and not policy.stable_group_key_valid(args.only_stable_group_key):
        parser.error(
            "--only-stable-group-key must be non-empty valid UTF-8, contain "
            "no NUL, and be no longer than "
            f"{policy.stable_group_key_max_bytes} bytes"
        )


def _validate_controlled_dispatch_id(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    policy: SchedulerCliPolicy,
) -> None:
    if args.only_dispatch_id and not policy.controlled_dispatch_id.fullmatch(args.only_dispatch_id):
        parser.error(
            "--only-dispatch-id must be one exact 64-character lowercase "
            "SHA-256 hex digest"
        )


def _validate_controlled_identity(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    policy: SchedulerCliPolicy,
) -> None:
    _validate_controlled_identity_completeness(parser, args)
    _validate_controlled_group_id(parser, args)
    _validate_controlled_alert_id(parser, args, policy)
    _validate_controlled_stable_group_key(parser, args, policy)
    _validate_controlled_dispatch_id(parser, args, policy)


def _validate_correlation_args(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
) -> None:
    if args.correlation_limit <= 0:
        parser.error("--correlation-limit must be positive")
    if args.correlation_min_score < 0 or args.correlation_min_score > 100:
        parser.error("--correlation-min-score must be between 0 and 100")


def _validate_args(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    policy: SchedulerCliPolicy,
) -> argparse.Namespace:
    _validate_numeric_args(parser, args)
    _normalize_controlled_identity(args)
    _validate_controlled_identity(parser, args, policy)
    _validate_correlation_args(parser, args)
    return args


def parse_scheduler_args(
    defaults: SchedulerCliDefaults,
    policy: SchedulerCliPolicy,
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    """Parse and validate the stable launchd-facing scheduler CLI."""
    parser = argparse.ArgumentParser(
        description="Analyze the next eligible SOC alert using local AI"
    )
    _add_runtime_paths(parser, defaults)
    _add_scheduler_policy(parser, defaults)
    return _validate_args(parser, parser.parse_args(argv), policy)
