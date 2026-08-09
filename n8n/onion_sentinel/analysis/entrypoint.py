"""Command-line contract for the local Onion Sentinel analysis runner."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Mapping, Sequence


@dataclass(frozen=True)
class Defaults:
    prompt_dir: Path
    out_dir: Path
    ai_settings_file: Path
    harness_policy: Path
    harness_db: Path
    system_prompt_file: Path
    second_opinion_prompt_file: Path
    adjudicator_prompt_file: Path
    live_osquery_config: Path
    incident_evidence_config: Path
    investigation_pivot_dir: Path
    max_response_bytes: int
    max_prompt_bytes: int


def _add_initial_paths(parser: argparse.ArgumentParser, defaults: Defaults) -> None:
    parser.add_argument("--prompt-package", type=Path, help="Prompt package JSON to analyze")
    parser.add_argument("--prompt-dir", type=Path, default=defaults.prompt_dir, help="Directory containing prompt packages")
    parser.add_argument("--out-dir", type=Path, default=defaults.out_dir, help="Directory for AI analysis JSON/Markdown output")
    parser.add_argument("--ai-settings-file", type=Path, default=defaults.ai_settings_file, help="AI model routing settings JSON")
    parser.add_argument("--investigation-harness-policy", type=Path, default=defaults.harness_policy, help="Versioned Onion Sentinel investigation harness policy")
    parser.add_argument("--investigation-harness-db", type=Path, default=defaults.harness_db, help="Owner-only durable investigation harness event store")


def _add_evidence_paths(parser: argparse.ArgumentParser, defaults: Defaults) -> None:
    parser.add_argument("--system-prompt-file", type=Path, default=defaults.system_prompt_file, help="Editable SOC Analyst system prompt file")
    parser.add_argument("--second-opinion-prompt-file", type=Path, default=defaults.second_opinion_prompt_file, help="Independent second-opinion system prompt file")
    parser.add_argument("--disagreement-adjudicator-prompt-file", type=Path, default=defaults.adjudicator_prompt_file, help="Bounded shadow-mode disagreement adjudicator system prompt file")
    parser.add_argument("--live-osquery-config", type=Path, default=defaults.live_osquery_config, help="Explicit live OSQuery capability configuration")
    parser.add_argument("--incident-evidence-config", type=Path, default=defaults.incident_evidence_config, help="Explicit restricted read-only Relay evidence transport config")
    parser.add_argument("--investigation-pivot-dir", type=Path, default=defaults.investigation_pivot_dir, help="Directory for restricted dynamic-investigation pivot artifacts")


def _add_model_controls(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--analysis-mode", choices=("ollama", "cloud", "hybrid"), help="Override configured analysis mode")
    parser.add_argument("--model", help="Override the configured Ollama roster with one model for this invocation")
    parser.add_argument("--ollama-url", help="Override the configured Ollama base URL for this invocation")


def _add_model_response_controls(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-predict-tokens", type=int, default=4096, help="Maximum output tokens for one bounded local analysis")
    parser.add_argument("--temperature", type=float, default=0.1, help="Low temperature keeps SOC analysis repeatable")
    parser.add_argument("--response-json", type=Path, help="Use an existing model response JSON instead of calling Ollama")


def _add_runtime_limits(
    parser: argparse.ArgumentParser,
    defaults: Defaults,
    environment: Mapping[str, str],
) -> None:
    parser.add_argument("--timeout", type=int, default=600, help="Ollama request timeout in seconds")
    parser.add_argument("--max-response-bytes", type=int, default=defaults.max_response_bytes, help="Maximum bytes accepted from one local or cloud model response")
    parser.add_argument("--max-prompt-bytes", type=int, default=defaults.max_prompt_bytes, help="Maximum serialized prompt-package bytes admitted to a model call")


def _add_persistence_controls(
    parser: argparse.ArgumentParser,
    environment: Mapping[str, str],
) -> None:
    parser.add_argument("--alert-store-url", default=environment.get("ALERT_STORE_URL", "http://127.0.0.1:8787"), help="Alert-store URL for durable analysis indexing")
    parser.add_argument("--reanalysis-attempt-id", default="", help="Non-secret immutable Incident Responder lease fingerprint")
    parser.add_argument("--flush-index-only", action="store_true", help="Publish deferred analysis indexes and exit without invoking a model")
    parser.add_argument("--stdout", action="store_true", help="Print paths and response JSON after writing files")


def _add_generation(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--generate-prompt", action="store_true", help="Generate a fresh prompt package before analysis")
    parser.add_argument("--levels", default="critical,high,medium,low,informational", help="Levels passed to prompt generation")
    parser.add_argument("--hours", type=int, default=24, help="Lookback hours passed to prompt generation")
    parser.add_argument("--related-limit", type=int, default=8, help="Related alert limit passed to prompt generation")
    parser.add_argument("--correlation-limit", type=int, default=8, help="Correlation candidate limit passed to prompt generation")
    parser.add_argument("--correlation-min-score", type=int, default=15, help="Minimum deterministic correlation score")


def build_parser(
    defaults: Defaults,
    environment: Mapping[str, str],
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run local AI analysis for a SOC alert prompt package"
    )
    _add_initial_paths(parser, defaults)
    _add_model_controls(parser)
    _add_evidence_paths(parser, defaults)
    _add_runtime_limits(parser, defaults, environment)
    _add_model_response_controls(parser)
    _add_generation(parser)
    _add_persistence_controls(parser, environment)
    return parser


def _validate(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    positive = (
        (args.timeout, "--timeout must be positive"),
        (args.max_predict_tokens, "--max-predict-tokens must be positive"),
        (args.max_response_bytes, "--max-response-bytes must be positive"),
        (args.correlation_limit, "--correlation-limit must be positive"),
    )
    for value, message in positive:
        if value <= 0:
            parser.error(message)
    if args.max_prompt_bytes < 256 * 1024:
        parser.error("--max-prompt-bytes must be at least 262144")
    if not 0 <= args.correlation_min_score <= 100:
        parser.error("--correlation-min-score must be between 0 and 100")
    if args.reanalysis_attempt_id and not re.fullmatch(
        r"ira-[a-f0-9]{40}", args.reanalysis_attempt_id,
    ):
        parser.error("--reanalysis-attempt-id is invalid")


def parse(
    defaults: Defaults,
    environment: Mapping[str, str],
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    parser = build_parser(defaults, environment)
    args = parser.parse_args(argv)
    _validate(parser, args)
    return args
