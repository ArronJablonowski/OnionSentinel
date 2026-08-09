#!/usr/bin/env python3
"""Automatically analyze the next eligible SOC alert with its assigned model.

This wrapper is intended for launchd. Separate provider lanes allow hosted CLI
work to proceed while local Ollama inference is active. Each lane still holds
its own worker lock, while run-local-ai-analysis.py enforces a second host-wide
lock around every Ollama call so local models can never overlap.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import math
import os
import re
import sqlite3
import stat
import tempfile
import time
import urllib.error
import urllib.request
import sys
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from disk_capacity import require_runtime_capacity
from agent_memory import (
    role_memory_file,
    role_prompt_file,
    role_second_opinion_prompt_file,
)
from bounded_http import BoundedHttpError, read_bounded_json
from bounded_process import BoundedProcessError, run_bounded_command
from controlled_evaluation_isolation import (
    ControlledEvaluationIsolationError,
    pin_controlled_tmpdir,
    validate_controlled_incident_evidence_route,
)
from scheduler_cli import (
    SchedulerCliDefaults,
    SchedulerCliPolicy,
    parse_scheduler_args,
)
from scheduler_claim import (
    SchedulerClaimSources,
    acquire_scheduler_claim,
)
from scheduler_execution import (
    SchedulerExecutionSources,
    execute_scheduler_analysis,
)
from scheduler_drain import (
    SchedulerDrainSources,
    SchedulerDrainState,
    select_scheduler_work,
)
from scheduler_job_reporting import (
    ClaimedAiLease,
    ControlledClaimRejected,
    SchedulerReportingSources,
    transition_ai_job_status,
)
from scheduler_outcome import (
    SchedulerOutcomeSources,
    handle_controlled_claim_rejection,
    handle_process_outcome,
    handle_scheduler_exception,
)
from scheduler_indexed_state import (
    indexed_reconcilable_ai_job_ids as load_indexed_reconcilable_ai_job_ids,
    indexed_scheduler_available as indexed_scheduler_state_available,
)
from scheduler_indexed_selection import (
    IndexedSelectionRequest,
    IndexedSelectionSources,
    provider_lane_predicate,
    select_next_indexed_alert,
)
from scheduler_legacy_selection import (
    LegacySelectionRequest,
    LegacySelectionSources,
    select_next_legacy_alert,
)
from scheduler_startup import (
    SchedulerStartupSources,
    initialize_scheduler_run,
    prepare_scheduler_run,
)
from scheduler_settlement import (
    SchedulerSettlement,
    SchedulerSettlementSources,
    settle_scheduler_run,
)
from scheduler_terminal_recovery import (
    TerminalRecoverySources,
    reconcile_terminal_success,
    terminal_success_recovery_candidates as load_terminal_success_recovery_candidates,
)
from scheduler_worker import (
    SchedulerWorkerSources,
    process_scheduler_selection,
)


HOME = Path.home()
DEFAULT_DB = HOME / "n8n-local" / "alert_store_data" / "alerts.sqlite3"
DEFAULT_HARNESS_DB = (
    HOME / "n8n-local" / "alert_store_data" / "investigation-harness.sqlite3"
)
DEFAULT_PROMPT_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-prompts"
DEFAULT_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-analysis"
DEFAULT_PCAP_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "pcap-analysis"
DEFAULT_ROLLUP_DIR = HOME / "n8n-local" / "soc-alerts" / "daily-rollups"
DEFAULT_AGENT_MEMORY_DIR = HOME / "n8n-local" / "soc-alerts" / "agent-memory"
DEFAULT_SHARED_MEMORY_FILE = (
    DEFAULT_AGENT_MEMORY_DIR / "shared-agent-memory.md"
)
DEFAULT_ASSET_INVENTORY_FILE = (
    HOME / "n8n-local" / "config" / "asset_inventory.database-export.json"
)
DEFAULT_LIVE_OSQUERY_CONFIG = (
    HOME / "n8n-local" / "config" / "live-osquery.json"
)
DEFAULT_DISAGREEMENT_ADJUDICATOR_PROMPT = (
    HOME / "n8n-local" / "config" / "disagreement_adjudicator_system_prompt.md"
)
DEFAULT_INVESTIGATION_PIVOT_DIR = (
    HOME / "n8n-local" / "soc-alerts" / "investigation-pivots"
)
DEFAULT_INCIDENT_EVIDENCE_DIR = HOME / "n8n-local" / "soc-alerts" / "incident-evidence"
DEFAULT_INCIDENT_EVIDENCE_CONFIG = HOME / "n8n-local" / "config" / "incident-evidence.json"
DEFAULT_AI_SETTINGS = HOME / "n8n-local" / "config" / "ai_model_settings.json"
DEFAULT_INVESTIGATION_HARNESS_POLICY = (
    HOME / "n8n-local" / "config" / "investigation_harness_policy.json"
)
DEFAULT_DETECTION_PLAYBOOKS = (
    HOME / "n8n-local" / "config" / "detection_playbooks.json"
)
DEFAULT_INVESTIGATION_SKILLS = (
    HOME / "n8n-local" / "config" / "investigation_skills.json"
)
DEFAULT_LOCK = HOME / "n8n-local" / "run" / "ai-analysis.lock"
DEFAULT_DRAIN = HOME / "n8n-local" / "run" / "ai-analysis-maintenance-drain"
DEFAULT_WAKE = Path(os.environ.get(
    "AI_ANALYSIS_WAKE_PATH",
    HOME / "n8n-local" / "run" / "ai-analysis.wake",
))
DEFAULT_DASHBOARD_WAKE = Path(os.environ.get(
    "SOC_DASHBOARD_WAKE_PATH",
    HOME / "n8n-local" / "run" / "dashboard-refresh.wake",
))
DEFAULT_MODEL = os.environ.get("SOC_AI_MODEL", "")
DEFAULT_LEVELS = "critical,high,medium,low,informational"
SEVERITY_PRIORITY = ("critical", "high", "medium", "low", "informational")
ELIGIBLE_FILTER_STATUSES = ("accepted", "escalated", "unknown", "suppressed")
TEST_PREFIXES = ("phase%", "config-%", "internal-test-%", "sqlite-%", "policy-%", "codex-%")
DEFAULT_MAX_PROMPT_BYTES = max(256 * 1024, int(os.environ.get("SOC_AI_MAX_PROMPT_PACKAGE_BYTES", 4 * 1024 * 1024)))
CODEX_CLI_INITIAL_PROMPT_PACKAGE_BYTES = 320 * 1024
CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES = 384 * 1024
DEFAULT_MAX_CHILD_STDOUT_BYTES = max(1024 * 1024, int(os.environ.get("SOC_AI_SCHEDULER_MAX_STDOUT_BYTES", 16 * 1024 * 1024)))
DEFAULT_MAX_CHILD_STDERR_BYTES = max(256 * 1024, int(os.environ.get("SOC_AI_SCHEDULER_MAX_STDERR_BYTES", 2 * 1024 * 1024)))
DEFAULT_MAX_CONTROL_RESPONSE_BYTES = 1024 * 1024
MAX_CONTROLLED_RESULT_SPOOL_BYTES = 16 * 1024 * 1024
CONTROLLED_RESULT_SUBMISSION_ATTEMPTS = 3
CONTROLLED_EXACT_CLAIM_ATTEMPTS = 3
CONTROLLED_RESULT_SUBMISSION_INDETERMINATE = (
    "controlled analysis result submission remains indeterminate"
)
CONTROLLED_SELECTED_JOB_FAILURE_EXIT_CODE = 1
MAX_AI_SETTINGS_BYTES = 256 * 1024
CODEX_CLI_REASONING_EFFORTS = frozenset({"low", "medium", "high", "xhigh"})
CODEX_CLI_MODEL_CATALOG = frozenset({
    "gpt-5.5",
    "gpt-5.6-sol",
    "gpt-5.6-terra",
    "gpt-5.6-luna",
})
AGENT_ROLES = (
    "soc-analyst",
    "incident-responder",
    "siem-engineer",
    "cyber-threat-intel",
    "threat-hunter",
)
CONTROLLED_ALERT_ID_RE = re.compile(r"[A-Za-z0-9._:@=-]{1,256}")
CONTROLLED_DISPATCH_ID_RE = re.compile(r"[a-f0-9]{64}")
CONTROLLED_RELEASE_ID_RE = re.compile(r"[a-f0-9]{40}")
CONTROLLED_MODEL_ROUTE_RE = re.compile(
    r"codex-cli:(?:gpt-5\.5|gpt-5\.6-(?:sol|terra|luna)):"
    r"(?:low|medium|high|xhigh)"
)
CONTROLLED_COHORT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}")
CONTROLLED_LEASE_TOKEN_RE = re.compile(
    r"[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-"
    r"[89ab][a-f0-9]{3}-[a-f0-9]{12}"
)
CONTROLLED_ANALYSIS_ID_RE = re.compile(r"[a-z0-9_-]{8,120}")
CONTROLLED_STABLE_GROUP_KEY_MAX_LENGTH = 2048
CONTROLLED_EVALUATION_TOKEN_ENV = "ONION_SENTINEL_EVALUATION_TOKEN"
CONTROLLED_EVALUATION_TOKEN_HEADER = (
    "X-Onion-Sentinel-Evaluation-Token"
)
CONTROLLED_EVALUATION_TOKEN_RE = re.compile(r"[a-f0-9]{64}")
CONTROLLED_JS_WHITESPACE_CLASS = (
    r"\u0009-\u000d\u0020\u00a0\u1680\u2000-\u200a"
    r"\u2028\u2029\u202f\u205f\u3000\ufeff"
)
CONTROLLED_TIMESTAMP_SEPARATOR_RE = re.compile(
    rf"(\d{{4}}-\d{{2}}-\d{{2}})"
    rf"(?:T|[{CONTROLLED_JS_WHITESPACE_CLASS}]+)"
    rf"(?=\d{{2}}:\d{{2}}:\d{{2}})"
)

_STRICT_AI_SETTINGS_MODULE: Any | None = None
CONTROLLED_TIMESTAMP_RE = re.compile(
    rf"(?<![A-Za-z0-9_])\d{{4}}-\d{{2}}-\d{{2}}"
    rf"(?:T|[{CONTROLLED_JS_WHITESPACE_CLASS}]+)"
    rf"\d{{2}}:\d{{2}}:\d{{2}}"
    rf"(?:\.\d+)?(?:Z|[+-]\d{{2}}:?\d{{2}})?"
    rf"(?![A-Za-z0-9_])",
)
RUNTIME_RELEASE_ENV_KEY = "ONION_SENTINEL_RELEASE_ID"
DEFAULT_RUNTIME_ENV_PATH = HOME / "n8n-local" / ".env"
MAX_RUNTIME_ENV_BYTES = 1024 * 1024
# Keep one busy provider lane from starving another analysis role. This is
# deliberately shorter than the 30-minute operational SLO so an eligible job
# receives a scheduling opportunity before the stalled-worker alarm fires.
AI_JOB_FAIRNESS_AGE_SECONDS = 15 * 60
_CONTROLLED_EVALUATION_TOKEN = ""


def javascript_trim(value: str) -> str:
    """Mirror ECMAScript String.prototype.trim(), not Python str.strip()."""
    return re.sub(
        rf"^[{CONTROLLED_JS_WHITESPACE_CLASS}]+"
        rf"|[{CONTROLLED_JS_WHITESPACE_CLASS}]+$",
        "",
        value,
    )


def javascript_string_value(value: object) -> str:
    """Mirror String(value ?? '') for bounded JSON metadata fields."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        try:
            number = float(value)
        except OverflowError:
            number = math.inf if value > 0 else -math.inf
        if math.isnan(number):
            return "NaN"
        if math.isinf(number):
            return "Infinity" if number > 0 else "-Infinity"
        return javascript_json_number(number)
    if isinstance(value, list):
        return ",".join(
            javascript_string_value(item) if item is not None else ""
            for item in value
        )
    if isinstance(value, dict):
        return "[object Object]"
    return str(value)


def javascript_safe_string(value: object, max_length: int) -> str:
    """Project safeString() through node-sqlite3's stored-text encoding."""
    collapsed = re.sub(
        rf"[{CONTROLLED_JS_WHITESPACE_CLASS}]+",
        " ",
        javascript_trim(javascript_string_value(value)),
    )
    encoded = collapsed.encode("utf-16-le", errors="surrogatepass")
    sliced = encoded[: max(0, int(max_length)) * 2].decode(
        "utf-16-le",
        errors="surrogatepass",
    )
    # UTF-16 slice() may split a non-BMP character. Node's SQLite binding
    # persists each resulting lone surrogate as the Unicode replacement
    # character, which is what a read-only terminal proof observes.
    return "".join(
        "\ufffd" if 0xD800 <= ord(character) <= 0xDFFF else character
        for character in sliced
    )


def javascript_truthy(value: object) -> bool:
    """Return JavaScript truthiness for JSON-compatible values."""
    if value is None or value is False:
        return False
    if isinstance(value, (int, float)):
        try:
            number = float(value)
        except OverflowError:
            number = math.inf if value > 0 else -math.inf
        if number == 0 or math.isnan(number):
            return False
    if isinstance(value, str) and value == "":
        return False
    return True


def controlled_evaluation_runtime(
    args: argparse.Namespace,
) -> Path | None:
    """Validate the one-member, owner-only evaluation worker boundary."""
    mode_value = str(
        os.environ.get("ONION_SENTINEL_EVALUATION_MODE") or ""
    ).strip()
    if mode_value not in {"", "0", "1"}:
        raise SystemExit(
            "ONION_SENTINEL_EVALUATION_MODE must be unset, 0, or 1"
        )
    if mode_value != "1":
        return None
    if str(getattr(args, "model", "") or "").strip():
        raise SystemExit(
            "controlled evaluation forbids --model and SOC_AI_MODEL overrides"
        )
    raw_root = str(
        os.environ.get("ONION_SENTINEL_EVALUATION_RUNTIME_DIR") or ""
    ).strip()
    try:
        root = Path(raw_root)
        metadata = root.lstat()
        resolved_root = root.resolve(strict=True)
        expected_parent = (
            HOME / "n8n-local" / "harness-evaluations"
        ).resolve(strict=True)
        resolved_root.relative_to(expected_parent)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise SystemExit(
            f"controlled evaluation runtime directory is unsafe: {exc}"
        ) from exc
    try:
        alert_store_origin = urlparse(args.alert_store_url)
        alert_store_port = alert_store_origin.port
    except ValueError as exc:
        raise SystemExit(
            "controlled evaluation alert-store origin is unsafe"
        ) from exc
    controlled_identity = (
        args.only_group_id,
        args.only_alert_id,
        args.only_stable_group_key,
        args.only_dispatch_id,
    )
    if (
        not raw_root
        or not root.is_absolute()
        or resolved_root != root
        or root.is_symlink()
        or not root.is_dir()
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or str(
            os.environ.get("ONION_SENTINEL_EVALUATION_FREEZE_MEMORY")
            or ""
        ).strip() != "1"
        or not CONTROLLED_RELEASE_ID_RE.fullmatch(
            str(os.environ.get(RUNTIME_RELEASE_ENV_KEY) or "")
        )
        or not CONTROLLED_EVALUATION_TOKEN_RE.fullmatch(
            str(
                os.environ.get(CONTROLLED_EVALUATION_TOKEN_ENV)
                or ""
            ).strip()
        )
        or not all(controlled_identity)
        or args.max_per_run != 1
        or alert_store_origin.scheme != "http"
        or alert_store_origin.hostname != "127.0.0.1"
        or alert_store_port is None
        or alert_store_port < 1
        or alert_store_port == 8787
        or alert_store_origin.username is not None
        or alert_store_origin.password is not None
        or alert_store_origin.path not in {"", "/"}
        or alert_store_origin.params
        or alert_store_origin.query
        or alert_store_origin.fragment
    ):
        raise SystemExit(
            "controlled evaluation requires one exact frozen job, an "
            "owner-only runtime, frozen memory, a loopback alert store, "
            "an exact release ID, and an ephemeral authorization token"
        )
    try:
        pin_controlled_tmpdir(resolved_root)
    except ControlledEvaluationIsolationError as exc:
        raise SystemExit(f"controlled evaluation {exc}") from exc

    def owner_private_path(
        candidate: Path,
        *,
        label: str,
        kind: str,
        inside_runtime: bool = True,
    ) -> Path:
        candidate = candidate.expanduser()
        try:
            candidate_metadata = candidate.lstat()
            resolved_candidate = candidate.resolve(strict=True)
            if inside_runtime:
                resolved_candidate.relative_to(resolved_root)
        except (FileNotFoundError, OSError, ValueError) as exc:
            location = " inside the evaluation runtime" if inside_runtime else ""
            raise SystemExit(
                f"controlled evaluation {label} must be a canonical "
                f"owner-private {kind}{location}"
            ) from exc
        expected_kind = (
            candidate.is_file() if kind == "file" else candidate.is_dir()
        )
        if (
            not candidate.is_absolute()
            or resolved_candidate != candidate
            or candidate.is_symlink()
            or not expected_kind
            or candidate_metadata.st_uid != os.getuid()
            or stat.S_IMODE(candidate_metadata.st_mode) & 0o077
        ):
            location = " inside the evaluation runtime" if inside_runtime else ""
            raise SystemExit(
                f"controlled evaluation {label} must be a canonical "
                f"owner-private {kind}{location}"
            )
        return resolved_candidate

    def owner_private_mutable_file(candidate: Path, *, label: str) -> None:
        candidate = candidate.expanduser()
        try:
            resolved_candidate = candidate.resolve(strict=False)
            resolved_candidate.relative_to(resolved_root)
        except (OSError, ValueError) as exc:
            raise SystemExit(
                f"controlled evaluation {label} must stay inside its "
                "runtime directory"
            ) from exc
        if not candidate.is_absolute() or resolved_candidate != candidate:
            raise SystemExit(
                f"controlled evaluation {label} must stay inside its "
                "runtime directory"
            )
        if candidate.exists():
            owner_private_path(candidate, label=label, kind="file")
            return
        owner_private_path(candidate.parent, label=f"{label} parent", kind="directory")

    context_directories = {
        "prompt directory": args.prompt_dir,
        "analysis output directory": args.analysis_dir,
        "prior-analysis directory": args.prior_analysis_dir,
        "PCAP analysis directory": args.pcap_analysis_dir,
        "rollup directory": args.rollup_dir,
        "agent-memory directory": args.agent_memory_dir,
        "incident-evidence directory": args.incident_evidence_dir,
        "investigation-pivot directory": args.investigation_pivot_dir,
    }
    for label, candidate in context_directories.items():
        owner_private_path(candidate, label=label, kind="directory")
    if args.analysis_dir.resolve() == args.prior_analysis_dir.resolve():
        raise SystemExit(
            "controlled evaluation prior analysis must be frozen separately "
            "from analysis output"
        )

    config_dir = args.ai_settings_file.parent
    runtime_read_files = {
        "clone database": args.db,
        "AI settings": args.ai_settings_file,
        "harness policy": args.investigation_harness_policy,
        "detection playbooks": args.detection_playbooks,
        "investigation skills": args.investigation_skills,
        "shared memory": args.shared_memory_file,
        "asset inventory": args.asset_inventory_file,
        "live OSQuery config": args.live_osquery_config,
        "disagreement prompt": args.disagreement_adjudicator_prompt_file,
        "SOC Analyst prompt": role_prompt_file(config_dir, "soc-analyst"),
        "SOC Analyst reviewer prompt": role_second_opinion_prompt_file(
            config_dir,
            "soc-analyst",
        ),
        "Incident Responder prompt": role_prompt_file(
            config_dir,
            "incident-responder",
        ),
        "Incident Responder reviewer prompt": role_second_opinion_prompt_file(
            config_dir,
            "incident-responder",
        ),
        "SOC Analyst frozen memory": role_memory_file(
            args.agent_memory_dir,
            "soc-analyst",
        ),
        "Incident Responder frozen memory": role_memory_file(
            args.agent_memory_dir,
            "incident-responder",
        ),
    }
    for label, candidate in runtime_read_files.items():
        owner_private_path(candidate, label=label, kind="file")

    try:
        validate_controlled_incident_evidence_route(
            args.incident_evidence_config,
            resolved_root,
            expected_home=HOME,
        )
    except ControlledEvaluationIsolationError as exc:
        raise SystemExit(
            f"controlled evaluation {exc}"
        ) from exc

    try:
        live_osquery_document = json.loads(
            args.live_osquery_config.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(
            "controlled evaluation live OSQuery config is invalid"
        ) from exc
    if (
        not isinstance(live_osquery_document, dict)
        or live_osquery_document.get("enabled") is not False
    ):
        raise SystemExit(
            "controlled evaluation requires live OSQuery to be explicitly disabled"
        )

    for label, candidate in {
        "lock file": args.lock_file,
        "worker wake file": args.wake_file,
        "dashboard wake file": args.portal_wake_file,
    }.items():
        owner_private_mutable_file(candidate, label=label)
    return resolved_root


def valid_controlled_stable_group_key(value: object) -> bool:
    """Return whether a frozen group key has one safe bounded UTF-8 encoding."""
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return len(encoded) <= CONTROLLED_STABLE_GROUP_KEY_MAX_LENGTH


def controlled_canonical_digest(value: object, *, ensure_ascii: bool = True) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=ensure_ascii,
        ).encode("utf-8")
    ).hexdigest()


def consume_controlled_evaluation_token(enabled: bool) -> str:
    """Keep the mutation credential out of unrelated child environments."""
    global _CONTROLLED_EVALUATION_TOKEN
    supplied = str(
        os.environ.pop(CONTROLLED_EVALUATION_TOKEN_ENV, "") or ""
    ).strip()
    if enabled:
        if not CONTROLLED_EVALUATION_TOKEN_RE.fullmatch(supplied):
            raise SystemExit(
                "controlled evaluation requires an exact ephemeral "
                "authorization token"
            )
        _CONTROLLED_EVALUATION_TOKEN = supplied
    else:
        _CONTROLLED_EVALUATION_TOKEN = ""
    return _CONTROLLED_EVALUATION_TOKEN


def alert_store_mutation_headers(*, user_agent: str = "") -> dict[str, str]:
    """Attach the ephemeral token only inside controlled evaluation mode."""
    headers = {"Content-Type": "application/json"}
    if user_agent:
        headers["User-Agent"] = user_agent
    supplied_token = str(
        os.environ.get(CONTROLLED_EVALUATION_TOKEN_ENV) or ""
    ).strip()
    evaluation_token = (
        supplied_token
        if CONTROLLED_EVALUATION_TOKEN_RE.fullmatch(supplied_token)
        else _CONTROLLED_EVALUATION_TOKEN
    )
    if (
        str(
            os.environ.get("ONION_SENTINEL_EVALUATION_MODE") or ""
        ).strip()
        == "1"
        and CONTROLLED_EVALUATION_TOKEN_RE.fullmatch(evaluation_token)
    ):
        headers[CONTROLLED_EVALUATION_TOKEN_HEADER] = evaluation_token
    return headers


def controlled_parse_javascript_timestamp(
    value: str,
) -> tuple[dt.datetime, int]:
    """Parse ISO fields that JavaScript Date normalizes beyond fromisoformat."""
    matched = re.fullmatch(
        r"(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-"
        r"(?P<day>[0-9]{2})T(?P<hour>[0-9]{2}):"
        r"(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
        r"(?:\.(?P<fraction>[0-9]+))?"
        r"(?P<zone>Z|[+-][0-9]{2}:?[0-9]{2})",
        value,
        re.ASCII,
    )
    if not matched:
        raise ValueError("timestamp does not match JavaScript ISO fields")
    year = int(matched.group("year"))
    month = int(matched.group("month"))
    day = int(matched.group("day"))
    hour = int(matched.group("hour"))
    minute = int(matched.group("minute"))
    second = int(matched.group("second"))
    fraction = matched.group("fraction") or ""
    if (
        month not in range(1, 13)
        or day not in range(1, 32)
        or hour not in range(0, 25)
        or minute not in range(0, 60)
        or second not in range(0, 60)
        or (
            hour == 24
            and (
                minute
                or second
                or any(character != "0" for character in fraction)
            )
        )
    ):
        raise ValueError("timestamp fields are outside JavaScript Date bounds")
    zone = matched.group("zone")
    if zone == "Z":
        timezone = dt.timezone.utc
    else:
        zone_hours = int(zone[1:3])
        zone_minutes = int(zone[-2:])
        if zone_hours > 23 or zone_minutes > 59:
            raise ValueError("timestamp offset is outside JavaScript bounds")
        direction = 1 if zone[0] == "+" else -1
        timezone = dt.timezone(
            direction
            * dt.timedelta(hours=zone_hours, minutes=zone_minutes)
        )
    # Python datetime cannot represent a local conversion that crosses year
    # zero or 10000. Gregorian calendars and projected timezone rules repeat
    # every 400 years, so shift only these boundary years into its safe range.
    if year <= 1:
        parse_year = year + 400
        year_adjustment = -400
    elif year >= 9999:
        parse_year = year - 400
        year_adjustment = 400
    else:
        parse_year = year
        year_adjustment = 0
    microseconds = int((fraction + "000000")[:6]) if fraction else 0
    parsed = dt.datetime(
        parse_year,
        month,
        1,
        tzinfo=timezone,
    ) + dt.timedelta(
        days=day - 1,
        hours=hour,
        minutes=minute,
        seconds=second,
        microseconds=microseconds,
    )
    return parsed, year_adjustment


def controlled_normalize_timestamp(value: str) -> str | None:
    """Mirror alert-store's normalizeTimestampValue() for stored JSON."""
    if value == "":
        return None
    text = javascript_trim(value)

    def replace_timestamp(match: re.Match[str]) -> str:
        timestamp = match.group(0)
        parseable = CONTROLLED_TIMESTAMP_SEPARATOR_RE.sub(
            r"\1T", timestamp, count=1
        )
        if not re.search(r"(?:Z|[+-]\d{2}:?\d{2})$", parseable):
            parseable = f"{parseable}Z"
        year_adjustment = 0
        try:
            timestamp_year = int(parseable[:4])
            if timestamp_year <= 1 or timestamp_year >= 9999:
                parsed, year_adjustment = (
                    controlled_parse_javascript_timestamp(parseable)
                )
            else:
                parsed = dt.datetime.fromisoformat(
                    parseable[:-1] + "+00:00"
                    if parseable.endswith("Z")
                    else parseable
                )
        except ValueError:
            try:
                parsed, year_adjustment = (
                    controlled_parse_javascript_timestamp(parseable)
                )
            except ValueError:
                return CONTROLLED_TIMESTAMP_SEPARATOR_RE.sub(
                    r"\1  ", timestamp
                )
        try:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            local = parsed.astimezone()
            offset = local.utcoffset()
            if offset is None:
                raise ValueError("timestamp has no UTC offset")
        except (OverflowError, ValueError):
            return CONTROLLED_TIMESTAMP_SEPARATOR_RE.sub(
                r"\1  ", timestamp
            )
        milliseconds = local.microsecond // 1000
        fractional = f".{milliseconds:03d}" if milliseconds else ""
        offset_minutes = int(offset.total_seconds() / 60)
        offset_sign = "+" if offset_minutes >= 0 else "-"
        offset_minutes = abs(offset_minutes)
        return (
            # Node's formatProjectTimestamp() deliberately does not pad
            # getFullYear(), including for historical four-digit inputs.
            f"{local.year + year_adjustment}-"
            f"{local.month:02d}-{local.day:02d}  "
            f"{local.hour:02d}:{local.minute:02d}:{local.second:02d}"
            f"{fractional}{offset_sign}{offset_minutes // 60:02d}:"
            f"{offset_minutes % 60:02d}"
        )

    return CONTROLLED_TIMESTAMP_RE.sub(replace_timestamp, text)


def controlled_normalize_stored_json(value: object) -> object:
    """Mirror alert-store's recursive normalizeJsonTimestamps()."""
    if isinstance(value, str):
        return controlled_normalize_timestamp(value)
    if isinstance(value, list):
        return [
            controlled_normalize_stored_json(item)
            for item in value
        ]
    if isinstance(value, dict):
        return {
            str(key): controlled_normalize_stored_json(item)
            for key, item in value.items()
        }
    return value


def javascript_json_number(value: int | float) -> str:
    """Render a JSON number with ECMAScript's JSON.stringify thresholds."""
    try:
        number = float(value)
    except OverflowError:
        return "null"
    if not math.isfinite(number):
        return "null"
    if number == 0:
        return "0"
    sign = "-" if number < 0 else ""
    representation = repr(abs(number)).lower()
    if "e" in representation:
        mantissa, raw_exponent = representation.split("e", 1)
        exponent = int(raw_exponent)
    else:
        mantissa = representation
        exponent = 0
    if "." in mantissa:
        integer, fraction = mantissa.split(".", 1)
        digits = integer + fraction
        decimal_position = len(integer) + exponent
    else:
        digits = mantissa
        decimal_position = len(mantissa) + exponent
    leading_zero_count = len(digits) - len(digits.lstrip("0"))
    digits = digits.lstrip("0").rstrip("0") or "0"
    decimal_position -= leading_zero_count
    scientific_exponent = decimal_position - 1
    if -6 <= scientific_exponent < 21:
        if decimal_position <= 0:
            rendered = f"0.{('0' * -decimal_position)}{digits}"
        elif decimal_position >= len(digits):
            rendered = digits + ("0" * (decimal_position - len(digits)))
        else:
            rendered = (
                f"{digits[:decimal_position]}."
                f"{digits[decimal_position:]}"
            )
        return sign + rendered
    coefficient = (
        digits
        if len(digits) == 1
        else f"{digits[0]}.{digits[1:]}"
    )
    exponent_sign = "+" if scientific_exponent >= 0 else ""
    return f"{sign}{coefficient}e{exponent_sign}{scientific_exponent}"


def javascript_object_key_order(value: dict[str, object]) -> list[str]:
    """Return JSON.stringify order after canonical Object.fromEntries()."""
    array_indexes: list[tuple[int, str]] = []
    ordinary_keys: list[str] = []
    for key in value:
        if (
            re.fullmatch(r"0|[1-9][0-9]*", key, re.ASCII)
            and int(key) < (2**32 - 1)
        ):
            array_indexes.append((int(key), key))
        else:
            ordinary_keys.append(key)
    array_indexes.sort()
    ordinary_keys.sort(
        key=lambda key: key.encode("utf-16-be", errors="surrogatepass")
    )
    return [key for _, key in array_indexes] + ordinary_keys


def javascript_json_string(value: str) -> str:
    """Use well-formed JSON.stringify escaping while preserving Unicode."""
    encoded = json.dumps(value, ensure_ascii=False)
    return "".join(
        f"\\u{ord(character):04x}"
        if 0xD800 <= ord(character) <= 0xDFFF
        else character
        for character in encoded
    )


def controlled_storage_canonical_json(value: object) -> str:
    """Mirror alert-store canonicalJsonText() for terminal DB proof."""
    normalized = controlled_normalize_stored_json(value)

    def serialize(item: object) -> str:
        if item is None:
            return "null"
        if item is True:
            return "true"
        if item is False:
            return "false"
        if isinstance(item, (int, float)):
            return javascript_json_number(item)
        if isinstance(item, str):
            return javascript_json_string(item)
        if isinstance(item, list):
            return "[" + ",".join(serialize(entry) for entry in item) + "]"
        if isinstance(item, dict):
            keys = javascript_object_key_order(item)
            return (
                "{"
                + ",".join(
                    f"{javascript_json_string(key)}:{serialize(item[key])}"
                    for key in keys
                )
                + "}"
            )
        raise TypeError(
            "controlled stored response contains a non-JSON value"
        )

    return serialize(normalized)


def controlled_storage_canonical_digest(value: object) -> str:
    return hashlib.sha256(
        controlled_storage_canonical_json(value).encode("utf-8")
    ).hexdigest()


def controlled_expected_accepted_fields(
    payload: dict[str, Any],
    response: dict[str, Any],
) -> dict[str, str | None]:
    """Rebuild recordAiAnalysisResult's immutable acceptance projection."""
    payload_model = payload.get("model")
    payload_model_path = payload.get("model_path")
    generated_at = javascript_safe_string(
        payload.get("generated_at"),
        64,
    )
    return {
        # An omitted/empty generated_at is replaced by server time. No
        # immutable spool-to-row proof is possible for that dynamic value.
        "generated_at": generated_at or None,
        "model": javascript_safe_string(
            payload_model
            if javascript_truthy(payload_model)
            else response.get("_analysis_model"),
            200,
        ),
        "model_path": javascript_safe_string(
            payload_model_path
            if javascript_truthy(payload_model_path)
            else response.get("_analysis_model_path"),
            100,
        ),
        "detection_outcome": javascript_safe_string(
            response.get("detection_outcome"),
            100,
        ),
        "bluf": javascript_safe_string(response.get("bluf"), 4000),
        "summary": javascript_safe_string(
            response.get("summary"),
            8000,
        ),
        "confidence": javascript_safe_string(
            response.get("confidence"),
            16,
        ).lower(),
        "artifact_path": javascript_safe_string(
            payload.get("artifact_path"),
            2048,
        ),
        "evidence_hash": javascript_safe_string(
            payload.get("evidence_hash"),
            128,
        ).lower(),
    }


def controlled_accepted_fields_match(
    accepted: sqlite3.Row,
    expected: dict[str, str | None],
) -> bool:
    """Match every immutable field checked by recordAiAnalysisResult replay."""
    expected_generated_at = expected.get("generated_at")
    if not isinstance(expected_generated_at, str):
        return False
    actual_generated_at = javascript_safe_string(
        accepted["generated_at"],
        64,
    )
    if (
        controlled_normalize_timestamp(actual_generated_at)
        != controlled_normalize_timestamp(expected_generated_at)
    ):
        return False
    limits = {
        "model": 200,
        "model_path": 100,
        "detection_outcome": 100,
        "bluf": 4000,
        "summary": 8000,
        "confidence": 16,
        "artifact_path": 2048,
        "evidence_hash": 128,
    }
    for field, limit in limits.items():
        actual = javascript_safe_string(accepted[field], limit)
        expected_value = expected.get(field)
        if field in {"confidence", "evidence_hash"}:
            actual = actual.lower()
        if actual != expected_value:
            return False
    return True


def owner_private_directory(path: Path, runtime_root: Path) -> bool:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        resolved.relative_to(runtime_root)
    except (FileNotFoundError, OSError, ValueError):
        return False
    return bool(
        resolved == path
        and not path.is_symlink()
        and path.is_dir()
        and metadata.st_uid == os.getuid()
        and not (stat.S_IMODE(metadata.st_mode) & 0o077)
    )


def load_owner_private_json(
    path: Path,
    runtime_root: Path,
    *,
    max_bytes: int,
) -> dict[str, Any]:
    """Read one non-symlink owner-only evaluation artifact with a byte cap."""
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(runtime_root)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise RuntimeError(
            "controlled evaluation recovery artifact is unsafe"
        ) from exc
    if resolved != path or path.parent.resolve(strict=True) != path.parent:
        raise RuntimeError(
            "controlled evaluation recovery artifact is not canonical"
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size > max_bytes
        ):
            raise RuntimeError(
                "controlled evaluation recovery artifact must be one "
                "bounded owner-only regular file"
            )
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            payload = json.load(handle)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "controlled evaluation recovery artifact is invalid JSON"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(payload, dict):
        raise RuntimeError(
            "controlled evaluation recovery artifact must contain an object"
        )
    return payload


def post_controlled_recovery_result(
    payload: dict[str, Any],
    alert_store_url: str,
    *,
    attempts: int = CONTROLLED_RESULT_SUBMISSION_ATTEMPTS,
) -> dict[str, Any]:
    """Replay the exact immutable result with bounded immediate retries."""
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    submission_sha256 = hashlib.sha256(body).hexdigest()
    last_error = ""
    for attempt_index in range(max(1, min(int(attempts), 5))):
        if attempt_index:
            time.sleep(0.05 * attempt_index)
        request = urllib.request.Request(
            f"{alert_store_url.rstrip('/')}/analysis/result",
            data=body,
            headers=alert_store_mutation_headers(
                user_agent="Onion-Sentinel-AI-Recovery/1.0",
            ),
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status not in range(200, 300):
                    status_code = int(response.status)
                    detail = (
                        f"analysis result recovery returned HTTP "
                        f"{status_code}"
                    )
                    if status_code == 409:
                        raise RuntimeError(
                            f"{CONTROLLED_RESULT_SUBMISSION_INDETERMINATE}: "
                            f"{detail}"
                        )
                    if (
                        status_code < 500
                        and status_code not in {408, 425, 429}
                    ):
                        raise RuntimeError(detail)
                    last_error = detail
                    continue
                result = read_bounded_json(
                    response,
                    max_bytes=DEFAULT_MAX_CONTROL_RESPONSE_BYTES,
                )
            stored_response_sha256 = str(
                result.get("stored_response_sha256") or ""
            ).lower()
            if (
                result.get("ok") is True
                and str(result.get("analysis_id") or "").lower()
                == str(payload.get("analysis_id") or "").lower()
                and str(result.get("submission_sha256") or "").lower()
                == submission_sha256
                and re.fullmatch(r"[a-f0-9]{64}", stored_response_sha256)
            ):
                return result
            last_error = "analysis result recovery receipt was not exact"
        except urllib.error.HTTPError as exc:
            status_code = int(exc.code)
            exc.close()
            last_error = (
                f"analysis result recovery returned HTTP {status_code}"
            )
            if status_code == 409:
                # Node safeString() can produce a lone surrogate at a UTF-16
                # field limit that SQLite stores as U+FFFD. The original
                # transaction is authoritative but its exact HTTP replay then
                # conflicts. Only the complete terminal DB proof may retire it.
                raise RuntimeError(
                    f"{CONTROLLED_RESULT_SUBMISSION_INDETERMINATE}: "
                    f"{last_error}"
                ) from exc
            if status_code < 500 and status_code not in {408, 425, 429}:
                raise RuntimeError(last_error) from exc
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            BoundedHttpError,
        ) as exc:
            last_error = (
                f"analysis result recovery transport failed: "
                f"{type(exc).__name__}"
            )
    raise RuntimeError(
        f"{CONTROLLED_RESULT_SUBMISSION_INDETERMINATE}: {last_error}"
    )


def validate_controlled_recovery_payload(
    payload: dict[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Bind a spooled result to the frozen scheduler pins and old lease."""
    identity = payload.get("controlled_job")
    response = payload.get("response")
    expected_identity_fields = {
        "job_id",
        "job_type",
        "lease_token",
        "cohort_id",
        "dispatch_id",
        "representative_alert_id",
        "stable_group_id",
        "stable_group_key",
        "agent_role",
        "reanalysis_attempt_id",
        "release_id",
        "expected_assigned_route",
        "expected_reviewer_route",
        "reviewer_required",
    }
    if (
        not isinstance(identity, dict)
        or set(identity) != expected_identity_fields
        or not isinstance(response, dict)
    ):
        raise RuntimeError(
            "controlled evaluation recovery identity is incomplete"
        )
    job_id = identity.get("job_id")
    job_type = identity.get("job_type")
    lease_token = identity.get("lease_token")
    cohort_id = identity.get("cohort_id")
    role = identity.get("agent_role")
    attempt_id = identity.get("reanalysis_attempt_id")
    release_id = identity.get("release_id")
    assigned_route = identity.get("expected_assigned_route")
    reviewer_route = identity.get("expected_reviewer_route")
    expected_role = {
        "ai_analysis": "soc-analyst",
        "incident_response_analysis": "incident-responder",
    }.get(job_type)
    expected_attempt = (
        ""
        if job_type == "ai_analysis"
        else incident_reanalysis_attempt_id(str(lease_token or ""))
    )
    runtime_release_id = current_runtime_release_id()
    claim_digest = controlled_canonical_digest(
        identity,
        ensure_ascii=False,
    )
    analysis_id = payload.get("analysis_id")
    if (
        not isinstance(job_id, int)
        or isinstance(job_id, bool)
        or job_id < 1
        or not isinstance(job_type, str)
        or not isinstance(lease_token, str)
        or not CONTROLLED_LEASE_TOKEN_RE.fullmatch(lease_token)
        or not isinstance(cohort_id, str)
        or not CONTROLLED_COHORT_ID_RE.fullmatch(cohort_id)
        or identity.get("dispatch_id") != args.only_dispatch_id
        or identity.get("representative_alert_id") != args.only_alert_id
        or identity.get("stable_group_id") != args.only_group_id
        or identity.get("stable_group_key") != args.only_stable_group_key
        or not isinstance(role, str)
        or role != expected_role
        or not isinstance(attempt_id, str)
        or attempt_id != expected_attempt
        or not isinstance(release_id, str)
        or release_id != runtime_release_id
        or not isinstance(assigned_route, str)
        or not CONTROLLED_MODEL_ROUTE_RE.fullmatch(assigned_route)
        or not isinstance(reviewer_route, str)
        or not CONTROLLED_MODEL_ROUTE_RE.fullmatch(reviewer_route)
        or assigned_route.rsplit(":", 1)[0]
        == reviewer_route.rsplit(":", 1)[0]
        or identity.get("reviewer_required") is not True
        or not isinstance(analysis_id, str)
        or not CONTROLLED_ANALYSIS_ID_RE.fullmatch(analysis_id)
        or payload.get("alert_id") != args.only_alert_id
        or payload.get("agent_role") != role
        or str(payload.get("reanalysis_attempt_id") or "") != attempt_id
        or response.get("_analysis_evaluation_memory_frozen") is not True
        or response.get("_analysis_controlled_claim_sha256")
        != claim_digest
        or response.get("_analysis_model_route") != assigned_route
        or not isinstance(response.get("_second_opinion"), dict)
        or response["_second_opinion"].get("status") != "completed"
        or response["_second_opinion"].get("model_route") != reviewer_route
        or not isinstance(
            response["_second_opinion"].get("response"),
            dict,
        )
        or response["_second_opinion"]["response"].get(
            "_analysis_model_route"
        ) != reviewer_route
    ):
        raise RuntimeError(
            "controlled evaluation recovery identity does not match "
            "the frozen scheduler pins"
        )
    return {
        "analysis_id": analysis_id,
        "job_id": job_id,
        "job_type": job_type,
        "lease_token": lease_token,
        "stable_group_id": args.only_group_id,
        # The runner binds frozen-memory tasks to its pre-storage response
        # digest. Alert-store separately normalizes timestamps before hashing
        # the stored response, so recovery must retain both exact bindings.
        "response_digest": controlled_canonical_digest(response),
        "stored_response_fallback_digest": (
            controlled_storage_canonical_digest(response)
        ),
        "accepted_fields": controlled_expected_accepted_fields(
            payload,
            response,
        ),
        "claim_digest": claim_digest,
        "identity": identity,
    }


def settle_controlled_frozen_memory_artifacts(
    runtime_root: Path,
    recovery: dict[str, Any],
) -> None:
    """Remove only frozen, response-bound memory tasks for this analysis."""
    analysis_id = str(recovery["analysis_id"])
    task_name = f"{analysis_id}.json"
    for directory_name in (
        "memory-writeback-pending",
        "memory-writeback-committed",
    ):
        directory = runtime_root / directory_name
        if not directory.exists():
            continue
        if not owner_private_directory(directory, runtime_root):
            raise RuntimeError(
                "controlled evaluation memory recovery directory is unsafe"
            )
        task_path = directory / task_name
        if not task_path.exists():
            continue
        task = load_owner_private_json(
            task_path,
            runtime_root,
            max_bytes=256 * 1024,
        )
        lanes = (task.get("primary"), task.get("reviewer"))
        if (
            task.get("schema")
            != "onion-sentinel-memory-writeback-task-v1"
            or task.get("analysis_id") != analysis_id
            or task.get("submitted_response_sha256")
            != recovery["response_digest"]
            or any(
                not isinstance(lane, dict)
                or lane.get("allowed") is not False
                or lane.get("candidates") != []
                for lane in lanes
            )
        ):
            raise RuntimeError(
                "controlled evaluation frozen-memory task is not exact"
            )
        task_path.unlink()
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def recover_controlled_evaluation_spool(
    args: argparse.Namespace,
    runtime_root: Path,
) -> bool:
    """Commit and retire one prior exact lease before any new inference."""
    queue_dir = runtime_root / "analysis-index-pending"
    if not queue_dir.exists():
        return False
    if not owner_private_directory(queue_dir, runtime_root):
        raise RuntimeError(
            "controlled evaluation recovery spool directory is unsafe"
        )
    entries = list(queue_dir.iterdir())
    spool_files = [path for path in entries if path.suffix == ".json"]
    if not spool_files:
        if entries:
            raise RuntimeError(
                "controlled evaluation recovery spool contains "
                "an unexpected artifact"
            )
        return False
    if len(entries) != 1 or len(spool_files) != 1:
        raise RuntimeError(
            "controlled evaluation recovery requires exactly one spool"
        )
    spool_path = spool_files[0]
    payload = load_owner_private_json(
        spool_path,
        runtime_root,
        max_bytes=MAX_CONTROLLED_RESULT_SPOOL_BYTES,
    )
    recovery = validate_controlled_recovery_payload(payload, args)
    if spool_path.name != f"{recovery['analysis_id']}.json":
        raise RuntimeError(
            "controlled evaluation recovery spool filename is not exact"
        )
    try:
        receipt = post_controlled_recovery_result(
            payload,
            args.alert_store_url,
        )
        recovery["stored_response_digest"] = str(
            receipt.get("stored_response_sha256") or ""
        ).lower()
    except RuntimeError as replay_error:
        if (
            CONTROLLED_RESULT_SUBMISSION_INDETERMINATE
            not in str(replay_error)
            or not controlled_recovery_terminal_success(args, recovery)
        ):
            raise
    else:
        if not controlled_recovery_terminal_success(args, recovery):
            raise RuntimeError(
                "controlled evaluation recovered result has no exact terminal "
                "database proof"
            )
    settle_controlled_frozen_memory_artifacts(runtime_root, recovery)
    spool_path.unlink()
    directory_fd = os.open(queue_dir, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return True


def controlled_recovery_spool_pending(runtime_root: Path) -> bool:
    """Return true without following an unsafe recovery-directory symlink."""
    queue_dir = runtime_root / "analysis-index-pending"
    try:
        metadata = queue_dir.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if (
        queue_dir.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        return True
    try:
        return any(queue_dir.iterdir())
    except OSError:
        return True


def controlled_recovery_terminal_success(
    args: argparse.Namespace,
    recovery: dict[str, Any],
) -> bool:
    """Prove a lost completion response from immutable read-only DB state."""
    try:
        connection = sqlite3.connect(
            f"file:{args.db}?mode=ro",
            uri=True,
            timeout=5,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN")
            job = connection.execute(
                """
                SELECT id, status, lease_token, lease_expires_at,
                       rerun_requested, payload_json
                FROM durable_jobs
                WHERE job_type = ? AND dedupe_key = ?
                """,
                (
                    recovery["job_type"],
                    recovery["stable_group_id"],
                ),
            ).fetchone()
            accepted = connection.execute(
                """
                SELECT group_id, alert_id, agent_role, generated_at, model,
                       model_path, detection_outcome, bluf, summary,
                       confidence, artifact_path, evidence_hash, response_json
                FROM ai_analysis_runs WHERE analysis_id = ?
                """,
                (recovery["analysis_id"],),
            ).fetchone()
            incident_attempt = connection.execute(
                """
                SELECT attempt_id, run_id, case_id, group_id, status,
                       analysis_id
                FROM incident_reanalysis_attempts
                WHERE analysis_id = ?
                """,
                (recovery["analysis_id"],),
            ).fetchone()
        finally:
            connection.close()
        job_payload = json.loads(str(job["payload_json"])) if job else {}
        stored_response = (
            json.loads(str(accepted["response_json"])) if accepted else {}
        )
    except (
        OSError,
        sqlite3.Error,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ):
        return False
    identity = recovery["identity"]
    expected_stored_response_digest = str(
        recovery.get("stored_response_digest")
        or recovery.get("stored_response_fallback_digest")
        or recovery["response_digest"]
    ).lower()
    return bool(
        job
        and accepted
        and int(job["id"] or 0) == int(recovery["job_id"])
        and job["status"] == "completed"
        and not job["lease_token"]
        and not job["lease_expires_at"]
        and int(job["rerun_requested"] or 0) == 0
        and job_payload.get("cohort_id") == identity["cohort_id"]
        and job_payload.get("dispatch_id") == identity["dispatch_id"]
        and job_payload.get("release_id") == identity["release_id"]
        and job_payload.get("alert_id")
        == identity["representative_alert_id"]
        and job_payload.get("representative_alert_id")
        == identity["representative_alert_id"]
        and job_payload.get("group_id") == identity["stable_group_id"]
        and job_payload.get("stable_group_id")
        == identity["stable_group_id"]
        and job_payload.get("stable_group_key")
        == identity["stable_group_key"]
        and accepted["group_id"] == identity["stable_group_id"]
        and accepted["alert_id"] == identity["representative_alert_id"]
        and accepted["agent_role"] == identity["agent_role"]
        and controlled_accepted_fields_match(
            accepted,
            recovery["accepted_fields"],
        )
        and isinstance(stored_response, dict)
        and stored_response.get("_analysis_controlled_claim_sha256")
        == recovery["claim_digest"]
        and re.fullmatch(
            r"[a-f0-9]{64}",
            expected_stored_response_digest,
        )
        and controlled_storage_canonical_digest(stored_response)
        == expected_stored_response_digest
        and (
            (
                recovery["job_type"] == "ai_analysis"
                and incident_attempt is None
            )
            or (
                recovery["job_type"] == "incident_response_analysis"
                and incident_attempt is not None
                and incident_attempt["attempt_id"]
                == identity["reanalysis_attempt_id"]
                and incident_attempt["run_id"]
                == job_payload.get("reanalysis_run_id")
                and incident_attempt["case_id"]
                == job_payload.get("case_id")
                and incident_attempt["group_id"]
                == identity["stable_group_id"]
                and incident_attempt["status"] == "completed"
                and incident_attempt["analysis_id"]
                == recovery["analysis_id"]
            )
        )
    )


def current_runtime_release_id(
    *,
    environ: object | None = None,
    env_path: Path | None = None,
) -> str:
    """Return the exact deployed commit attestation without evaluating .env.

    LaunchAgents invoke this worker directly and therefore do not inherit the
    runtime ``.env`` loaded by alert-store's shell wrapper. An explicitly
    supplied process value is authoritative; only its absence permits the
    bounded, literal fallback below.
    """
    source = os.environ if environ is None else environ
    try:
        explicitly_supplied = RUNTIME_RELEASE_ENV_KEY in source
    except TypeError:
        explicitly_supplied = False
    if explicitly_supplied:
        candidate = source.get(RUNTIME_RELEASE_ENV_KEY, "")
        return (
            candidate
            if isinstance(candidate, str)
            and CONTROLLED_RELEASE_ID_RE.fullmatch(candidate)
            else ""
        )

    path = DEFAULT_RUNTIME_ENV_PATH if env_path is None else Path(env_path)
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            return ""
        if metadata.st_size > MAX_RUNTIME_ENV_BYTES:
            return ""
        raw = path.read_bytes()
    except OSError:
        return ""
    if len(raw) > MAX_RUNTIME_ENV_BYTES:
        return ""
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return ""

    candidates: list[str] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == RUNTIME_RELEASE_ENV_KEY:
            candidates.append(value.strip())
    if len(candidates) != 1:
        return ""
    candidate = candidates[0]
    return candidate if CONTROLLED_RELEASE_ID_RE.fullmatch(candidate) else ""


def require_controlled_release_attestation(
    claimed_payload: dict[str, object],
) -> str:
    """Bind one controlled durable payload to the code running this worker."""
    payload_release_id = claimed_payload.get("release_id")
    runtime_release_id = current_runtime_release_id()
    if (
        not isinstance(payload_release_id, str)
        or not CONTROLLED_RELEASE_ID_RE.fullmatch(payload_release_id)
        or not runtime_release_id
        or payload_release_id != runtime_release_id
    ):
        raise ControlledClaimRejected(
            "controlled AI claim release_id did not match the deployed runtime"
        )
    return runtime_release_id


def alert_time_sql(alias: str = "") -> str:
    """Return the newest usable alert timestamp expression for queue priority."""
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


def severity_priority_sql(column: str = "triage_level") -> str:
    """Return SQL that drains each severity bucket before moving lower.

    Policy: no High alert is selected while any eligible Critical group remains;
    no Medium alert is selected while any eligible Critical or High group
    remains; and so on. Inside each severity bucket, newest alerts go first.
    """
    cases = "\n            ".join(
        f"WHEN '{level}' THEN {index}"
        for index, level in enumerate(SEVERITY_PRIORITY, start=1)
    )
    return f"CASE {column}\n            {cases}\n            ELSE {len(SEVERITY_PRIORITY) + 1}\n          END"


def scheduler_cli_defaults() -> SchedulerCliDefaults:
    """Resolve scheduler defaults at parse time for test and environment parity."""
    return SchedulerCliDefaults(
        db=DEFAULT_DB,
        harness_db=DEFAULT_HARNESS_DB,
        prompt_dir=DEFAULT_PROMPT_DIR,
        analysis_dir=DEFAULT_ANALYSIS_DIR,
        pcap_analysis_dir=DEFAULT_PCAP_ANALYSIS_DIR,
        rollup_dir=DEFAULT_ROLLUP_DIR,
        agent_memory_dir=DEFAULT_AGENT_MEMORY_DIR,
        shared_memory_file=DEFAULT_SHARED_MEMORY_FILE,
        asset_inventory_file=DEFAULT_ASSET_INVENTORY_FILE,
        incident_evidence_dir=DEFAULT_INCIDENT_EVIDENCE_DIR,
        incident_evidence_config=DEFAULT_INCIDENT_EVIDENCE_CONFIG,
        investigation_pivot_dir=DEFAULT_INVESTIGATION_PIVOT_DIR,
        live_osquery_config=DEFAULT_LIVE_OSQUERY_CONFIG,
        disagreement_adjudicator_prompt=DEFAULT_DISAGREEMENT_ADJUDICATOR_PROMPT,
        ai_settings=DEFAULT_AI_SETTINGS,
        investigation_harness_policy=DEFAULT_INVESTIGATION_HARNESS_POLICY,
        detection_playbooks=DEFAULT_DETECTION_PLAYBOOKS,
        investigation_skills=DEFAULT_INVESTIGATION_SKILLS,
        lock=DEFAULT_LOCK,
        drain=DEFAULT_DRAIN,
        wake=DEFAULT_WAKE,
        levels=DEFAULT_LEVELS,
        model=DEFAULT_MODEL,
        max_prompt_bytes=DEFAULT_MAX_PROMPT_BYTES,
        portal_wake=DEFAULT_DASHBOARD_WAKE,
        alert_store_url=os.environ.get(
            "ALERT_STORE_URL", "http://127.0.0.1:8787"
        ),
    )


def parse_args() -> argparse.Namespace:
    return parse_scheduler_args(
        scheduler_cli_defaults(),
        SchedulerCliPolicy(
            controlled_alert_id=CONTROLLED_ALERT_ID_RE,
            controlled_dispatch_id=CONTROLLED_DISPATCH_ID_RE,
            stable_group_key_valid=valid_controlled_stable_group_key,
            stable_group_key_max_bytes=CONTROLLED_STABLE_GROUP_KEY_MAX_LENGTH,
        ),
    )


def project_now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  ")


def project_now_precise() -> str:
    """Return a queue clock precise enough for sub-second retry timestamps."""
    return dt.datetime.now().astimezone().isoformat(
        timespec="milliseconds"
    ).replace("T", "  ")


def cli_agent_roles(settings_path: Path) -> set[str]:
    """Return roles explicitly assigned to a hosted CLI inference lane.

    Settings are treated as untrusted runtime input. A missing, oversized, or
    malformed file fails closed to the local lane so a configuration accident
    cannot unexpectedly send alert evidence to a hosted model.
    """
    try:
        if not settings_path.is_file() or settings_path.stat().st_size > MAX_AI_SETTINGS_BYTES:
            return set()
        raw = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return set()
    routes = raw.get("agent_models") if isinstance(raw, dict) else {}
    if not isinstance(routes, dict):
        return set()
    codex_models = raw.get("codex_cli_models", [])
    if not isinstance(codex_models, list):
        return set()
    enabled_codex_routes: set[str] = set()
    for entry in codex_models:
        if not isinstance(entry, dict) or entry.get("enabled") is not True:
            continue
        model = str(entry.get("model") or "").strip()
        effort = str(entry.get("reasoning_effort") or "").strip().lower()
        if (
            model in CODEX_CLI_MODEL_CATALOG
            and effort in CODEX_CLI_REASONING_EFFORTS
        ):
            enabled_codex_routes.add(f"codex-cli:{model}:{effort}")
    enabled_hosted_routes = set(enabled_codex_routes)
    if raw.get("hermes_agent_enabled") is True:
        model = str(raw.get("hermes_agent_model") or "gpt-5.5").strip()
        effort = str(raw.get("hermes_agent_reasoning_effort") or "medium").strip().lower()
        if model in CODEX_CLI_MODEL_CATALOG and effort == "medium":
            enabled_hosted_routes.add(f"hermes-agent:{model}:{effort}")
    # The isolated OpenClaw adapter currently admits explicit ollama/ routes
    # only. Those runs consume the serialized local GPU lane and must never be
    # classified as hosted CLI work, even if an untrusted settings file names
    # a different OpenClaw provider.
    cli_roles: set[str] = set()
    for role in AGENT_ROLES:
        route = str(routes.get(role) or "").strip()
        if route.lower() in {"gpt-cli", "codex-cli"} or route in enabled_hosted_routes:
            cli_roles.add(role)
    return cli_roles


def _role_uses_codex_cli(
    args: argparse.Namespace,
    *,
    agent_role: str = "",
) -> bool:
    """Return whether either configured route for this role uses Codex CLI."""
    role = str(agent_role or "").strip()
    settings_path = Path(
        getattr(args, "ai_settings_file", DEFAULT_AI_SETTINGS)
    )
    routes: list[str] = []
    try:
        if (
            settings_path.is_file()
            and settings_path.stat().st_size <= MAX_AI_SETTINGS_BYTES
        ):
            raw = json.loads(settings_path.read_text(encoding="utf-8"))
        else:
            raw = {}
        if isinstance(raw, dict):
            for field in (
                "agent_models",
                "agent_second_opinion_models",
                "agent_adjudicator_models",
            ):
                mapping = raw.get(field)
                if isinstance(mapping, dict):
                    routes.append(
                        str(mapping.get(role) or "").strip().lower()
                    )
    except (OSError, ValueError, TypeError):
        routes = []
    return any(
        route in {"gpt-cli", "codex-cli"}
        or route.startswith("codex-cli:")
        for route in routes
    )


def effective_prompt_package_limit(
    args: argparse.Namespace,
    *,
    agent_role: str = "",
) -> int:
    """Clamp the mutable Codex runner prompt to its transport-safe ceiling."""
    configured = int(
        getattr(args, "max_prompt_bytes", DEFAULT_MAX_PROMPT_BYTES)
        or DEFAULT_MAX_PROMPT_BYTES
    )
    if _role_uses_codex_cli(args, agent_role=agent_role):
        return min(configured, CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES)
    return configured


def effective_initial_prompt_package_limit(
    args: argparse.Namespace,
    *,
    agent_role: str = "",
) -> int:
    """Leave deterministic headroom for audited follow-up query evidence."""
    configured = int(
        getattr(args, "max_prompt_bytes", DEFAULT_MAX_PROMPT_BYTES)
        or DEFAULT_MAX_PROMPT_BYTES
    )
    if _role_uses_codex_cli(args, agent_role=agent_role):
        return min(configured, CODEX_CLI_INITIAL_PROMPT_PACKAGE_BYTES)
    return configured


def configured_analysis_levels(settings_path: Path, configured_levels: str) -> list[str]:
    """Return the launch allowlist constrained by the saved automatic AI floor.

    The scheduler argument remains a deployment-level ceiling. Settings can
    raise the floor at runtime without editing or reloading the launchd plist.
    Older settings files retain the historical all-severity analysis behavior
    until the operator explicitly saves the new control.
    """
    requested = [
        level.strip().lower()
        for level in str(configured_levels or "").split(",")
        if level.strip().lower() in SEVERITY_PRIORITY
    ]
    try:
        if not settings_path.is_file() or settings_path.stat().st_size > MAX_AI_SETTINGS_BYTES:
            raw = {}
        else:
            raw = json.loads(settings_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raw = {}
    except (OSError, ValueError, TypeError):
        raw = {}
    threshold = str(
        raw.get("soc_analyst_analysis_min_severity", "informational") or ""
    ).strip().lower()
    if threshold == "info":
        threshold = "informational"
    if threshold == "disabled":
        return []
    if threshold not in SEVERITY_PRIORITY:
        threshold = "informational"
    highest_allowed_index = SEVERITY_PRIORITY.index(threshold)
    return [
        level
        for level in SEVERITY_PRIORITY[: highest_allowed_index + 1]
        if level in requested
    ]


def provider_lane_sql(args: argparse.Namespace) -> tuple[str, list[object]]:
    """Build an allowlisted SQL predicate for the selected provider lane."""
    provider_lane = str(getattr(args, "provider_lane", "any") or "any")
    cli_roles = sorted(cli_agent_roles(Path(getattr(args, "ai_settings_file", DEFAULT_AI_SETTINGS))))
    return provider_lane_predicate(provider_lane, cli_roles)


def rows(conn: sqlite3.Connection, sql: str, params: Iterable[object] = ()) -> list[sqlite3.Row]:
    return conn.execute(sql, tuple(params)).fetchall()


def scheduler_reporting_sources() -> SchedulerReportingSources:
    """Bind the scheduler's bounded HTTP and controlled-claim policy ports."""
    return SchedulerReportingSources(
        request_factory=urllib.request.Request,
        open_url=urllib.request.urlopen,
        read_json=read_bounded_json,
        mutation_headers=alert_store_mutation_headers,
        sleep=time.sleep,
        valid_stable_group_key=valid_controlled_stable_group_key,
        model_route_pattern=CONTROLLED_MODEL_ROUTE_RE,
        max_response_bytes=DEFAULT_MAX_CONTROL_RESPONSE_BYTES,
        exact_claim_attempts=CONTROLLED_EXACT_CLAIM_ATTEMPTS,
    )


def report_ai_job_status(
    base_url: str,
    group_id: str,
    status: str,
    error: str = "",
    lease_token: str = "",
    job_type: str = "ai_analysis",
    retryable: bool = True,
    expected_job_id: int = 0,
    expected_representative_alert_id: str = "",
    expected_dispatch_id: str = "",
    expected_stable_group_key: str = "",
    expected_assigned_route: str = "",
    expected_reviewer_route: str = "",
    reviewer_required: bool = False,
) -> bool | str:
    """Transition durable AI intent through a bounded local HTTP contract.

    Returning ``False`` only represents a rolling-deployment 404. Network,
    malformed-response, and oversized-response failures remain visible so the
    worker never performs expensive inference without a durable processing
    lease in the current indexed architecture.
    """
    return transition_ai_job_status(
        scheduler_reporting_sources(),
        base_url,
        group_id,
        status,
        error,
        lease_token,
        job_type,
        retryable,
        expected_job_id,
        expected_representative_alert_id,
        expected_dispatch_id,
        expected_stable_group_key,
        expected_assigned_route,
        expected_reviewer_route,
        reviewer_required,
    )


def incident_reanalysis_attempt_id(lease_token: str) -> str:
    """Return the non-secret fingerprint alert-store uses for one IR lease."""
    token = str(lease_token or "").strip()
    if not token:
        return ""
    return "ira-" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:40]


def job_reanalysis_attempt_id(job_payload: dict, lease_token: str) -> str:
    """Fingerprint only a validated manual reanalysis job, never escalation."""
    if job_payload.get("manual_reanalysis") is not True:
        return ""
    run_id = str(job_payload.get("reanalysis_run_id") or "").strip().lower()
    case_id = str(job_payload.get("case_id") or "").strip().lower()
    if not re.fullmatch(r"irr-[a-f0-9-]{36}", run_id):
        return ""
    if not re.fullmatch(r"ir-[a-z0-9_-]{1,64}", case_id):
        return ""
    return incident_reanalysis_attempt_id(lease_token)


NON_RETRYABLE_AI_FAILURE_MARKERS = (
    "model context window exhausted",
    "prompt package remains above",
    "prompt package exceeded",
    "codex cli complete transport exceeds",
    "investigation follow-up prompt exceeds",
    "investigation query prompt projection exceeds",
    "no safe prompt budget remains",
    "codex cli executable was not found",
    "codex cli model name is invalid",
    "codex cli reasoning effort is invalid",
    "provider authentication failed",
    "configured model is unavailable or unauthorized",
    "command stderr exceeded the",
    "command stdout exceeded the",
    "incident reanalysis claim did not return its server-authoritative job identity",
    "incident reanalysis lease identity did not match its server-bound attempt",
    "durable ai claim job identity is invalid",
    "durable ai claim group identity is invalid",
    "durable ai claim alert identity is invalid",
    "controlled ai run requires a durable ai job claim",
    "controlled ai run identity arguments are incomplete",
    "controlled ai claim group identity did not match",
    "controlled ai claim alert identity did not match",
    "controlled ai claim dispatch identity did not match",
    "controlled ai claim release_id did not match",
)


def ai_failure_is_retryable(error: object) -> bool:
    """Return false for deterministic failures that rebuilding cannot repair."""
    detail = str(error or "").strip().lower()
    return not any(marker in detail for marker in NON_RETRYABLE_AI_FAILURE_MARKERS)


def reconcile_completed_ai_jobs(base_url: str, group_ids: set[str]) -> int:
    """Mark pending queue intent complete when current artifacts already satisfy it."""
    if not group_ids:
        return 0
    payload = json.dumps({
        "job_type": "ai_analysis",
        "dedupe_keys": sorted(group_ids),
    }).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/jobs/reconcile-completed",
        data=payload,
        headers=alert_store_mutation_headers(),
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status not in range(200, 300):
                raise RuntimeError(f"AI job reconciliation returned HTTP {response.status}")
            result = read_bounded_json(response, max_bytes=DEFAULT_MAX_CONTROL_RESPONSE_BYTES)
            return int(result.get("reconciled") or 0)
    except urllib.error.HTTPError as exc:
        # Older alert-store versions may not have the batch endpoint during a
        # rolling deployment. Analysis must continue and the next run retries.
        if exc.code == 404:
            return 0
        raise RuntimeError(f"AI job reconciliation returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, BoundedHttpError) as exc:
        raise RuntimeError(f"AI job reconciliation failed: {exc}") from exc


def test_filter_sql(column: str = "alert_id") -> tuple[str, list[object]]:
    clauses = []
    params: list[object] = []
    for pattern in TEST_PREFIXES:
        clauses.append(f"{column} NOT LIKE ?")
        params.append(pattern)
    return " AND ".join(clauses), params


def latest_analysis_mtimes(analysis_dir: Path) -> dict[str, float]:
    latest: dict[str, float] = {}
    if not analysis_dir.exists():
        return latest
    for path in analysis_dir.glob("*-local-ai-analysis.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        alert_id = str(data.get("alert_id") or "").strip()
        if alert_id:
            latest[alert_id] = max(latest.get(alert_id, 0), path.stat().st_mtime)
    return latest


def latest_pcap_analysis_mtimes(pcap_analysis_dir: Path) -> dict[str, float]:
    latest: dict[str, float] = {}
    if not pcap_analysis_dir.exists():
        return latest
    for path in pcap_analysis_dir.glob("*-pcap-analysis.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        request = data.get("request") if isinstance(data.get("request"), dict) else {}
        alert_id = str(request.get("alert_id") or data.get("alert_id") or "").strip()
        if alert_id:
            latest[alert_id] = max(latest.get(alert_id, 0), path.stat().st_mtime)
    return latest


def latest_pcap_group_mtimes(pcap_analysis_dir: Path) -> dict[str, float]:
    """Return newest parsed PCAP evidence time keyed by grouped detection id."""
    latest: dict[str, float] = {}
    if not pcap_analysis_dir.exists():
        return latest
    for path in pcap_analysis_dir.glob("*-pcap-analysis.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        request = data.get("request") if isinstance(data.get("request"), dict) else {}
        group_id = str(request.get("group_id") or "").strip()
        if group_id:
            latest[group_id] = max(latest.get(group_id, 0), path.stat().st_mtime)
    return latest


def latest_prompt_mtimes(prompt_dir: Path) -> dict[str, float]:
    latest: dict[str, float] = {}
    if not prompt_dir.exists():
        return latest
    for path in prompt_dir.glob("*-ai-prompt.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
        alert_id = str(alert.get("alert_id") or data.get("alert_id") or "").strip()
        if alert_id:
            latest[alert_id] = max(latest.get(alert_id, 0), path.stat().st_mtime)
    return latest


def alert_group_key_from_mapping(alert: dict) -> str:
    """Return the scheduler duplicate-group key for prompt-package alert data."""
    suppression_key = str(alert.get("suppression_key") or "").strip()
    if suppression_key:
        return suppression_key
    return "|".join(
        [
            str(alert.get("triage_level") or ""),
            str(alert.get("rule_name") or ""),
            str(alert.get("source_ip") or ""),
            str(alert.get("destination_ip") or ""),
            str(alert.get("filter_status") or "accepted"),
        ]
    )


def latest_prompt_group_mtimes(conn: sqlite3.Connection, prompt_dir: Path) -> dict[str, float]:
    """Return newest AI prompt time keyed by the live DB duplicate group.

    Prompt packages are immutable queue artifacts, but duplicate-group fields can
    be repaired or normalized later in SQLite. Resolve prompt alert IDs through
    the current DB so manual reanalysis uses the same group key as selection.
    """
    prompt_mtimes = latest_prompt_mtimes(prompt_dir)
    latest: dict[str, float] = {}
    if not prompt_mtimes:
        return latest
    placeholders = ", ".join("?" for _ in prompt_mtimes)
    prompt_rows = rows(
        conn,
        f"""
        SELECT alert_id, suppression_key, triage_level, rule_name, source_ip,
               destination_ip, filter_status
        FROM alerts
        WHERE alert_id IN ({placeholders})
        """,
        sorted(prompt_mtimes),
    )
    db_prompt_ids: set[str] = set()
    for row in prompt_rows:
        alert_id = str(row["alert_id"] or "").strip()
        db_prompt_ids.add(alert_id)
        group_key = alert_group_key(row)
        latest[group_key] = max(latest.get(group_key, 0), prompt_mtimes.get(alert_id, 0))

    # Fallback for prompt packages whose source alert has been aged out of the
    # DB. These cannot make the scheduler select work, but retaining the mapping
    # keeps diagnostics deterministic.
    if not prompt_dir.exists():
        return latest
    for path in prompt_dir.glob("*-ai-prompt.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
        alert_id = str(alert.get("alert_id") or data.get("alert_id") or "").strip()
        if alert_id in db_prompt_ids:
            continue
        group_key = alert_group_key_from_mapping(alert)
        if group_key:
            latest[group_key] = max(latest.get(group_key, 0), path.stat().st_mtime)
    return latest


def analyzed_alert_ids(analysis_dir: Path, pcap_analysis_dir: Path | None = None, prompt_dir: Path | None = None) -> set[str]:
    """Return analyzed alert ids, excluding AI artifacts stale versus PCAP or manual requeue prompts."""
    ai_mtimes = latest_analysis_mtimes(analysis_dir)
    prompt_mtimes = latest_prompt_mtimes(prompt_dir) if prompt_dir else {}
    if not pcap_analysis_dir:
        return {alert_id for alert_id, ai_mtime in ai_mtimes.items() if prompt_mtimes.get(alert_id, 0) <= ai_mtime}
    pcap_mtimes = latest_pcap_analysis_mtimes(pcap_analysis_dir)
    return {
        alert_id
        for alert_id, ai_mtime in ai_mtimes.items()
        if pcap_mtimes.get(alert_id, 0) <= ai_mtime and prompt_mtimes.get(alert_id, 0) <= ai_mtime
    }


def alert_group_key(row: sqlite3.Row) -> str:
    """Return the same duplicate-group key used by the SOC dashboard."""
    suppression_key = str(row["suppression_key"] or "").strip() if "suppression_key" in row.keys() else ""
    if suppression_key:
        return suppression_key
    filter_status = str(row["filter_status"] or "accepted")
    return "|".join(
        [
            str(row["triage_level"] or ""),
            str(row["rule_name"] or ""),
            str(row["source_ip"] or ""),
            str(row["destination_ip"] or ""),
            filter_status,
        ]
    )


def alert_group_id(group_key: str) -> str:
    return hashlib.sha1(group_key.encode("utf-8")).hexdigest()[:12]


def analyzed_alert_groups(
    conn: sqlite3.Connection,
    analyzed_ids: set[str],
    analysis_dir: Path | None = None,
    pcap_analysis_dir: Path | None = None,
    prompt_dir: Path | None = None,
) -> set[str]:
    """Map analyzed alert IDs back to grouped detections.

    The dashboard displays grouped duplicate detections, not every raw alert row.
    A group is complete only when its newest AI analysis is newer than both its
    newest parsed PCAP evidence and newest prompt package. That keeps duplicate
    suppression efficient while still honoring manual reanalysis requests.
    """
    if not analyzed_ids:
        return set()
    ai_mtimes = latest_analysis_mtimes(analysis_dir) if analysis_dir else {}
    pcap_group_mtimes = latest_pcap_group_mtimes(pcap_analysis_dir) if pcap_analysis_dir else {}
    prompt_group_mtimes = latest_prompt_group_mtimes(conn, prompt_dir) if prompt_dir else {}
    placeholders = ", ".join("?" for _ in analyzed_ids)
    analyzed_rows = rows(
        conn,
        f"""
        SELECT alert_id, suppression_key, triage_level, rule_name, source_ip,
               destination_ip, filter_status
        FROM alerts
        WHERE alert_id IN ({placeholders})
        """,
        sorted(analyzed_ids),
    )
    group_ai_mtimes: dict[str, float] = {}
    for row in analyzed_rows:
        group_key = alert_group_key(row)
        ai_mtime = ai_mtimes.get(str(row["alert_id"] or "").strip(), 0)
        group_ai_mtimes[group_key] = max(group_ai_mtimes.get(group_key, 0), ai_mtime)

    analyzed_groups: set[str] = set()
    for group_key, ai_mtime in group_ai_mtimes.items():
        group_pcap_mtime = pcap_group_mtimes.get(alert_group_id(group_key), 0)
        group_prompt_mtime = prompt_group_mtimes.get(group_key, 0)
        if group_pcap_mtime and ai_mtime and group_pcap_mtime > ai_mtime:
            continue
        if group_prompt_mtime and ai_mtime and group_prompt_mtime > ai_mtime:
            continue
        analyzed_groups.add(group_key)
    return analyzed_groups


def completed_analysis_group_ids(
    conn: sqlite3.Connection,
    analyzed_ids: set[str],
    analysis_dir: Path,
    pcap_analysis_dir: Path,
    prompt_dir: Path,
) -> set[str]:
    """Return stable queue keys for groups whose analysis artifacts are current."""
    completed_keys = analyzed_alert_groups(
        conn,
        analyzed_ids,
        analysis_dir,
        pcap_analysis_dir,
        prompt_dir,
    )
    if not completed_keys or not analyzed_ids:
        return set()
    columns = {str(item[1]) for item in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    stable_select = "stable_group_id" if "stable_group_id" in columns else "NULL AS stable_group_id"
    placeholders = ", ".join("?" for _ in analyzed_ids)
    analyzed_rows = rows(
        conn,
        f"""
        SELECT alert_id, suppression_key, triage_level, rule_name, source_ip,
               destination_ip, filter_status, {stable_select}
        FROM alerts WHERE alert_id IN ({placeholders})
        """,
        sorted(analyzed_ids),
    )
    completed_ids: set[str] = set()
    for row in analyzed_rows:
        group_key = alert_group_key(row)
        if group_key not in completed_keys:
            continue
        stable_id = str(row["stable_group_id"] or "").strip()
        completed_ids.add(stable_id or alert_group_id(group_key))
    return completed_ids


def orphaned_pending_ai_job_ids(conn: sqlite3.Connection) -> set[str]:
    """Return pending AI queue keys that no longer map to an alert group.

    Stable group identities can be replaced when legacy rows are normalized or
    grouping policy changes. Those old durable intents are not actionable, but
    leaving them pending makes queue health report a worker stall forever.
    """
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "durable_jobs" not in tables:
        return set()
    pending_ids = {
        str(row[0] or "").strip()
        for row in conn.execute(
            "SELECT dedupe_key FROM durable_jobs WHERE job_type = 'ai_analysis' AND status = 'pending'"
        ).fetchall()
        if str(row[0] or "").strip()
    }
    if not pending_ids:
        return set()
    # alert_group_summary is the authoritative set of currently actionable
    # groups. Raw alert rows can retain superseded identities after a recovery
    # or grouping-policy migration, which otherwise leaves queue intents that
    # no scheduler selection can ever satisfy.
    active_ids = {
        str(row[0] or "").strip()
        for row in conn.execute("SELECT group_id FROM alert_group_summary").fetchall()
        if str(row[0] or "").strip()
    }
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "alert_group_alias" in tables:
        for legacy_id, stable_id in conn.execute(
            "SELECT legacy_group_id, stable_group_id FROM alert_group_alias"
        ).fetchall():
            # Summaries retain the legacy dashboard identifier while durable
            # AI jobs use the V2 stable identity. Follow the alias in that
            # direction so both forms remain actionable.
            if str(legacy_id or "").strip() in active_ids:
                active_ids.add(str(stable_id or "").strip())
    return pending_ids - active_ids


def pending_ai_job_ids(conn: sqlite3.Connection) -> set[str]:
    """Return coalesced durable AI intents that still require a model run."""
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "durable_jobs" not in tables:
        return set()
    return {
        str(row[0] or "").strip()
        for row in conn.execute(
            "SELECT dedupe_key FROM durable_jobs WHERE job_type = 'ai_analysis' AND status = 'pending'"
        ).fetchall()
        if str(row[0] or "").strip()
    }


def reconcilable_completed_ai_job_ids(conn: sqlite3.Connection, group_ids: set[str]) -> set[str]:
    """Keep artifact reconciliation from erasing newly queued evidence.

    A pending job is artifact-reconcilable only when a worker previously began
    processing it. Fresh alert, enrichment, and PCAP intents deliberately have
    no processing start and must reach the scheduler even when an older report
    artifact exists for the same duplicate group.
    """
    if not group_ids:
        return set()
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "durable_jobs" not in tables:
        return set()
    columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(durable_jobs)").fetchall()}
    if "processing_started_at" not in columns or "rerun_requested" not in columns:
        return group_ids
    placeholders = ", ".join("?" for _ in group_ids)
    return {
        str(row[0] or "").strip()
        for row in conn.execute(
            f"""
            SELECT dedupe_key FROM durable_jobs
            WHERE job_type = 'ai_analysis' AND status = 'pending'
              AND COALESCE(rerun_requested, 0) = 0
              AND processing_started_at IS NOT NULL
              AND dedupe_key IN ({placeholders})
            """,
            sorted(group_ids),
        ).fetchall()
        if str(row[0] or "").strip()
    }


def reconcilable_ai_job_ids(
    conn: sqlite3.Connection,
    analyzed_ids: set[str],
    analysis_dir: Path,
    pcap_analysis_dir: Path,
    prompt_dir: Path,
) -> set[str]:
    """Combine artifact-complete and obsolete durable AI queue intents."""
    completed = completed_analysis_group_ids(
        conn,
        analyzed_ids,
        analysis_dir,
        pcap_analysis_dir,
        prompt_dir,
    )
    return reconcilable_completed_ai_job_ids(conn, completed) | orphaned_pending_ai_job_ids(conn)


def indexed_scheduler_available(conn: sqlite3.Connection) -> bool:
    """Compatibility delegate for indexed scheduler capability detection."""
    return indexed_scheduler_state_available(conn)


def indexed_reconcilable_ai_job_ids(conn: sqlite3.Connection) -> set[str]:
    """Compatibility delegate for indexed committed-result reconciliation."""
    return load_indexed_reconcilable_ai_job_ids(conn)


def select_next_alert_indexed(
    conn: sqlite3.Connection,
    args: argparse.Namespace,
    already_selected_groups: set[str] | None = None,
) -> sqlite3.Row | None:
    lane_sql, lane_params = provider_lane_sql(args)
    # Indexed groups are guarded by durable job state. Do not apply the legacy
    # per-process exclusion set: a request coalesced while inference is active
    # becomes a fresh pending job and should be eligible immediately.
    del already_selected_groups
    request = IndexedSelectionRequest(
        levels=args.levels,
        hours=args.hours,
        include_tests=args.include_tests,
        only_group_id=str(getattr(args, "only_group_id", "") or ""),
        lane_sql=lane_sql,
        lane_params=tuple(lane_params),
    )
    sources = IndexedSelectionSources(
        now=lambda: dt.datetime.now().astimezone(),
        precise_now=project_now_precise,
        alert_time_sql=alert_time_sql,
        severity_priority_sql=severity_priority_sql,
        test_filter_sql=test_filter_sql,
        eligible_filter_statuses=ELIGIBLE_FILTER_STATUSES,
        fairness_age_seconds=AI_JOB_FAIRNESS_AGE_SECONDS,
    )
    return select_next_indexed_alert(conn, request, sources)


def select_next_alert(
    conn: sqlite3.Connection,
    args: argparse.Namespace,
    already_analyzed: set[str],
    already_selected_groups: set[str] | None = None,
) -> sqlite3.Row | None:
    request = LegacySelectionRequest(
        levels=args.levels,
        hours=args.hours,
        include_tests=args.include_tests,
        only_group_id=str(getattr(args, "only_group_id", "") or ""),
        analysis_dir=getattr(args, "analysis_dir", None),
        pcap_analysis_dir=getattr(args, "pcap_analysis_dir", None),
        prompt_dir=getattr(args, "prompt_dir", None),
        already_analyzed=frozenset(already_analyzed),
        already_selected_groups=frozenset(already_selected_groups or set()),
    )
    sources = LegacySelectionSources(
        now=lambda: dt.datetime.now().astimezone(),
        alert_time_sql=lambda: alert_time_sql(),
        alert_group_key_sql=alert_group_key_sql,
        severity_priority_sql=lambda: severity_priority_sql(),
        test_filter_sql=lambda: test_filter_sql(),
        latest_prompt_mtimes=latest_prompt_mtimes,
        latest_analysis_mtimes=latest_analysis_mtimes,
        analyzed_alert_groups=analyzed_alert_groups,
        pending_ai_job_ids=pending_ai_job_ids,
        alert_group_key=alert_group_key,
        alert_group_id=alert_group_id,
        eligible_filter_statuses=ELIGIBLE_FILTER_STATUSES,
    )
    return select_next_legacy_alert(conn, request, sources)


def latest_prompt_for_alert(prompt_dir: Path, alert_id: str) -> Path | None:
    if not prompt_dir.exists():
        return None
    matches: list[tuple[float, Path]] = []
    for path in prompt_dir.glob("*-ai-prompt.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
        if alert.get("alert_id") == alert_id:
            matches.append((path.stat().st_mtime, path))
    if not matches:
        return None
    return sorted(matches)[-1][1]


def latest_pcap_evidence_mtime_for_alert(selected: sqlite3.Row, pcap_analysis_dir: Path) -> float:
    """Return newest parsed PCAP evidence mtime for the selected alert group."""
    if not pcap_analysis_dir.exists():
        return 0
    selected_alert_id = str(selected["alert_id"] or "").strip()
    selected_group_id = alert_group_id(str(selected["queue_group_key"] or alert_group_key(selected)))
    newest = 0.0
    for path in pcap_analysis_dir.glob("*-pcap-analysis.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        request = data.get("request") if isinstance(data.get("request"), dict) else {}
        if str(request.get("alert_id") or "").strip() != selected_alert_id and str(request.get("group_id") or "").strip() != selected_group_id:
            continue
        newest = max(newest, path.stat().st_mtime)
    return newest


def reusable_prompt_for_alert(prompt_dir: Path, selected: sqlite3.Row, pcap_analysis_dir: Path) -> Path | None:
    """Return a prompt package only if it is current with parsed PCAP evidence."""
    prompt = latest_prompt_for_alert(prompt_dir, str(selected["alert_id"] or ""))
    if not prompt:
        return None
    pcap_mtime = latest_pcap_evidence_mtime_for_alert(selected, pcap_analysis_dir)
    if pcap_mtime and pcap_mtime > prompt.stat().st_mtime:
        return None
    return prompt


def durable_payload(selected: sqlite3.Row) -> dict[str, object]:
    """Decode trusted queue metadata without letting corruption alter limits."""
    if "durable_payload_json" not in selected.keys():
        return {}
    try:
        payload = json.loads(str(selected["durable_payload_json"] or "{}"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def claimed_durable_ai_job(
    processing_transition: object,
    database_path: Path,
    *,
    expected_job_type: str,
    expected_group_id: str,
    expected_job_id: int = 0,
) -> tuple[dict[str, object], str, str, str]:
    """Validate and return the exact durable AI snapshot bound to a lease."""
    claimed_payload = getattr(processing_transition, "job_payload", None)
    if not isinstance(claimed_payload, dict) or not claimed_payload:
        raise RuntimeError(
            "durable AI claim did not return its server-authoritative job identity"
        )

    claimed_job_type = str(
        getattr(processing_transition, "job_type", "") or ""
    ).strip()
    if claimed_job_type != expected_job_type:
        raise RuntimeError("durable AI claim job identity is invalid")
    claimed_job_id = int(
        getattr(processing_transition, "job_id", 0) or 0
    )
    if expected_job_id and claimed_job_id != expected_job_id:
        raise RuntimeError("durable AI claim job identity is invalid")

    resolved_group_id = str(
        getattr(processing_transition, "resolved_key", "") or ""
    ).strip().lower()
    payload_group_id = str(
        claimed_payload.get("group_id") or ""
    ).strip().lower()
    if (
        not resolved_group_id
        or resolved_group_id != expected_group_id.strip().lower()
        or not payload_group_id
        or payload_group_id != resolved_group_id
    ):
        raise RuntimeError("durable AI claim group identity is invalid")

    payload_alert_ids = {
        str(claimed_payload.get(field) or "").strip()
        for field in ("alert_id", "representative_alert_id")
        if str(claimed_payload.get(field) or "").strip()
    }
    if len(payload_alert_ids) != 1:
        raise RuntimeError("durable AI claim alert identity is invalid")
    claimed_alert_id = next(iter(payload_alert_ids))

    try:
        connection = sqlite3.connect(
            f"file:{database_path}?mode=ro",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        try:
            alert = connection.execute(
                """
                SELECT stable_group_id, stable_group_key, triage_level
                FROM alerts
                WHERE alert_id = ?
                LIMIT 1
                """,
                (claimed_alert_id,),
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise RuntimeError(
            "durable AI claim identity verification failed"
        ) from exc

    if (
        not alert
        or str(alert["stable_group_id"] or "").strip().lower()
        != resolved_group_id
    ):
        raise RuntimeError("durable AI claim alert identity is invalid")
    claimed_stable_group_key = claimed_payload.get("stable_group_key")
    if (
        claimed_stable_group_key is not None
        and (
            not valid_controlled_stable_group_key(claimed_stable_group_key)
            or not valid_controlled_stable_group_key(
                alert["stable_group_key"]
            )
            or str(alert["stable_group_key"] or "")
            != claimed_stable_group_key
        )
    ):
        raise RuntimeError("durable AI claim stable group key is invalid")
    triage_level = str(alert["triage_level"] or "").strip().lower()
    if triage_level not in SEVERITY_PRIORITY:
        raise RuntimeError("durable AI claim alert identity is invalid")
    return (
        dict(claimed_payload),
        claimed_alert_id,
        resolved_group_id,
        triage_level,
    )


def require_controlled_claim_identity(
    args: argparse.Namespace,
    claimed_payload: dict[str, object],
    *,
    claimed_alert_id: str,
    claimed_group_id: str,
    claimed_job_id: int,
    expected_job_id: int,
) -> None:
    """Fail closed when a controlled run leases a different frozen member."""
    expected_group_id = str(
        getattr(args, "only_group_id", "") or ""
    ).strip().lower()
    expected_alert_id = str(
        getattr(args, "only_alert_id", "") or ""
    ).strip()
    expected_stable_group_key = str(
        getattr(args, "only_stable_group_key", "") or ""
    )
    expected_dispatch_id = str(
        getattr(args, "only_dispatch_id", "") or ""
    ).strip()
    configured_identity = (
        bool(expected_group_id),
        bool(expected_alert_id),
        bool(expected_stable_group_key),
        bool(expected_dispatch_id),
    )
    if not any(configured_identity):
        return
    if not all(configured_identity):
        raise ControlledClaimRejected(
            "controlled AI run identity arguments are incomplete"
        )
    if not valid_controlled_stable_group_key(expected_stable_group_key):
        raise ControlledClaimRejected(
            "controlled AI run stable group key is invalid"
        )
    require_controlled_release_attestation(claimed_payload)
    controlled_job_route_contract(args, claimed_payload)

    if (
        int(claimed_job_id or 0) != int(expected_job_id or 0)
        or int(expected_job_id or 0) < 1
    ):
        raise ControlledClaimRejected(
            "controlled AI claim job identity did not match the selected job"
        )

    payload_group_id = str(
        claimed_payload.get("group_id") or ""
    ).strip().lower()
    payload_stable_group_id = str(
        claimed_payload.get("stable_group_id") or ""
    ).strip().lower()
    if (
        str(claimed_group_id or "").strip().lower() != expected_group_id
        or payload_group_id != expected_group_id
        or payload_stable_group_id != expected_group_id
    ):
        raise ControlledClaimRejected(
            "controlled AI claim group identity did not match --only-group-id"
        )

    payload_alert_id = str(claimed_payload.get("alert_id") or "").strip()
    payload_representative_alert_id = str(
        claimed_payload.get("representative_alert_id") or ""
    ).strip()
    if (
        str(claimed_alert_id or "").strip() != expected_alert_id
        or payload_alert_id != expected_alert_id
        or payload_representative_alert_id != expected_alert_id
    ):
        raise ControlledClaimRejected(
            "controlled AI claim alert identity did not match --only-alert-id"
        )

    if (
        not valid_controlled_stable_group_key(
            claimed_payload.get("stable_group_key")
        )
        or claimed_payload.get("stable_group_key")
        != expected_stable_group_key
    ):
        raise ControlledClaimRejected(
            "controlled AI claim stable group key did not match "
            "--only-stable-group-key"
        )

    payload_dispatch_id = str(
        claimed_payload.get("dispatch_id") or ""
    ).strip()
    if payload_dispatch_id != expected_dispatch_id:
        raise ControlledClaimRejected(
            "controlled AI claim dispatch identity did not match "
            "--only-dispatch-id"
        )


def _strict_ai_settings_module() -> Any:
    """Load the analysis runner so both processes use one settings parser."""

    global _STRICT_AI_SETTINGS_MODULE
    if _STRICT_AI_SETTINGS_MODULE is not None:
        return _STRICT_AI_SETTINGS_MODULE
    runner_path = (BIN_DIR / "run-local-ai-analysis.py").resolve(strict=True)
    module_name = (
        "_onion_sentinel_strict_ai_settings_"
        + hashlib.sha256(str(runner_path).encode("utf-8")).hexdigest()[:16]
    )
    module = sys.modules.get(module_name)
    if module is None:
        spec = importlib.util.spec_from_file_location(module_name, runner_path)
        if spec is None or spec.loader is None:
            raise RuntimeError("analysis runner settings loader is unavailable")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop(module_name, None)
            raise
    if not callable(getattr(module, "load_ai_settings", None)) or not callable(
        getattr(module, "enabled_agent_model_routes", None)
    ):
        raise RuntimeError("analysis runner settings loader is incomplete")
    _STRICT_AI_SETTINGS_MODULE = module
    return module


def _strict_controlled_ai_settings(
    settings_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], set[str]]:
    """Return runner-normalized settings plus exact persisted assignments."""

    if (
        not settings_path.is_file()
        or settings_path.stat().st_size > MAX_AI_SETTINGS_BYTES
    ):
        raise RuntimeError("settings file is missing or oversized")
    runner = _strict_ai_settings_module()
    settings = runner.load_ai_settings(settings_path)
    raw = json.loads(
        runner.read_bytes_bounded(
            settings_path,
            runner.DEFAULT_MAX_SETTINGS_BYTES,
        ).decode("utf-8", errors="strict")
    )
    if not isinstance(settings, dict) or not isinstance(raw, dict):
        raise RuntimeError("AI settings root must be an object")
    enabled_routes = set(runner.enabled_agent_model_routes(settings))
    return settings, raw, enabled_routes


def controlled_job_route_contract(
    args: argparse.Namespace,
    job_payload: dict[str, object],
) -> dict[str, object]:
    """Bind a controlled job to exact canonical, enabled role assignments."""

    assigned_route = job_payload.get("expected_assigned_route")
    reviewer_route = job_payload.get("expected_reviewer_route")
    reviewer_required = job_payload.get("reviewer_required")
    role = str(job_payload.get("agent_role") or "").strip().lower()
    if (
        not isinstance(assigned_route, str)
        or not isinstance(reviewer_route, str)
        or not CONTROLLED_MODEL_ROUTE_RE.fullmatch(assigned_route)
        or not CONTROLLED_MODEL_ROUTE_RE.fullmatch(reviewer_route)
        or assigned_route.rsplit(":", 1)[0]
        == reviewer_route.rsplit(":", 1)[0]
        or reviewer_required is not True
        or role not in {"soc-analyst", "incident-responder"}
    ):
        raise ControlledClaimRejected(
            "controlled durable AI job route contract is invalid"
        )

    settings_path = Path(
        getattr(args, "ai_settings_file", DEFAULT_AI_SETTINGS)
    )
    try:
        settings, raw, enabled_routes = _strict_controlled_ai_settings(
            settings_path
        )
    except (OSError, UnicodeError, ValueError, TypeError, RuntimeError) as exc:
        raise ControlledClaimRejected(
            "controlled AI route settings are unavailable"
        ) from exc
    assignments = raw.get("agent_models")
    reviewers = raw.get("agent_second_opinion_models")
    normalized_assignments = settings.get("agent_models")
    normalized_reviewers = settings.get("agent_second_opinion_models")
    if (
        not isinstance(assignments, dict)
        or assignments.get(role) != assigned_route
        or not isinstance(reviewers, dict)
        or reviewers.get(role) != reviewer_route
        or not isinstance(normalized_assignments, dict)
        or normalized_assignments.get(role) != assigned_route
        or not isinstance(normalized_reviewers, dict)
        or normalized_reviewers.get(role) != reviewer_route
        or assigned_route not in enabled_routes
        or reviewer_route not in enabled_routes
    ):
        raise ControlledClaimRejected(
            "controlled AI job routes do not exactly match enabled settings"
        )
    return {
        "expected_assigned_route": assigned_route,
        "expected_reviewer_route": reviewer_route,
        "reviewer_required": True,
    }


def controlled_claim_expectations(
    args: argparse.Namespace,
    selected: sqlite3.Row,
    job_payload: dict[str, object],
) -> dict[str, object]:
    """Validate the read-only candidate before asking for an exact atomic claim."""
    expected_group_id = str(
        getattr(args, "only_group_id", "") or ""
    ).strip().lower()
    expected_alert_id = str(
        getattr(args, "only_alert_id", "") or ""
    ).strip()
    expected_stable_group_key = str(
        getattr(args, "only_stable_group_key", "") or ""
    )
    expected_dispatch_id = str(
        getattr(args, "only_dispatch_id", "") or ""
    ).strip()
    identity = (
        expected_group_id,
        expected_alert_id,
        expected_stable_group_key,
        expected_dispatch_id,
    )
    if not any(identity):
        return {}
    if not all(identity):
        raise ControlledClaimRejected(
            "controlled AI run identity arguments are incomplete"
        )
    if not valid_controlled_stable_group_key(expected_stable_group_key):
        raise ControlledClaimRejected(
            "controlled AI run stable group key is invalid"
        )
    require_controlled_release_attestation(job_payload)
    route_contract = controlled_job_route_contract(args, job_payload)
    try:
        expected_job_id = int(selected["durable_job_id"] or 0)
    except (IndexError, KeyError, TypeError, ValueError):
        expected_job_id = 0
    if expected_job_id < 1:
        raise ControlledClaimRejected(
            "controlled AI run requires an exact durable AI job"
        )
    payload_alert_id = str(job_payload.get("alert_id") or "").strip()
    payload_representative_alert_id = str(
        job_payload.get("representative_alert_id") or ""
    ).strip()
    payload_group_id = str(job_payload.get("group_id") or "").strip().lower()
    payload_stable_group_id = str(
        job_payload.get("stable_group_id") or ""
    ).strip().lower()
    if (
        payload_alert_id != expected_alert_id
        or payload_representative_alert_id != expected_alert_id
        or payload_group_id != expected_group_id
        or payload_stable_group_id != expected_group_id
        or not valid_controlled_stable_group_key(
            job_payload.get("stable_group_key")
        )
        or job_payload.get("stable_group_key") != expected_stable_group_key
        or str(job_payload.get("dispatch_id") or "").strip()
        != expected_dispatch_id
    ):
        raise ControlledClaimRejected(
            "controlled durable AI candidate no longer matches the frozen dispatch"
        )
    return {
        "expected_job_id": expected_job_id,
        "expected_representative_alert_id": expected_alert_id,
        "expected_dispatch_id": expected_dispatch_id,
        "expected_stable_group_key": expected_stable_group_key,
        **route_contract,
    }


def bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def run_command(
    cmd: list[str],
    *,
    timeout_seconds: float,
    max_stdout_bytes: int = DEFAULT_MAX_CHILD_STDOUT_BYTES,
    max_stderr_bytes: int = DEFAULT_MAX_CHILD_STDERR_BYTES,
    env: dict[str, str] | None = None,
    progress_callback=None,
    progress_interval_seconds: float = 30,
):
    """Run one trusted helper with bounded time, memory, and descendants."""
    print("running:", " ".join(cmd), flush=True)
    return run_bounded_command(
        cmd,
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
        env=env,
        progress_callback=progress_callback,
        progress_interval_seconds=progress_interval_seconds,
    )


def collect_incident_evidence(alert_id: str, args: argparse.Namespace, *, progress_callback=None) -> Path:
    collector = Path(__file__).with_name("collect-incident-evidence.py")
    proc = run_command(
        [
            sys.executable,
            str(collector),
            "--alert-id",
            alert_id,
            "--db",
            str(args.db),
            "--config",
            str(args.incident_evidence_config),
            "--out-dir",
            str(args.incident_evidence_dir),
        ],
        timeout_seconds=360,
        max_stdout_bytes=1024 * 1024,
        max_stderr_bytes=DEFAULT_MAX_CHILD_STDERR_BYTES,
        progress_callback=progress_callback,
        progress_interval_seconds=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"incident evidence collector failed rc={proc.returncode}")
    output_lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not output_lines:
        raise RuntimeError("incident evidence collector returned no artifact path")
    artifact = Path(output_lines[-1])
    try:
        artifact.resolve().relative_to(args.incident_evidence_dir.resolve())
    except ValueError as exc:
        raise RuntimeError("incident evidence collector returned a path outside its configured directory") from exc
    if not artifact.is_file():
        raise RuntimeError("incident evidence collector did not publish its artifact")
    return artifact


def build_prompt(
    alert_id: str,
    args: argparse.Namespace,
    job_payload: dict[str, object] | None = None,
    incident_evidence_path: Path | None = None,
) -> Path:
    builder = Path(__file__).with_name("build-ai-investigation-prompt.py")
    job_payload = job_payload or {}
    related_limit = bounded_int(job_payload.get("related_limit"), args.related_limit, 1, 500)
    pcap_analysis_limit = bounded_int(job_payload.get("pcap_analysis_limit"), 8, 1, 25)
    agent_role = str(job_payload.get("agent_role") or "soc-analyst")
    prompt_limit = effective_initial_prompt_package_limit(
        args,
        agent_role=agent_role,
    )
    config_dir = Path(args.ai_settings_file).parent
    cmd = [
        sys.executable,
        str(builder),
        "--db",
        str(getattr(args, "db", DEFAULT_DB)),
        "--alert-id",
        alert_id,
        "--out-dir",
        str(args.prompt_dir),
        "--rollup-dir",
        str(getattr(args, "rollup_dir", DEFAULT_ROLLUP_DIR)),
        "--related-limit",
        str(related_limit),
        "--correlation-limit",
        str(args.correlation_limit),
        "--correlation-min-score",
        str(args.correlation_min_score),
        "--pcap-analysis-limit",
        str(pcap_analysis_limit),
        "--max-package-bytes",
        str(prompt_limit),
        "--agent-role",
        agent_role,
        "--system-prompt-file",
        str(role_prompt_file(config_dir, agent_role)),
        "--second-opinion-prompt-file",
        str(role_second_opinion_prompt_file(config_dir, agent_role)),
        "--agent-memory-file",
        str(
            role_memory_file(
                getattr(args, "agent_memory_dir", DEFAULT_AGENT_MEMORY_DIR),
                agent_role,
            )
        ),
        "--shared-memory-file",
        str(getattr(args, "shared_memory_file", DEFAULT_SHARED_MEMORY_FILE)),
        "--pcap-analysis-dir",
        str(getattr(args, "pcap_analysis_dir", DEFAULT_PCAP_ANALYSIS_DIR)),
        "--analysis-dir",
        str(getattr(args, "prior_analysis_dir", DEFAULT_ANALYSIS_DIR)),
        "--asset-inventory-file",
        str(getattr(args, "asset_inventory_file", DEFAULT_ASSET_INVENTORY_FILE)),
        "--detection-playbooks",
        str(
            getattr(
                args,
                "detection_playbooks",
                DEFAULT_DETECTION_PLAYBOOKS,
            )
        ),
        "--investigation-skills",
        str(
            getattr(
                args,
                "investigation_skills",
                DEFAULT_INVESTIGATION_SKILLS,
            )
        ),
    ]
    if incident_evidence_path is not None:
        cmd.extend(["--incident-evidence-file", str(incident_evidence_path)])
    if job_payload.get("manual_reanalysis") is True:
        cmd.append("--blind-reanalysis")
    if args.include_tests:
        cmd.append("--include-tests")
    proc = run_command(
        cmd,
        timeout_seconds=180,
        max_stdout_bytes=1024 * 1024,
        max_stderr_bytes=DEFAULT_MAX_CHILD_STDERR_BYTES,
    )
    if proc.returncode != 0:
        if proc.stderr:
            print(proc.stderr, file=sys.stderr, end="")
        # Preserve the bounded terminal diagnostic so deterministic admission
        # failures (especially an irreducibly oversized package) are retired
        # instead of being retried forever under the generic wrapper error.
        stderr_lines = [
            line.strip()
            for line in str(proc.stderr or "").splitlines()
            if line.strip()
        ]
        detail = stderr_lines[-1][:700] if stderr_lines else ""
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(
            f"prompt builder failed rc={proc.returncode}{suffix}"
        )
    output_lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not output_lines:
        raise RuntimeError("prompt builder returned no output path")
    prompt_path = Path(output_lines[-1])
    if not prompt_path.exists():
        raise RuntimeError(f"prompt builder did not create a prompt package: {prompt_path}")
    try:
        prompt_path.resolve().relative_to(args.prompt_dir.resolve())
    except ValueError as exc:
        raise RuntimeError("prompt builder returned a path outside the configured prompt directory") from exc
    if prompt_path.stat().st_size > prompt_limit:
        raise RuntimeError(
            f"prompt package exceeded the {prompt_limit}-byte worker limit"
        )
    return prompt_path


def analysis_command(
    prompt_path: Path,
    args: argparse.Namespace,
    *,
    reanalysis_attempt_id: str = "",
    agent_role: str = "",
) -> list[str]:
    agent_role = str(agent_role or "soc-analyst")
    runner = Path(__file__).with_name("run-local-ai-analysis.py")
    cmd = [
        sys.executable,
        str(runner),
        "--prompt-package",
        str(prompt_path),
        "--prompt-dir",
        str(getattr(args, "prompt_dir", DEFAULT_PROMPT_DIR)),
        "--out-dir",
        str(args.analysis_dir),
        "--timeout",
        str(args.timeout),
        "--max-prompt-bytes",
        str(
            effective_prompt_package_limit(
                args,
                agent_role=agent_role,
            )
        ),
        "--alert-store-url",
        args.alert_store_url,
        "--ai-settings-file",
        str(args.ai_settings_file),
        "--investigation-harness-policy",
        str(
            getattr(
                args,
                "investigation_harness_policy",
                DEFAULT_INVESTIGATION_HARNESS_POLICY,
            )
        ),
        "--system-prompt-file",
        str(
            role_prompt_file(
                Path(args.ai_settings_file).parent,
                agent_role,
            )
        ),
        "--second-opinion-prompt-file",
        str(
            role_second_opinion_prompt_file(
                Path(args.ai_settings_file).parent,
                agent_role,
            )
        ),
        "--disagreement-adjudicator-prompt-file",
        str(
            getattr(
                args,
                "disagreement_adjudicator_prompt_file",
                DEFAULT_DISAGREEMENT_ADJUDICATOR_PROMPT,
            )
        ),
        "--live-osquery-config",
        str(getattr(args, "live_osquery_config", DEFAULT_LIVE_OSQUERY_CONFIG)),
        "--incident-evidence-config",
        str(
            getattr(
                args,
                "incident_evidence_config",
                DEFAULT_INCIDENT_EVIDENCE_CONFIG,
            )
        ),
        "--investigation-pivot-dir",
        str(
            getattr(
                args,
                "investigation_pivot_dir",
                DEFAULT_INVESTIGATION_PIVOT_DIR,
            )
        ),
    ]
    if args.model:
        cmd.extend(["--model", args.model])
    if reanalysis_attempt_id:
        cmd.extend(["--reanalysis-attempt-id", reanalysis_attempt_id])
    return cmd


def run_analysis(
    prompt_path: Path,
    args: argparse.Namespace,
    *,
    progress_callback=None,
    reanalysis_attempt_id: str = "",
    agent_role: str = "",
    controlled_result_identity: dict[str, object] | None = None,
):
    cmd = analysis_command(
        prompt_path,
        args,
        reanalysis_attempt_id=reanalysis_attempt_id,
        agent_role=agent_role,
    )
    # One durable analysis may now include the initial inference, as many as
    # three bounded evidence-pivot follow-ups, and an independent review.  The
    # child enforces the per-call timeout and query budgets; this outer watchdog
    # must not terminate a healthy multi-turn investigation after only one
    # model-call allowance.
    worker_timeout = (args.timeout * 5) + 300
    child_environment = None
    if controlled_result_identity:
        field_environment = {
            "job_id": "ONION_SENTINEL_EVALUATION_JOB_ID",
            "job_type": "ONION_SENTINEL_EVALUATION_JOB_TYPE",
            "lease_token": "ONION_SENTINEL_EVALUATION_LEASE_TOKEN",
            "cohort_id": "ONION_SENTINEL_EVALUATION_COHORT_ID",
            "dispatch_id": "ONION_SENTINEL_EVALUATION_DISPATCH_ID",
            "representative_alert_id": (
                "ONION_SENTINEL_EVALUATION_REPRESENTATIVE_ALERT_ID"
            ),
            "stable_group_id": (
                "ONION_SENTINEL_EVALUATION_STABLE_GROUP_ID"
            ),
            "stable_group_key": (
                "ONION_SENTINEL_EVALUATION_STABLE_GROUP_KEY"
            ),
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
            "reviewer_required": (
                "ONION_SENTINEL_EVALUATION_REVIEWER_REQUIRED"
            ),
        }
        child_environment = dict(os.environ)
        evaluation_token = (
            str(
                os.environ.get(CONTROLLED_EVALUATION_TOKEN_ENV)
                or ""
            ).strip()
            or _CONTROLLED_EVALUATION_TOKEN
        )
        if CONTROLLED_EVALUATION_TOKEN_RE.fullmatch(evaluation_token):
            child_environment[
                CONTROLLED_EVALUATION_TOKEN_ENV
            ] = evaluation_token
        child_environment["TMPDIR"] = str(os.environ["TMPDIR"])
        for field, environment_key in field_environment.items():
            value = controlled_result_identity.get(field)
            child_environment[environment_key] = (
                "1" if field == "reviewer_required" and value is True
                else str(value or "")
            )
    return run_command(
        cmd,
        timeout_seconds=worker_timeout,
        max_stdout_bytes=DEFAULT_MAX_CHILD_STDOUT_BYTES,
        max_stderr_bytes=DEFAULT_MAX_CHILD_STDERR_BYTES,
        env=child_environment,
        progress_callback=progress_callback,
        progress_interval_seconds=60,
    )


def flush_deferred_analysis_results(args: argparse.Namespace) -> None:
    """Publish locally spooled result indexes before scheduling new GPU work."""
    runner = Path(__file__).with_name("run-local-ai-analysis.py")
    proc = run_command(
        [
            sys.executable,
            str(runner),
            "--flush-index-only",
            "--alert-store-url",
            args.alert_store_url,
        ],
        timeout_seconds=60,
        max_stdout_bytes=1024 * 1024,
        max_stderr_bytes=1024 * 1024,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"rc={proc.returncode}"
        raise RuntimeError(f"deferred analysis index flush failed: {detail}")


def signal_dashboard_refresh(
    args: argparse.Namespace,
    *,
    controlled_evaluation: bool = False,
) -> None:
    """Wake the independent portal worker without delaying local inference.

    The Web UI polls fast-changing AI state from the API. Static dashboard
    generation is therefore eventual presentation work and must never sit on
    the alert-analysis critical path.
    """
    if (
        args.no_portal_refresh
        or controlled_evaluation
    ):
        return
    try:
        args.portal_wake_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        args.portal_wake_file.write_text(f"{project_now()} ai-analysis-complete\n", encoding="utf-8")
        args.portal_wake_file.chmod(0o600)
    except OSError as error:
        # Durable AI completion remains authoritative even if presentation
        # refresh signaling is temporarily unavailable.
        print(f"dashboard refresh signal failed: {error}", file=sys.stderr)


def consume_wake_marker(path: Path) -> None:
    """Clear the event that launched this run so later work is not lost.

    If durable work arrives while the worker is active, alert-store recreates
    the marker. launchd then observes a pending path event and starts another
    pass after this process exits.
    """
    try:
        path.unlink(missing_ok=True)
    except OSError as error:
        print(f"AI wake marker could not be consumed: {error}", file=sys.stderr)


def maintenance_drain_active(path: Path) -> tuple[bool, str]:
    """Fail closed when a maintenance marker exists but is not trustworthy.

    The marker is an operator control, not job input.  Requiring an owner-only
    regular file prevents another local account, directory swap, or symlink
    from silently controlling scheduler availability.  An unsafe marker still
    drains the worker so an operator can repair it without new claims racing
    the maintenance window.
    """
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False, ""
    except OSError as error:
        return True, f"maintenance drain marker cannot be inspected: {error}"
    if not stat.S_ISREG(metadata.st_mode):
        return True, "maintenance drain marker is not a regular file"
    if metadata.st_uid != os.getuid():
        return True, "maintenance drain marker is not owned by the worker account"
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        return True, "maintenance drain marker is not owner-only"
    if metadata.st_size > 4096:
        return True, "maintenance drain marker exceeds its byte limit"
    return True, "maintenance drain requested"


def stop_for_maintenance_drain(path: Path) -> bool:
    active, detail = maintenance_drain_active(path)
    if active:
        print(f"{project_now()} {detail}; no additional AI work will be claimed", flush=True)
    return active


def reconcile_worker_state(
    args: argparse.Namespace,
    indexed_mode: bool,
    *,
    controlled_evaluation: bool = False,
) -> int:
    """Reconcile durable queue state without scanning artifacts in modern mode."""
    if controlled_evaluation:
        # A controlled cohort invocation owns exactly one freshly dispatched
        # durable job. Global reconciliation could otherwise complete unrelated
        # production jobs whose older artifacts happen to be current.
        return 0
    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        if indexed_mode:
            completed_group_ids = indexed_reconcilable_ai_job_ids(conn)
        else:
            analyzed_ids = analyzed_alert_ids(args.analysis_dir, args.pcap_analysis_dir, args.prompt_dir)
            completed_group_ids = reconcilable_ai_job_ids(
                conn,
                analyzed_ids,
                args.analysis_dir,
                args.pcap_analysis_dir,
                args.prompt_dir,
            )
    finally:
        conn.close()
    return reconcile_completed_ai_jobs(args.alert_store_url, completed_group_ids)


def terminal_success_recovery_candidates(
    alert_conn: sqlite3.Connection,
    harness_conn: sqlite3.Connection,
    provider_lane: str,
    *,
    limit: int = 32,
) -> list[dict[str, object]]:
    """Compatibility delegate for exact terminal-success proof."""
    return load_terminal_success_recovery_candidates(
        alert_conn,
        harness_conn,
        provider_lane,
        limit=limit,
    )


def scheduler_read_only_connection(path: Path) -> sqlite3.Connection:
    """Open a SQLite database without granting mutation capability."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def terminal_recovery_sources() -> TerminalRecoverySources:
    """Bind recovery services at call time for compatibility and testing."""
    return TerminalRecoverySources(
        connect_read_only=scheduler_read_only_connection,
        path_exists=lambda path: path.exists(),
        load_candidates=load_terminal_success_recovery_candidates,
        report_status=report_ai_job_status,
    )


def reconcile_terminal_success_durable_jobs(args: argparse.Namespace) -> int:
    """Compatibility delegate for exact stranded-lease recovery."""
    provider_lane = str(getattr(args, "provider_lane", "any") or "any")
    harness_db = Path(
        getattr(args, "harness_db", args.db.parent / "investigation-harness.sqlite3")
    )
    return reconcile_terminal_success(
        terminal_recovery_sources(),
        alert_db=args.db,
        harness_db=harness_db,
        provider_lane=provider_lane,
        alert_store_url=args.alert_store_url,
    )


def detect_indexed_scheduler_mode(path: Path) -> bool:
    """Inspect scheduler schema without granting database mutation access."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return indexed_scheduler_available(conn)
    finally:
        conn.close()


def scheduler_startup_sources() -> SchedulerStartupSources:
    """Bind startup services at call time for compatibility and testing."""
    return SchedulerStartupSources(
        stop_for_drain=stop_for_maintenance_drain,
        controlled_runtime=controlled_evaluation_runtime,
        consume_controlled_token=consume_controlled_evaluation_token,
        require_capacity=require_runtime_capacity,
        path_exists=lambda path: path.exists(),
        consume_wake_marker=consume_wake_marker,
        detect_indexed_mode=detect_indexed_scheduler_mode,
        recover_controlled_spool=recover_controlled_evaluation_spool,
        flush_deferred_results=flush_deferred_analysis_results,
        recover_terminal_success=reconcile_terminal_success_durable_jobs,
        reconcile_worker_state=reconcile_worker_state,
        emit=lambda message: print(message, flush=True),
        emit_error=lambda message: print(message, file=sys.stderr),
        now=project_now,
    )


def scheduler_settlement_sources() -> SchedulerSettlementSources:
    """Bind post-drain settlement effects at call time."""
    return SchedulerSettlementSources(
        signal_dashboard_refresh=signal_dashboard_refresh,
        reconcile_worker_state=reconcile_worker_state,
        emit=lambda message: print(message, flush=True),
        emit_error=lambda message: print(message, file=sys.stderr),
        now=project_now,
        controlled_failure_exit_code=CONTROLLED_SELECTED_JOB_FAILURE_EXIT_CODE,
    )


def scheduler_claim_sources() -> SchedulerClaimSources:
    """Bind exact claim and server-authoritative identity services."""
    return SchedulerClaimSources(
        exact_expectations=controlled_claim_expectations,
        report_status=report_ai_job_status,
        load_claimed_job=claimed_durable_ai_job,
        require_controlled_identity=require_controlled_claim_identity,
        job_reanalysis_attempt_id=job_reanalysis_attempt_id,
        emit=lambda message: print(message, flush=True),
        now=project_now,
    )


def scheduler_execution_sources() -> SchedulerExecutionSources:
    """Bind evidence, prompt, lease-renewal, and runner services."""
    return SchedulerExecutionSources(
        report_status=report_ai_job_status,
        validate_controlled_route=controlled_job_route_contract,
        collect_incident_evidence=collect_incident_evidence,
        build_prompt=build_prompt,
        reusable_prompt=reusable_prompt_for_alert,
        run_analysis=run_analysis,
    )


def scheduler_outcome_sources() -> SchedulerOutcomeSources:
    """Bind status reporting, spool recovery, and output effects."""
    return SchedulerOutcomeSources(
        report_status=report_ai_job_status,
        failure_is_retryable=ai_failure_is_retryable,
        recover_controlled_spool=recover_controlled_evaluation_spool,
        controlled_spool_pending=controlled_recovery_spool_pending,
        now=project_now,
        emit=lambda message: print(message, flush=True),
        emit_error=lambda message: print(message, file=sys.stderr),
        write_stdout=lambda message: print(message, end=""),
        write_stderr=lambda message: print(message, file=sys.stderr, end=""),
        result_submission_indeterminate_marker=(
            CONTROLLED_RESULT_SUBMISSION_INDETERMINATE
        ),
    )


def scheduler_drain_sources() -> SchedulerDrainSources:
    """Bind queue selection and drain-loop projection services."""
    def open_readonly_database(database_path: Path) -> sqlite3.Connection:
        connection = sqlite3.connect(
            f"file:{database_path}?mode=ro",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        return connection

    return SchedulerDrainSources(
        stop_for_drain=stop_for_maintenance_drain,
        configured_levels=configured_analysis_levels,
        open_readonly_database=open_readonly_database,
        select_indexed=select_next_alert_indexed,
        select_legacy=select_next_alert,
        analyzed_alert_ids=analyzed_alert_ids,
        alert_group_key=alert_group_key,
        alert_group_id=alert_group_id,
        durable_payload=durable_payload,
        now=project_now,
        emit=lambda message: print(message, flush=True),
    )


def scheduler_worker_sources() -> SchedulerWorkerSources:
    """Bind the per-selection scheduler application workflow."""
    return SchedulerWorkerSources(
        acquire_claim=acquire_scheduler_claim,
        claim_sources=scheduler_claim_sources,
        execute_analysis=execute_scheduler_analysis,
        execution_sources=scheduler_execution_sources,
        handle_process_outcome=handle_process_outcome,
        handle_claim_rejection=handle_controlled_claim_rejection,
        handle_exception=handle_scheduler_exception,
        outcome_sources=scheduler_outcome_sources,
        controlled_claim_error=ControlledClaimRejected,
        execution_errors=(BoundedProcessError, RuntimeError, OSError),
    )


def main() -> int:
    args = parse_args()
    startup_sources = scheduler_startup_sources()
    preflight = prepare_scheduler_run(
        startup_sources,
        args,
        drain_file=getattr(args, "drain_file", DEFAULT_DRAIN),
    )
    if not preflight.proceed:
        return preflight.exit_code
    controlled_evaluation_dir = preflight.controlled_evaluation_dir
    launch_levels = preflight.launch_levels

    args.lock_file.parent.mkdir(parents=True, exist_ok=True)
    with args.lock_file.open("w") as lock_handle:
        try:
            fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(f"{project_now()} another AI analysis run is already active")
            return 0

        initialization = initialize_scheduler_run(
            startup_sources,
            args,
            controlled_evaluation_dir=controlled_evaluation_dir,
        )
        if not initialization.proceed:
            return 0
        indexed_mode = initialization.indexed_mode
        drain_state = SchedulerDrainState()
        while True:
            selection = select_scheduler_work(
                scheduler_drain_sources(),
                args,
                drain_state,
                indexed_mode=indexed_mode,
                launch_levels=launch_levels,
                drain_file=getattr(args, "drain_file", DEFAULT_DRAIN),
            )
            if selection.disposition != "selected":
                break
            if process_scheduler_selection(
                scheduler_worker_sources(),
                args,
                drain_state,
                selection,
                indexed_mode=indexed_mode,
                controlled_evaluation_dir=controlled_evaluation_dir,
            ):
                break

        return settle_scheduler_run(
            scheduler_settlement_sources(),
            args,
            SchedulerSettlement(
                analyzed_count=drain_state.analyzed_count,
                indexed_mode=indexed_mode,
                controlled_evaluation=controlled_evaluation_dir is not None,
                controlled_owned_job_failed=(
                    drain_state.controlled_owned_job_failed
                ),
                controlled_failure_detail=drain_state.controlled_failure_detail,
                controlled_failure_group_id=(
                    drain_state.controlled_failure_group_id
                ),
            ),
        )


if __name__ == "__main__":
    raise SystemExit(main())
