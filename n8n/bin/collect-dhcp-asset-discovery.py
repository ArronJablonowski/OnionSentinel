#!/usr/bin/env python3
"""Compatibility CLI for bounded DHCP asset discovery through the SSH relay."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path


BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

import dhcp_asset_adapters as _adapters
import dhcp_asset_workflow as _workflow
from bounded_process import BoundedProcessError, run_bounded_command
from dhcp_asset_adapters import (
    asset_store_token,
    persist_database_state,
    relay_failure_diagnostic,
)
from dhcp_asset_contract import (
    CONTRACT,
    MAX_RESPONSE_OBSERVATIONS,
    STATE_SCHEMA,
    format_timestamp,
    observation_identity,
    parse_timestamp,
    utc_now,
    validate_response,
)
from dhcp_asset_state import (
    CONFIG_KEYS,
    MAX_CONFIG_BYTES,
    MAX_OBSERVATIONS,
    MAX_STATE_BYTES,
    atomic_write_json,
    bounded_json,
    empty_state,
    load_config,
    load_state,
    merge_observations,
)
from dhcp_asset_workflow import (
    MAX_BACKFILL_DAYS,
    MAX_BACKFILL_QUERY_SEGMENTS,
    MAX_QUERY_SEGMENTS,
    MIN_QUERY_SEGMENT,
    collection_window,
)
from security_jsonl_log import SecurityJsonlLogger


HOME = Path.home()
DEFAULT_CONFIG = HOME / "n8n-local" / "config" / "dhcp-asset-discovery.json"
DEFAULT_STATE = HOME / "n8n-local" / "asset-discovery" / "dhcp-observations.json"
DEFAULT_LOG = HOME / "n8n-local" / "logs" / "dhcp-asset-discovery.jsonl"
DEFAULT_ENV = HOME / "n8n-local" / ".env"
DEFAULT_ASSET_API_URL = "http://127.0.0.1:8787"


def query_dhcp(
    config: dict,
    start: dt.datetime,
    end: dt.datetime,
    size: int,
) -> dict:
    return _adapters.query_dhcp(
        config,
        start,
        end,
        size,
        now_fn=utc_now,
        run_command_fn=run_bounded_command,
        validate_response_fn=validate_response,
        diagnostic_fn=relay_failure_diagnostic,
    )


def query_complete_window(
    config: dict,
    start: dt.datetime,
    end: dt.datetime,
    size: int,
    *,
    max_segments: int = MAX_QUERY_SEGMENTS,
) -> dict:
    return _workflow.query_complete_window(
        config,
        start,
        end,
        size,
        max_segments=max_segments,
        query_fn=query_dhcp,
    )


def backfill(
    config: dict,
    state: dict,
    now: dt.datetime,
    days: int,
) -> dict:
    return _workflow.backfill(
        config,
        state,
        now,
        days,
        query_window_fn=query_complete_window,
        merge_fn=merge_observations,
    )


def collect(config: dict, state: dict, now: dt.datetime) -> dict:
    return _workflow.collect(
        config,
        state,
        now,
        collection_window_fn=collection_window,
        query_window_fn=query_complete_window,
        merge_fn=merge_observations,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--env", type=Path, default=DEFAULT_ENV)
    parser.add_argument("--asset-api-url", default=DEFAULT_ASSET_API_URL)
    parser.add_argument(
        "--require-database",
        action="store_true",
        help=(
            "fail closed unless PostgreSQL accepts the state before the JSON "
            "cache is written"
        ),
    )
    parser.add_argument(
        "--backfill-days",
        type=int,
        default=0,
        help=(
            "merge 1-30 historical 24-hour windows without moving the live "
            "checkpoint"
        ),
    )
    return parser


def _persist_if_required(args, state: dict) -> dict:
    if not args.require_database:
        return {}
    token = asset_store_token(args.env)
    return persist_database_state(args.asset_api_url, token, state)


def _successful_run(args, config: dict, state: dict, attempted_at: dt.datetime):
    if args.backfill_days:
        updated = backfill(config, state, attempted_at, args.backfill_days)
        return (
            updated, "dhcp_asset_discovery.backfill_completed",
            updated["backfill"]["status"], updated["backfill"]["last_returned"],
            updated["backfill"]["status"] != "ok",
        )
    updated = collect(config, state, attempted_at)
    return (
        updated, "dhcp_asset_discovery.completed",
        updated["collection"]["status"], updated["collection"]["last_returned"],
        updated["collection"]["last_truncated"],
    )


def _record_failure(args, attempted_at: dt.datetime, message: str) -> None:
    try:
        state = load_state(args.state)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        state = empty_state()
    state["updated_at"] = format_timestamp(attempted_at)
    state["collection"] = {
        **state.get("collection", {}),
        "status": "failed",
        "last_attempt_at": format_timestamp(attempted_at),
        "last_error": message,
    }
    try:
        _persist_if_required(args, state)
    except (OSError, UnicodeError, ValueError, RuntimeError, json.JSONDecodeError):
        pass
    try:
        atomic_write_json(args.state, state)
    except (OSError, ValueError):
        pass


def main() -> int:
    args = _parser().parse_args()
    logger = SecurityJsonlLogger(args.log, service="dhcp-asset-discovery")
    attempted_at = utc_now()
    try:
        config = load_config(args.config)
        state = load_state(args.state)
        if not config["enabled"]:
            state["updated_at"] = format_timestamp(attempted_at)
            state["collection"] = {
                **state.get("collection", {}),
                "status": "disabled",
                "last_attempt_at": format_timestamp(attempted_at),
                "last_error": "",
            }
            _persist_if_required(args, state)
            atomic_write_json(args.state, state)
            logger.log("info", "dhcp_asset_discovery.disabled", state_file=str(args.state))
            return 0
        updated, event, status, returned, truncated = _successful_run(
            args, config, state, attempted_at,
        )
        database_result = _persist_if_required(args, updated)
        atomic_write_json(args.state, updated)
        logger.log(
            "info",
            event,
            status=status,
            returned=returned,
            retained=len(updated["observations"]),
            database_retained=int(database_result.get("retained") or 0),
            truncated=truncated,
        )
        return 0
    except (
        BoundedProcessError,
        OSError,
        UnicodeError,
        ValueError,
        RuntimeError,
        json.JSONDecodeError,
    ) as exc:
        message = " ".join(str(exc).split())[:300]
        _record_failure(args, attempted_at, message)
        logger.log("error", "dhcp_asset_discovery.failed", error=message,
                   state_file=str(args.state))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
