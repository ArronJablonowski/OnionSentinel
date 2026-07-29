#!/usr/bin/env python3
"""Run reviewed, read-only Security Onion queries through the SSH Relay."""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.machinery
import importlib.util
import json
import sys
from pathlib import Path

from security_jsonl_log import SecurityJsonlLogger


BIN_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = Path.home() / "n8n-local" / "config" / "dhcp-asset-discovery.json"
DEFAULT_LOG = Path.home() / "n8n-local" / "logs" / "security-onion-query.jsonl"


def load_dhcp_client():
    """Load the deployed collector without duplicating its transport contract."""
    path = BIN_DIR / "collect-dhcp-asset-discovery.py"
    loader = importlib.machinery.SourceFileLoader("onion_sentinel_dhcp_query_client", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise RuntimeError("DHCP query client could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


def bounded_integer(value: str, minimum: int, maximum: int, label: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{label} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise argparse.ArgumentTypeError(
            f"{label} must be from {minimum} through {maximum}"
        )
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Query Security Onion through the forced-command Relay. "
            "Only reviewed read-only query contracts are available."
        )
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    dhcp = subparsers.add_parser(
        "dhcp",
        help="return normalized Zeek DHCP observations",
    )
    dhcp.add_argument(
        "--minutes",
        type=lambda value: bounded_integer(value, 5, 1440, "minutes"),
        default=15,
        help="lookback window when explicit timestamps are omitted (5-1440)",
    )
    dhcp.add_argument(
        "--size",
        type=lambda value: bounded_integer(value, 1, 1000, "size"),
        default=100,
        help="maximum Security Onion documents to examine (1-1000)",
    )
    dhcp.add_argument("--start", help="explicit UTC/offset window start")
    dhcp.add_argument("--end", help="explicit UTC/offset window end")
    dhcp.add_argument(
        "--summary",
        action="store_true",
        help="print accounting and query audit without observation details",
    )
    return parser.parse_args()


def resolve_window(args: argparse.Namespace, client, now: dt.datetime) -> tuple[dt.datetime, dt.datetime]:
    if bool(args.start) != bool(args.end):
        raise ValueError("--start and --end must be supplied together")
    if args.start:
        start = client.parse_timestamp(args.start)
        end = client.parse_timestamp(args.end)
    else:
        end = now
        start = end - dt.timedelta(minutes=args.minutes)
    if start >= end or end - start > dt.timedelta(hours=24):
        raise ValueError("query window must be positive and no longer than 24 hours")
    if end > now + dt.timedelta(minutes=5):
        raise ValueError("query window ends too far in the future")
    return start, end


def summarized(response: dict) -> dict:
    return {
        key: response[key]
        for key in (
            "ok",
            "contract",
            "generated_at",
            "status",
            "window",
            "hits_total",
            "returned",
            "truncated",
            "query_audit",
        )
        if key in response
    }


def main() -> int:
    args = parse_args()
    logger = SecurityJsonlLogger(args.log, service="security-onion-query")
    try:
        client = load_dhcp_client()
        config = client.load_config(args.config)
        now = client.utc_now()
        start, end = resolve_window(args, client, now)
        response = client.query_dhcp(config, start, end, args.size)
        logger.log(
            "info",
            "security_onion_query.completed",
            operation=args.operation,
            status=response.get("status"),
            hits_total=response.get("hits_total"),
            returned=response.get("returned"),
            truncated=response.get("truncated"),
            window=response.get("window"),
            query_digest=(response.get("query_audit") or {}).get("query_digest"),
        )
        print(json.dumps(
            summarized(response) if args.summary else response,
            separators=(",", ":"),
            sort_keys=True,
        ))
        return 0
    except (
        OSError,
        RuntimeError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        message = " ".join(str(exc).split())[:300]
        logger.log(
            "error",
            "security_onion_query.failed",
            operation=args.operation,
            error=message,
        )
        print(f"Security Onion query failed: {message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
