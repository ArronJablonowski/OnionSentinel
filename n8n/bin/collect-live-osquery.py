#!/usr/bin/env python3
"""Operator CLI for one restricted live-host OSQuery request batch."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from live_osquery_client import (
    DEFAULT_CONFIG_FILE,
    LiveOsqueryClientError,
    collect_live_osquery,
    load_live_osquery_config,
)
from live_osquery_contract import LiveOsqueryContractError, MAX_RESPONSE_BYTES


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect a bounded live-host OSQuery artifact through the relay"
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_FILE)
    parser.add_argument(
        "--request",
        type=Path,
        help="JSON request file; stdin is used when omitted",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        raw = (
            args.request.read_bytes()
            if args.request
            else sys.stdin.buffer.read(MAX_RESPONSE_BYTES + 1)
        )
        if len(raw) > MAX_RESPONSE_BYTES:
            raise LiveOsqueryClientError("request exceeds the transport limit")
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise LiveOsqueryClientError("request must be a JSON object")
        artifact = collect_live_osquery(
            case_id=str(value.get("case_id") or ""),
            requests=value.get("requests"),
            config=load_live_osquery_config(args.config),
        )
        print(json.dumps(artifact, separators=(",", ":"), sort_keys=True))
        return 0
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        LiveOsqueryClientError,
        LiveOsqueryContractError,
    ) as exc:
        print(f"live OSQuery collection failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
