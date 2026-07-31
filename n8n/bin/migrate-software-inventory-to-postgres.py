#!/usr/bin/env python3
"""Import the current validated Software Inventory snapshot into PostgreSQL."""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path


HOME = Path.home()
DEFAULT_COLLECTOR = HOME / "n8n-local" / "bin" / "collect-software-inventory.py"
DEFAULT_STATE = (
    HOME / "n8n-local" / "software-inventory" / "software-inventory.json"
)
DEFAULT_ENV = HOME / "n8n-local" / ".env"


def load_collector(path: Path):
    spec = importlib.util.spec_from_file_location(
        "_onion_sentinel_software_inventory_collector",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("software inventory collector cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--collector", type=Path, default=DEFAULT_COLLECTOR)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--env", type=Path, default=DEFAULT_ENV)
    parser.add_argument("--api-url", default="http://127.0.0.1:8787")
    args = parser.parse_args()
    collector = load_collector(args.collector)
    state = collector.load_state(args.state)
    if not state["records"] or state["collection"]["complete"] is not True:
        raise SystemExit(
            "refusing to migrate an empty or incomplete Software Inventory"
        )
    result = collector.publish_database_snapshot(
        state,
        api_url=args.api_url,
        token=collector.database_write_token(args.env),
    )
    print(
        "Software Inventory PostgreSQL migration complete: "
        f"{result['records']} records, snapshot {result['snapshot_id']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
