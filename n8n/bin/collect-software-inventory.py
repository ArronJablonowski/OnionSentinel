#!/usr/bin/env python3
"""CLI- and import-compatible facade for software inventory collection."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

import software_inventory_contract as _contract
import software_inventory_transport as _transport
import software_inventory_workflow as _workflow

from software_inventory_contract import *  # noqa: E402,F401,F403
from software_inventory_normalization import *  # noqa: E402,F401,F403
from software_inventory_normalization import _normalize_record  # noqa: E402,F401
from software_inventory_transport import *  # noqa: E402,F401,F403
from software_inventory_transport import _database_post  # noqa: E402,F401
from software_inventory_workflow import *  # noqa: E402,F401,F403

_PUBLISH_DATABASE_SNAPSHOT = _transport.publish_database_snapshot
_WORKFLOW_MAIN = _workflow.main

__all__ = [
    "CONTRACT",
    "SOURCE_POLICY",
    "SOURCES",
    "SoftwareInventoryError",
    "atomic_write_json",
    "build_request",
    "collect_snapshot",
    "collect_source",
    "disabled_state",
    "empty_state",
    "failed_state",
    "load_state",
    "main",
    "publish_database_snapshot",
    "validate_response",
    "validate_state",
]


def publish_database_snapshot(*args: Any, **kwargs: Any) -> Any:
    _transport._database_post = globals()["_database_post"]
    return _PUBLISH_DATABASE_SNAPSHOT(*args, **kwargs)


def main() -> int:
    _workflow.publish_database_snapshot = globals()["publish_database_snapshot"]
    return _WORKFLOW_MAIN()


if __name__ == "__main__":
    raise SystemExit(main())
