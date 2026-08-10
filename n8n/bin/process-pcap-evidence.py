#!/usr/bin/env python3
"""Import- and CLI-compatible facade for bounded PCAP evidence processing."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

import pcap_processor_contract as _contract
import pcap_processor_storage as _storage
import pcap_processor_zeek as _zeek
import pcap_processor_tshark as _tshark
import pcap_processor_workflow as _workflow

from pcap_processor_contract import *  # noqa: E402,F401,F403
from pcap_processor_storage import *  # noqa: E402,F401,F403
from pcap_processor_storage import _icmp_scope_match, _timestamp_epoch  # noqa: E402,F401
from pcap_processor_zeek import *  # noqa: E402,F401,F403
from pcap_processor_tshark import *  # noqa: E402,F401,F403
from pcap_processor_workflow import *  # noqa: E402,F401,F403

_STORAGE_SAFE_EXTRACT_TAR = _storage.safe_extract_tar
_STORAGE_SIGNATURE_CONTEXT = _storage.signature_context_for_request
_ZEEK_RUN = _zeek.run_zeek
_TSHARK_RUN = _tshark.run_tshark
_WORKFLOW_PROCESS_ONE = _workflow.process_one
_WORKFLOW_MAIN = _workflow.main

_COMPATIBILITY_WRAPPERS = {
    "main",
    "process_one",
    "run_tshark",
    "run_zeek",
    "safe_extract_tar",
    "signature_context_for_request",
}

def _sync_runtime_overrides() -> None:
    """Forward legacy module overrides to their owning implementation layer."""
    current = globals()
    for module in (_contract, _storage, _zeek, _tshark, _workflow):
        for name in tuple(vars(module)):
            if (
                not name.startswith("_")
                and name not in _COMPATIBILITY_WRAPPERS
                and name in current
            ):
                setattr(module, name, current[name])
    for name in ("run_zeek", "run_tshark", "signature_context_for_request"):
        setattr(_workflow, name, current[name])


def signature_context_for_request(*args: Any, **kwargs: Any) -> Any:
    _sync_runtime_overrides()
    return _STORAGE_SIGNATURE_CONTEXT(*args, **kwargs)


def safe_extract_tar(*args: Any, **kwargs: Any) -> Any:
    _sync_runtime_overrides()
    return _STORAGE_SAFE_EXTRACT_TAR(*args, **kwargs)


def run_zeek(*args: Any, **kwargs: Any) -> Any:
    _sync_runtime_overrides()
    return _ZEEK_RUN(*args, **kwargs)


def run_tshark(*args: Any, **kwargs: Any) -> Any:
    _sync_runtime_overrides()
    return _TSHARK_RUN(*args, **kwargs)


def process_one(*args: Any, **kwargs: Any) -> Any:
    _sync_runtime_overrides()
    return _WORKFLOW_PROCESS_ONE(*args, **kwargs)


def main() -> int:
    _sync_runtime_overrides()
    return _WORKFLOW_MAIN()


if __name__ == "__main__":
    raise SystemExit(main())
