#!/usr/bin/env python3
"""Launchd-compatible Onion Sentinel AI scheduler facade.

The public module surface remains installed at import time for compatibility.
Cohesive scheduler modules own configuration, controlled-evaluation policy,
selection, durable job orchestration, runtime adapters, and application flow.
"""
from __future__ import annotations

import sys
from pathlib import Path


BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_facade import install_scheduler_facade


install_scheduler_facade(globals(), __file__)

_installed_parse_args = parse_args
_installed_run_analysis = run_analysis
_installed_reconcile_terminal_success = reconcile_terminal_success_durable_jobs
_installed_main = main


def parse_args():
    return _installed_parse_args()


def run_analysis(
    prompt_path,
    args,
    *,
    progress_callback=None,
    reanalysis_attempt_id="",
    agent_role="",
    controlled_result_identity=None,
):
    return _installed_run_analysis(
        prompt_path,
        args,
        progress_callback=progress_callback,
        reanalysis_attempt_id=reanalysis_attempt_id,
        agent_role=agent_role,
        controlled_result_identity=controlled_result_identity,
    )


def reconcile_terminal_success_durable_jobs(args):
    return _installed_reconcile_terminal_success(args)


def main() -> int:
    return _installed_main()


if __name__ == "__main__":
    raise SystemExit(main())
