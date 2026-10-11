"""Regression checks for local AI alert scheduler queue ordering."""


from __future__ import annotations


import importlib.util


import io


import json


import os


import sqlite3


import tempfile


import unittest


from pathlib import Path


from types import SimpleNamespace


from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]


SCHEDULER_PATH = REPO_ROOT / "n8n" / "bin" / "auto-run-ai-analysis.py"


DEPLOYED_RELEASE = "d" * 40


PRIMARY_ROUTE = "codex-cli:gpt-5.5:high"


REVIEWER_ROUTE = "codex-cli:gpt-5.6-sol:xhigh"


CONTROLLED_ROUTE_FIELDS = {
    "expected_assigned_route": PRIMARY_ROUTE,
    "expected_reviewer_route": REVIEWER_ROUTE,
    "reviewer_required": True,
}


def write_controlled_route_fixture(runtime: Path, home: Path) -> Path:
    """Create a synthetic exact Relay route without live credential material."""
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    ssh_dir.chmod(0o700)
    ssh_key = ssh_dir / "onion-sentinel-incident-evidence_ed25519"
    known_hosts = runtime / "relay_known_hosts"
    ssh_key.write_text("synthetic-private-key-fixture\n", encoding="utf-8")
    known_hosts.write_text("synthetic-known-host-fixture\n", encoding="utf-8")
    ssh_key.chmod(0o600)
    known_hosts.chmod(0o600)
    route = runtime / "incident-evidence.json"
    route.write_text(
        json.dumps(
            {
                "investigation_query_contract": (
                    "onion-sentinel-investigation-pivots-v2"
                ),
                "host": "10.88.8.8",
                "ssh_user": "aj",
                "ssh_key": str(ssh_key),
                "known_hosts": str(known_hosts),
                "connect_timeout_seconds": 20,
                "timeout_seconds": 420,
                "max_response_bytes": 8 * 1024 * 1024,
                "max_stderr_bytes": 256 * 1024,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    route.chmod(0o600)
    return route


def load_scheduler():
    spec = importlib.util.spec_from_file_location("auto_run_ai_analysis", SCHEDULER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module
