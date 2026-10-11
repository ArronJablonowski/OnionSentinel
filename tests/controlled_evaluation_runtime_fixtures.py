"""Fail-closed contracts for the isolated harness-evaluation runtime.

These tests use only loopback listeners, temporary SQLite databases, and
owner-only temporary directories.  They deliberately never contact the live
Onion Sentinel or Security Onion services.
"""


from __future__ import annotations


import datetime as dt


import hashlib


import importlib.util


import io


import json


import os


import shutil


import socket


import sqlite3


import subprocess


import sys


import tempfile


import threading


import time


import unittest


import urllib.error


import urllib.request


from contextlib import closing


from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


from pathlib import Path


from types import SimpleNamespace


from unittest import mock


from tests.dashboard_startup_diagnostics import startup_failure_diagnostic


ROOT = Path(__file__).resolve().parents[1]


ALERT_STORE_DIR = ROOT / "n8n" / "alert_store"


ALERT_STORE = ALERT_STORE_DIR / "alert_store.js"


SCORING_RULES = ALERT_STORE_DIR / "config" / "scoring_rules.json"


DASHBOARD_SERVER = (
    ROOT / "onion-sentinel-dashboard" / "onion_sentinel_server.py"
)


BIN_DIR = ROOT / "n8n" / "bin"


RUNNER_PATH = BIN_DIR / "run-local-ai-analysis.py"


PIPELINE_ADAPTER_PATH = BIN_DIR / "local_ai_pipeline_adapters.py"


SCHEDULER_PATH = BIN_DIR / "auto-run-ai-analysis.py"


INSTALLER_PATH = BIN_DIR / "install-macstudio-stack.zsh"


RELEASE_ID = "c" * 40


REPLACEMENT_RELEASE_ID = "f" * 40


EVALUATION_TOKEN = "9" * 64


PRIMARY_ROUTE = "codex-cli:gpt-5.5:high"


REVIEWER_ROUTE = "codex-cli:gpt-5.6-sol:xhigh"


CONTROLLED_ROUTE_FIELDS = {
    "expected_assigned_route": PRIMARY_ROUTE,
    "expected_reviewer_route": REVIEWER_ROUTE,
    "reviewer_required": True,
}


def write_controlled_route_fixture(
    runtime: Path,
    home: Path,
    *,
    name: str = "incident-evidence.json",
) -> tuple[Path, Path, Path]:
    """Create a synthetic exact Relay route without copying live key data."""
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    ssh_dir.chmod(0o700)
    ssh_key = ssh_dir / "onion-sentinel-incident-evidence_ed25519"
    known_hosts = runtime / "relay_known_hosts"
    ssh_key.write_text("synthetic-private-key-fixture\n", encoding="utf-8")
    known_hosts.write_text("synthetic-known-host-fixture\n", encoding="utf-8")
    ssh_key.chmod(0o600)
    known_hosts.chmod(0o600)
    route = runtime / name
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
    return route, ssh_key, known_hosts


CONTROLLED_CREDENTIAL_KEYS = {
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
    "N8N_POST_COMMIT_TOKEN",
    "ASSET_STORE_WRITE_TOKEN",
    "ABUSEIPDB_API_KEY",
    "GREYNOISE_API_KEY",
    "OTX_API_KEY",
    "URLHAUS_AUTH_KEY",
    "VIRUSTOTAL_API_KEY",
    "URLSCAN_API_KEY",
    "GOOGLE_SAFE_BROWSING_API_KEY",
    "PHISHTANK_API_KEY",
    "MALWAREBAZAAR_AUTH_KEY",
    "THREATFOX_AUTH_KEY",
    "SHODAN_API_KEY",
    "CENSYS_API_ID",
    "CENSYS_API_SECRET",
    "CENSYS_API_TOKEN",
    "CENSYS_ORGANIZATION_ID",
    "NVD_API_KEY",
}


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def sanitized_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for key in CONTROLLED_CREDENTIAL_KEYS:
        environment.pop(key, None)
    for key in (
        "ONION_SENTINEL_EVALUATION_MODE",
        "ONION_SENTINEL_EVALUATION_RUNTIME_DIR",
        "ONION_SENTINEL_EVALUATION_FREEZE_MEMORY",
        "ONION_SENTINEL_EVALUATION_TOKEN",
    ):
        environment.pop(key, None)
    return environment


def request_json(
    url: str,
    method: str = "GET",
    payload: dict | None = None,
    *,
    timeout: float = 3,
    evaluation_token: str = EVALUATION_TOKEN,
    request_headers: dict[str, str] | None = None,
) -> tuple[int, dict]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"} if body is not None else {}
    headers.update(request_headers or {})
    if body is not None and evaluation_token:
        headers["X-Onion-Sentinel-Evaluation-Token"] = evaluation_token
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return (
                int(response.status),
                json.loads(raw) if raw else {},
            )
    except urllib.error.HTTPError as error:
        try:
            raw = error.read()
            return (
                int(error.code),
                json.loads(raw) if raw else {},
            )
        finally:
            error.close()


def request_json_bytes(
    url: str,
    payload: dict,
    *,
    timeout: float = 3,
    evaluation_token: str = EVALUATION_TOKEN,
) -> tuple[int, bytes]:
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if evaluation_token:
        headers["X-Onion-Sentinel-Evaluation-Token"] = evaluation_token
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        try:
            return int(error.code), error.read()
        finally:
            error.close()


def request_status(
    url: str,
    method: str = "GET",
    *,
    timeout: float = 3,
) -> int:
    request = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read()
            return int(response.status)
    except urllib.error.HTTPError as error:
        try:
            error.read()
            return int(error.code)
        finally:
            error.close()


def raw_request_status(
    host: str,
    port: int,
    target: str,
    method: str = "GET",
    *,
    timeout: float = 3,
    evaluation_token: str = EVALUATION_TOKEN,
) -> int:
    body = b"{}" if method == "POST" else b""
    request = (
        f"{method} {target} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Connection: close\r\n"
        + (
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            + (
                "X-Onion-Sentinel-Evaluation-Token: "
                f"{evaluation_token}\r\n"
                if evaluation_token
                else ""
            )
            if body
            else ""
        )
        + "\r\n"
    ).encode("ascii") + body
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(request)
        response = connection.recv(4096)
    status_line = response.split(b"\r\n", 1)[0].decode("ascii")
    return int(status_line.split(" ", 2)[1])


def process_output(log_file) -> str:
    log_file.flush()
    log_file.seek(0)
    return log_file.read()


def stop_process(process: subprocess.Popen, *, graceful: bool = True) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5 if graceful else 2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def load_python_module(name: str, path: Path):
    if str(BIN_DIR) not in sys.path:
        sys.path.insert(0, str(BIN_DIR))
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
