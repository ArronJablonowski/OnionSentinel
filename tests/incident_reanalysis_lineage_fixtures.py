"""End-to-end regression checks for immutable Incident Responder rerun lineage."""


from __future__ import annotations


import datetime as dt


import hashlib


import importlib.util


import json


import os


import socket


import sqlite3


import subprocess


import tempfile


import time


import unittest


import urllib.error


import urllib.request


from contextlib import closing


from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


ALERT_STORE_DIR = REPO_ROOT / "n8n" / "alert_store"


ALERT_STORE = ALERT_STORE_DIR / "alert_store.js"


SCORING_RULES = ALERT_STORE_DIR / "config" / "scoring_rules.json"


DEPLOYED_RELEASE = "d" * 40


PRIMARY_ROUTE = "codex-cli:gpt-5.5:high"


REVIEWER_ROUTE = "codex-cli:gpt-5.6-sol:xhigh"


CONTROLLED_ROUTE_FIELDS = {
    "expected_assigned_route": PRIMARY_ROUTE,
    "expected_reviewer_route": REVIEWER_ROUTE,
    "reviewer_required": True,
}


COHORT_MODULE_PATH = (
    REPO_ROOT / "operations" / "cohort_runner_service.py"
)


COHORT_SPEC = importlib.util.spec_from_file_location(
    "run_incident_harness_cohort_for_lineage_test",
    COHORT_MODULE_PATH,
)


assert COHORT_SPEC and COHORT_SPEC.loader


cohort = importlib.util.module_from_spec(COHORT_SPEC)


COHORT_SPEC.loader.exec_module(cohort)


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request_json(
    url: str,
    method: str = "GET",
    payload: dict | None = None,
) -> tuple[int, dict]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"Content-Type": "application/json"} if body else {},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.loads(error.read())
        finally:
            error.close()
