"""Contracts for durable SOC-to-Incident-Response escalation."""


from __future__ import annotations


import importlib.util


import io


import json


import sqlite3


import sys


import tempfile


import unittest


from pathlib import Path


from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]


DASHBOARD_DIR = REPO_ROOT / "onion-sentinel-dashboard"


BUILDER_PATH = DASHBOARD_DIR / "scripts" / "build_soc_alerts_dashboard.py"


INCIDENT_PAGE_PATH = DASHBOARD_DIR / "scripts" / "dashboard_incident_response_page.py"


SHELL_PAGE_PATH = DASHBOARD_DIR / "scripts" / "dashboard_shell_page.py"


PORTAL_PATH = DASHBOARD_DIR / "report_portal.py"


PORTAL_HTTP_HANDLER_PATH = DASHBOARD_DIR / "portal_http_handler.py"


ALERT_STORE_PATH = REPO_ROOT / "n8n" / "alert_store" / "alert_store.js"


CONTROLLED_INCIDENT_COMPOSITION_PATH = (
    REPO_ROOT
    / "n8n"
    / "alert_store"
    / "composition"
    / "controlled_incident_composition.js"
)


APPLICATION_COMPOSITION_PATH = (
    REPO_ROOT / "n8n" / "alert_store" / "composition" / "application_composition.js"
)


APPLICATION_GRAPH_RUNTIME_PATH = (
    REPO_ROOT
    / "n8n"
    / "alert_store"
    / "composition"
    / "application_graph_runtime.js"
)


MANUAL_ANALYSIS_DISPATCH_PATH = (
    REPO_ROOT / "n8n" / "alert_store" / "services" / "manual_analysis_dispatch.js"
)


INCIDENT_ANALYSIS_SCHEMA_PATH = (
    REPO_ROOT / "n8n" / "alert_store" / "services" / "incident_analysis_schema.js"
)


INCIDENT_REANALYSIS_REQUEST_PATH = (
    REPO_ROOT / "n8n" / "alert_store" / "services" / "incident_reanalysis_request.js"
)


INCIDENT_REANALYSIS_RUN_PERSISTENCE_PATH = (
    REPO_ROOT
    / "n8n"
    / "alert_store"
    / "services"
    / "incident_reanalysis_run_persistence.js"
)


INCIDENT_REANALYSIS_JOB_OWNERSHIP_PATH = (
    REPO_ROOT
    / "n8n"
    / "alert_store"
    / "services"
    / "incident_reanalysis_job_ownership.js"
)


INCIDENT_REANALYSIS_ATTEMPT_LIFECYCLE_PATH = (
    REPO_ROOT
    / "n8n"
    / "alert_store"
    / "services"
    / "incident_reanalysis_attempt_lifecycle.js"
)


ANALYSIS_REQUEST_ROUTES_PATH = (
    REPO_ROOT / "n8n" / "alert_store" / "routes" / "analysis_request_routes.js"
)


INCIDENT_REANALYSIS_BINDING_PATH = (
    REPO_ROOT
    / "n8n"
    / "alert_store"
    / "services"
    / "incident_reanalysis_binding.js"
)


INCIDENT_ANALYSIS_COMPLETION_PATH = (
    REPO_ROOT
    / "n8n"
    / "alert_store"
    / "services"
    / "incident_analysis_completion.js"
)


AI_RUNNER_PATH = REPO_ROOT / "n8n" / "bin" / "run-local-ai-analysis.py"


ANALYSIS_INDEX_PATH = (
    REPO_ROOT
    / "n8n"
    / "onion_sentinel"
    / "analysis"
    / "persistence"
    / "analysis_index.py"
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
