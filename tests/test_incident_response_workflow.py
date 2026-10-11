"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from incident_response_workflow_fixtures import (
    AI_RUNNER_PATH,
    ALERT_STORE_PATH,
    ANALYSIS_INDEX_PATH,
    ANALYSIS_REQUEST_ROUTES_PATH,
    APPLICATION_COMPOSITION_PATH,
    APPLICATION_GRAPH_RUNTIME_PATH,
    BUILDER_PATH,
    CONTROLLED_INCIDENT_COMPOSITION_PATH,
    DASHBOARD_DIR,
    INCIDENT_ANALYSIS_COMPLETION_PATH,
    INCIDENT_ANALYSIS_SCHEMA_PATH,
    INCIDENT_PAGE_PATH,
    INCIDENT_REANALYSIS_ATTEMPT_LIFECYCLE_PATH,
    INCIDENT_REANALYSIS_BINDING_PATH,
    INCIDENT_REANALYSIS_JOB_OWNERSHIP_PATH,
    INCIDENT_REANALYSIS_REQUEST_PATH,
    INCIDENT_REANALYSIS_RUN_PERSISTENCE_PATH,
    MANUAL_ANALYSIS_DISPATCH_PATH,
    PORTAL_HTTP_HANDLER_PATH,
    PORTAL_PATH,
    Path,
    REPO_ROOT,
    SHELL_PAGE_PATH,
    importlib,
    io,
    json,
    load_module,
    mock,
    sqlite3,
    sys,
    tempfile,
    unittest,
)

from incident_response_workflow_fixtures_incidentresponseworkflowtests import IncidentResponseWorkflowTestsFixtures
from cases_incident_response_workflow_incidentresponseworkflowtests_incident_agent_display_state_preserves_partial_success import IncidentResponseWorkflowTestsIncidentAgentDisplayStatePreservesPartialSuccessCases
from cases_incident_response_workflow_incidentresponseworkflowtests_incident_list_returns_case_and_only_incident_responder_analysis import IncidentResponseWorkflowTestsIncidentListReturnsCaseAndOnlyIncidentResponderAnalysisCases


class IncidentResponseWorkflowTests(
    IncidentResponseWorkflowTestsIncidentAgentDisplayStatePreservesPartialSuccessCases,
    IncidentResponseWorkflowTestsIncidentListReturnsCaseAndOnlyIncidentResponderAnalysisCases,
    IncidentResponseWorkflowTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
