from __future__ import annotations

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

class IncidentResponseWorkflowTestsFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "alerts.sqlite3"
        self.portal = load_module("incident_response_test_portal", PORTAL_PATH)
        self.portal.SOC_ALERT_STORE_DB = self.db_path


    def tearDown(self) -> None:
        self.tmp.cleanup()
