"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from soc_alert_summary_api_fixtures import (
    PORTAL_PATH,
    Path,
    REPO_ROOT,
    ThreadPoolExecutor,
    dt,
    importlib,
    json,
    load_portal,
    mock,
    sqlite3,
    sys,
    tempfile,
    time,
    unittest,
)

from soc_alert_summary_api_fixtures_socalertsummaryapitest import SocAlertSummaryApiTestFixtures
from cases_soc_alert_summary_api_socalertsummaryapitest_missing_reviewer_confidence_cannot_authorize_automation import SocAlertSummaryApiTestMissingReviewerConfidenceCannotAuthorizeAutomationCases
from cases_soc_alert_summary_api_socalertsummaryapitest_alert_list_marks_stale_no_matching_packets_pcap_request_for_retry import SocAlertSummaryApiTestAlertListMarksStaleNoMatchingPacketsPcapRequestForRetryCases
from cases_soc_alert_summary_api_socalertsummaryapitest_llm_analysis_log_includes_distinct_second_opinion_runs import SocAlertSummaryApiTestLlmAnalysisLogIncludesDistinctSecondOpinionRunsCases


class SocAlertSummaryApiTest(
    SocAlertSummaryApiTestMissingReviewerConfidenceCannotAuthorizeAutomationCases,
    SocAlertSummaryApiTestAlertListMarksStaleNoMatchingPacketsPcapRequestForRetryCases,
    SocAlertSummaryApiTestLlmAnalysisLogIncludesDistinctSecondOpinionRunsCases,
    SocAlertSummaryApiTestFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
