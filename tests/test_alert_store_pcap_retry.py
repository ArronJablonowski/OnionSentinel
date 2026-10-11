"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from alert_store_pcap_retry_fixtures import (
    ALERT_STORE,
    ALERT_STORE_DIR,
    CONTROLLED_ROUTE_FIELDS,
    DEPLOYED_RELEASE,
    Path,
    REPO_ROOT,
    SCORING_RULES,
    available_port,
    closing,
    io,
    json,
    mock,
    os,
    request_json,
    socket,
    sqlite3,
    subprocess,
    tempfile,
    time,
    unittest,
    urllib,
)

from alert_store_pcap_retry_fixtures_requestjsonownershiptest import RequestJsonOwnershipTestFixtures
from cases_alert_store_pcap_retry_requestjsonownershiptest_http_error_response_is_closed_after_read import RequestJsonOwnershipTestHttpErrorResponseIsClosedAfterReadCases


class RequestJsonOwnershipTest(
    RequestJsonOwnershipTestHttpErrorResponseIsClosedAfterReadCases,
    RequestJsonOwnershipTestFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


from alert_store_pcap_retry_fixtures_alertstorepcapretrytest import AlertStorePcapRetryTestFixtures
from cases_alert_store_pcap_retry_alertstorepcapretrytest_exact_alert_pcap_uses_event_time_not_later_ingest_rollup import AlertStorePcapRetryTestExactAlertPcapUsesEventTimeNotLaterIngestRollupCases
from cases_alert_store_pcap_retry_alertstorepcapretrytest_production_claim_ignores_controlled_exact_identity_fields import AlertStorePcapRetryTestProductionClaimIgnoresControlledExactIdentityFieldsCases


class AlertStorePcapRetryTest(
    AlertStorePcapRetryTestExactAlertPcapUsesEventTimeNotLaterIngestRollupCases,
    AlertStorePcapRetryTestProductionClaimIgnoresControlledExactIdentityFieldsCases,
    AlertStorePcapRetryTestFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
