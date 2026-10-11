"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from incident_evidence_contract_fixtures import (
    BIN_DIR,
    BUILDER_PATH,
    CONTRACT_PATH,
    Path,
    REPO_ROOT,
    copy,
    digest,
    elastic_result,
    evidence_artifact,
    execution_digest,
    hashlib,
    importlib,
    json,
    load_builder_module,
    load_contract_module,
    shutil,
    subprocess,
    sys,
    tempfile,
    unittest,
)

from incident_evidence_contract_fixtures_incidentevidencecontracttests import IncidentEvidenceContractTestsFixtures
from cases_incident_evidence_contract_incidentevidencecontracttests_accepts_complete_digest_matched_kql_and_dsl import IncidentEvidenceContractTestsAcceptsCompleteDigestMatchedKqlAndDslCases
from cases_incident_evidence_contract_incidentevidencecontracttests_anchorless_v2_request_is_accepted_only_as_semantically_partial import IncidentEvidenceContractTestsAnchorlessV2RequestIsAcceptedOnlyAsSemanticallyPartialCases


class IncidentEvidenceContractTests(
    IncidentEvidenceContractTestsAcceptsCompleteDigestMatchedKqlAndDslCases,
    IncidentEvidenceContractTestsAnchorlessV2RequestIsAcceptedOnlyAsSemanticallyPartialCases,
    IncidentEvidenceContractTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
