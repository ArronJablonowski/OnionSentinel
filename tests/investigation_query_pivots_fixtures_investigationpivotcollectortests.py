from __future__ import annotations

from investigation_query_pivots_fixtures import (
    ALERT_INDEX_SCOPE,
    BIN_DIR,
    BROKER_PATH,
    COLLECTOR_PATH,
    COMPAT_V1_COLLECTOR_PATH,
    EVENT_TUPLE_FIELDS,
    EVENT_TUPLE_PATHS,
    INVESTIGATION_QUERY_CONTRACT,
    InvestigationQueryContractError,
    OBSERVABLE_FIELDS,
    PACKS,
    Path,
    QUERY_AUTHORIZATION,
    QUERY_RESPONSE,
    RELAY_APP_DIR,
    REPO_ROOT,
    WRAPPER_PATH,
    authorize_investigation_query_request,
    build_query_dsl,
    canonical_digest,
    context,
    contextlib,
    controls_for,
    copy,
    hashlib,
    importlib,
    inspect,
    io,
    json,
    kql_equivalent,
    load_source_module,
    mock,
    oql_equivalent,
    proposal,
    query_endpoint,
    result_coverage,
    role_aware_context,
    role_aware_proposal,
    search_result_for,
    subprocess,
    sys,
    tempfile,
    unittest,
    valid_response,
    validate_investigation_query_response,
)

class InvestigationPivotCollectorTestsFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.collector = load_source_module("investigation_pivot_collector_test", COLLECTOR_PATH)
        cls.compat_v1_collector = load_source_module(
            "investigation_pivot_collector_v1_test",
            COMPAT_V1_COLLECTOR_PATH,
        )


