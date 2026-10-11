from __future__ import annotations

from provider_neutral_investigation_loop_fixtures import (
    BIN_DIR,
    Path,
    REPO_ROOT,
    RecordingHarness,
    argparse,
    ast,
    copy,
    hashlib,
    importlib,
    json,
    load_module,
    mock,
    sys,
    tempfile,
    unittest,
)

class ProviderNeutralInvestigationLoopTestsFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_module(
            "provider_neutral_investigation_runner",
            BIN_DIR / "run-local-ai-analysis.py",
        )
        cls.builder = load_module(
            "provider_neutral_investigation_builder",
            BIN_DIR / "build-ai-investigation-prompt.py",
        )
        cls.contract = load_module(
            "provider_neutral_investigation_contract",
            BIN_DIR / "investigation_query_contract.py",
        )
        cls.harness = sys.modules["onion_sentinel_harness"]


    @staticmethod
    def elastic_request(query_id: str = "pivot-1") -> dict:
        return {
            "query_id": query_id,
            "backend": "elastic",
            "purpose": "correlate_observable",
            "parameters": {
                "pack": "network_flow",
                "window": {
                    "start": "2026-07-24T18:00:00Z",
                    "end": "2026-07-24T19:00:00Z",
                },
                "observables": {
                    "ips": ["192.0.2.10"],
                    "domains": [],
                    "hosts": [],
                    "users": [],
                },
                "size": 25,
                "aggregation": "events",
            },
        }


    @staticmethod
    def successful_security_onion_round(
        requests: list[dict],
        *,
        round_number: int,
    ) -> dict:
        query_digest = "a" * 64
        result_digest = "b" * 64
        query_ids = [item["query_id"] for item in requests]
        return {
            "schema": "onion-sentinel-investigation-query-results-v1",
            "round": round_number,
            "requests": copy.deepcopy(requests),
            "results": [
                {
                    "backend": "security_onion",
                    "query_ids": query_ids,
                    "status": "ok",
                    "read_only": True,
                    "evidence": {
                        "controls_valid": True,
                        "results": [
                            {
                                "query_id": query_id,
                                "status": "ok",
                                "returned_hits": 1,
                            }
                            for query_id in query_ids
                        ],
                    },
                    "trusted_query_audit": [
                        {
                            "query_id": query_id,
                            "status": "ok",
                            "query_digest": query_digest,
                            "result_digest": result_digest,
                            "evidence_ref": f"query:{query_digest}",
                            "returned_hits": 1,
                        }
                        for query_id in query_ids
                    ],
                }
            ],
            "audit": [
                {
                    "backend": "security_onion",
                    "complete": True,
                    "partial": False,
                    "read_only": True,
                }
            ],
        }


