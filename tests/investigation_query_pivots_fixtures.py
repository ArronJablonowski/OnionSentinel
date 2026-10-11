"""Focused tests for policy-brokered iterative Elastic/OQL pivots."""


from __future__ import annotations


import copy


import contextlib


import hashlib


import io


import importlib.machinery


import importlib.util


import inspect


import json


import subprocess


import sys


import tempfile


import unittest


from pathlib import Path


from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]


BIN_DIR = REPO_ROOT / "n8n" / "bin"


RELAY_APP_DIR = REPO_ROOT / "relay" / "app"


WRAPPER_PATH = REPO_ROOT / "security-onion" / "bin" / "export-incident-evidence"


COLLECTOR_PATH = BIN_DIR / "collect-investigation-pivots.py"


BROKER_PATH = RELAY_APP_DIR / "incident_evidence_broker.py"


COMPAT_V1_COLLECTOR_PATH = (
    REPO_ROOT
    / "n8n"
    / "compat"
    / "investigation-pivots-v1"
    / "collect-investigation-pivots.py"
)


if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))


if str(RELAY_APP_DIR) not in sys.path:
    sys.path.insert(0, str(RELAY_APP_DIR))


from investigation_query_contract import (  # noqa: E402
    ALERT_INDEX_SCOPE,
    EVENT_TUPLE_FIELDS,
    EVENT_TUPLE_PATHS,
    INVESTIGATION_QUERY_CONTRACT,
    OBSERVABLE_FIELDS,
    PACKS,
    InvestigationQueryContractError,
    authorize_investigation_query_request,
    build_query_dsl,
    canonical_digest,
    kql_equivalent,
    oql_equivalent,
    query_endpoint,
    result_coverage,
    validate_investigation_query_response,
)


import investigation_query_response as QUERY_RESPONSE  # noqa: E402


import investigation_query_authorization as QUERY_AUTHORIZATION  # noqa: E402


def load_source_module(name: str, path: Path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def context() -> dict:
    return {
        "context_id": "context-1",
        "case_id": "case-1",
        "group_id": "group-1",
        "actor_role": "incident_responder",
        "anchor": {
            "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
            "id": "anchor-1",
        },
        "anchor_time": "2026-07-24T12:00:00.000Z",
        "time_envelope": {
            "start": "2026-07-24T10:00:00.000Z",
            "end": "2026-07-24T16:00:00.000Z",
        },
        "permitted_observables": {
            "ips": ["192.0.2.10"],
            "domains": [],
            "hosts": [],
            "users": [],
        },
        "discovered_observables": [{
            "kind": "domains",
            "value": "example.test",
            "evidence_ref": "elastic:prior-query:hit-1",
        }],
    }


def proposal() -> dict:
    return {
        "query_contract": INVESTIGATION_QUERY_CONTRACT,
        "batch_id": "batch-1",
        "queries": [{
            "query_id": "query-1",
            "dialect": "oql",
            "pack": "dns_activity",
            "purpose": "correlate_observable",
            "window": {
                "start": "2026-07-24T11:00:00.000Z",
                "end": "2026-07-24T12:00:00.000Z",
            },
            "observables": {
                "ips": ["192.0.2.10"],
                "domains": ["example.test"],
                "hosts": [],
                "users": [],
            },
            "size": 25,
            "aggregation": "timeline",
        }],
    }


def role_aware_context() -> dict:
    value = context()
    value["permitted_observables"]["ips"] = [
        "192.0.2.10",
        "198.51.100.20",
    ]
    value["permitted_event_tuples"] = [{
        "event_tuple": {
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": 49152,
            "destination_port": 443,
            "transport": "tcp",
            "protocol": "tls",
            "community_id": "1:trusted-flow=",
            "rule_id": "2016150",
        },
        "role_semantics": "packet_direction",
        "source": "trusted_context",
        "evidence_ref": "context:event-tuple:trusted-flow",
    }]
    return value


def role_aware_proposal() -> dict:
    value = proposal()
    value["queries"][0].update({
        "dialect": "elastic",
        "pack": "alert_context",
        "observables": {
            "ips": ["192.0.2.10", "198.51.100.20"],
            "domains": [],
            "hosts": [],
            "users": [],
        },
        "event_tuple": dict(
            role_aware_context()["permitted_event_tuples"][0]["event_tuple"]
        ),
        "aggregation": "events",
    })
    return value


def search_result_for(query: dict, *, hit: bool = True) -> dict:
    dsl = build_query_dsl(query)
    scope = PACKS[query["pack"]]["indices"]
    endpoint = query_endpoint(scope)
    hits = (
        [{
            "id": "hit-1",
            "index": ".ds-logs-zeek-so-2026.07.24-000001",
            "source": {
                "@timestamp": "2026-07-24T11:30:00.000Z",
                "event": {"dataset": "zeek.dns"},
                "dns": {"question": {"name": "example.test"}},
            },
        }]
        if hit
        else []
    )
    kql = kql_equivalent(query)
    oql = oql_equivalent(query)
    return {
        **query,
        "request_item_digest": canonical_digest(query),
        "execution_backend": "so-elasticsearch-query",
        "execution_semantics": (
            "compiled_oql_equivalent"
            if query["dialect"] == "oql"
            else "compiled_elastic_pack"
        ),
        "kql_equivalent": kql,
        "kql_digest": hashlib.sha256(kql.encode()).hexdigest(),
        "oql_equivalent": oql,
        "oql_digest": hashlib.sha256(oql.encode()).hexdigest(),
        "query_dsl": dsl,
        "query_digest": canonical_digest(dsl),
        "index_scope": scope,
        "query_endpoint": endpoint,
        "execution_digest": canonical_digest({
            "index_scope": scope,
            "query_endpoint": endpoint,
            "query_dsl": dsl,
        }),
        "status": "ok",
        "semantic_valid": True,
        "total_hits": len(hits),
        "total_hits_relation": "eq",
        "returned_hits": len(hits),
        "truncated": False,
        "result_coverage": result_coverage(
            query,
            status="ok",
            total_hits=len(hits),
            total_hits_relation="eq",
            returned_hits=len(hits),
        ),
        "duration_ms": 5,
        "timed_out": False,
        "took_ms": 3,
        "shards": {
            "total": 2,
            "successful": 2,
            "skipped": 0,
            "failed": 0,
            "failures": [],
        },
        "hits": hits,
    }


def controls_for(anchor: dict) -> dict:
    positive_dsl = {
        "size": 1,
        "track_total_hits": True,
        "timeout": "30s",
        "_source": ["@timestamp", "event.dataset"],
        "query": {"ids": {"values": [anchor["id"]]}},
    }
    negative_dsl = {
        "size": 1,
        "track_total_hits": True,
        "timeout": "30s",
        "_source": ["@timestamp", "event.dataset"],
        "query": {
            "bool": {
                "filter": [{"ids": {"values": [anchor["id"]]}}],
                "must_not": [{"ids": {"values": [anchor["id"]]}}],
            }
        },
    }
    def audit(dsl: dict, scope: list[str]) -> dict:
        endpoint = query_endpoint(scope)
        return {
            "query_dsl": dsl,
            "query_digest": canonical_digest(dsl),
            "index_scope": scope,
            "query_endpoint": endpoint,
            "execution_digest": canonical_digest({
                "index_scope": scope,
                "query_endpoint": endpoint,
                "query_dsl": dsl,
            }),
        }

    common = {
        "status": "ok",
        "semantic_valid": True,
        "total_hits_relation": "eq",
        "truncated": False,
        "duration_ms": 5,
        "timed_out": False,
        "took_ms": 3,
        "shards": {
            "total": 1,
            "successful": 1,
            "skipped": 0,
            "failed": 0,
            "failures": [],
        },
    }
    return {
        "anchor": anchor,
        "positive_anchor": {
            "passed": True,
            **audit(positive_dsl, [anchor["index"]]),
            **common,
            "total_hits": 1,
            "returned_hits": 1,
            "hits": [{
                "id": anchor["id"],
                "index": anchor["index"],
                "source": {
                    "@timestamp": "2026-07-24T11:30:00.000Z",
                    "event": {"dataset": "suricata.alert"},
                },
            }],
        },
        "negative_filter": {
            "passed": True,
            **audit(negative_dsl, ALERT_INDEX_SCOPE),
            **common,
            "total_hits": 0,
            "returned_hits": 0,
            "hits": [],
        },
    }


def valid_response(request: dict) -> dict:
    return {
        "ok": True,
        "complete": True,
        "partial": False,
        "read_only": True,
        "query_contract": INVESTIGATION_QUERY_CONTRACT,
        "batch_id": request["batch_id"],
        "request_digest": canonical_digest(request),
        "generated_at": "2026-07-24T12:01:00Z",
        "results": [search_result_for(query) for query in request["queries"]],
        "controls": controls_for(request["authorization"]["anchor"]),
        "semantic_validity": {
            "transport_valid": True,
            "controls_valid": True,
            "query_execution_valid": True,
            "coverage_valid": True,
            "semantic_valid": True,
            "reasons": [],
        },
    }
