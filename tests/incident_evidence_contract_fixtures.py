"""Regression tests for restricted Security Onion query provenance."""


from __future__ import annotations


import copy


import hashlib


import importlib.util


import json


import shutil


import subprocess


import sys


import tempfile


import unittest


from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


BIN_DIR = REPO_ROOT / "n8n" / "bin"


CONTRACT_PATH = BIN_DIR / "incident_evidence_contract.py"


BUILDER_PATH = BIN_DIR / "build-ai-investigation-prompt.py"


def load_contract_module():
    if str(BIN_DIR) not in sys.path:
        sys.path.insert(0, str(BIN_DIR))
    spec = importlib.util.spec_from_file_location("incident_evidence_contract_test", CONTRACT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_builder_module():
    if str(BIN_DIR) not in sys.path:
        sys.path.insert(0, str(BIN_DIR))
    spec = importlib.util.spec_from_file_location(
        "incident_evidence_prompt_builder_test",
        BUILDER_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def digest(query_dsl: dict) -> str:
    encoded = json.dumps(query_dsl, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def execution_digest(query_dsl: dict, index_scope: list[str], endpoint: str) -> str:
    encoded = json.dumps(
        {
            "index_scope": index_scope,
            "query_endpoint": endpoint,
            "query_dsl": query_dsl,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def elastic_result(
    query_dsl: dict,
    index_scope: list[str],
    *,
    status: str = "ok",
    hits: list[dict] | None = None,
) -> dict:
    hits = list(hits or [])
    endpoint = (
        f"{','.join(index_scope)}/_search"
        "?ignore_unavailable=true&expand_wildcards=open"
        "&preference=onion-sentinel-incident-evidence"
    )
    semantic_valid = status == "ok"
    return {
        "status": status,
        "semantic_valid": semantic_valid,
        "query_digest": digest(query_dsl),
        "execution_digest": execution_digest(query_dsl, index_scope, endpoint),
        "query_dsl": query_dsl,
        "index_scope": index_scope,
        "query_endpoint": endpoint,
        "total_hits": len(hits),
        "total_hits_relation": "eq",
        "returned_hits": len(hits),
        "truncated": False,
        "duration_ms": 12,
        "timed_out": status == "timeout",
        "took_ms": 4,
        "shards": {
            "total": 1,
            "successful": 1,
            "skipped": 0,
            "failed": 0,
            "failures": [],
        },
        "hits": hits,
    }


def evidence_artifact(*, status: str = "ok") -> dict:
    contract = load_contract_module()
    window = {"start": "2026-07-22T18:00:00Z", "end": "2026-07-22T19:00:00Z"}
    query_dsl = {
        "size": 25,
        "query": {"bool": {"filter": [{"term": {"source.ip": "192.0.2.10"}}]}},
    }
    anchor = {
        "index": ".ds-logs-suricata.alerts-so-2026.07.22-000001",
        "id": "elastic-anchor-unit",
    }
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
            },
        },
    }
    positive = elastic_result(
        positive_dsl,
        [anchor["index"]],
        hits=[{
            "id": anchor["id"],
            "index": anchor["index"],
            "source": {
                "@timestamp": "2026-07-22T18:30:00Z",
                "event": {"dataset": "suricata.alert"},
            },
        }],
    )
    positive["passed"] = True
    negative = elastic_result(negative_dsl, contract.ALERT_INDEX_SCOPE)
    negative["passed"] = True
    complete = status == "ok"
    pack_result = elastic_result(
        query_dsl,
        contract.PACK_INDEX_SCOPES["network_flow"],
        status=status,
    )
    pack_result.update({
        "pack": "network_flow",
        "kql_equivalent": 'source.ip : "192.0.2.10"',
        "window_index": 0,
        "window": window,
    })
    return {
        "schema": "onion-sentinel-incident-evidence-v2",
        "generated_at": "2026-07-22  13:00:00-06:00",
        "request": {
            "packs": ["network_flow"],
            "osquery_packs": ["system_inventory"],
            "windows": [window],
            "observables": {
                "ips": ["192.0.2.10"],
                "domains": [],
                "hosts": [],
                "users": [],
            },
            "size": 25,
            "anchor": anchor,
        },
        "security_onion_response": {
            "ok": True,
            "complete": complete,
            "partial": not complete,
            "read_only": True,
            "query_contract": "onion-sentinel-incident-evidence-v2",
            "observables": {
                "ips": ["192.0.2.10"],
                "domains": [],
                "hosts": [],
                "users": [],
            },
            "results": [pack_result],
            "osquery_results": [{
                "pack": "system_inventory",
                "target": "security-onion-local-host",
                "status": status,
                "query": contract.OSQUERY_PACKS["system_inventory"],
                "query_digest": hashlib.sha256(
                    contract.OSQUERY_PACKS["system_inventory"].encode("utf-8")
                ).hexdigest(),
                "total_rows": 1 if status == "ok" else 0,
                "returned_rows": 1 if status == "ok" else 0,
                "truncated": False,
                "duration_ms": 12,
                "rows": [{"hostname": "security-onion-test"}] if status == "ok" else [],
            }],
            "controls": {
                "anchor": anchor,
                "positive_anchor": positive,
                "negative_filter": negative,
            },
            "semantic_validity": {
                "transport_valid": True,
                "controls_valid": True,
                "query_execution_valid": complete,
                "coverage_valid": complete,
                "semantic_valid": complete,
                "reasons": [] if complete else [
                    "one or more Elasticsearch packs failed semantic validation",
                ],
            },
        },
    }
