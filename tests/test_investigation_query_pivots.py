#!/usr/bin/env python3
"""Focused tests for policy-brokered iterative Elastic/OQL pivots."""
from __future__ import annotations

import copy
import contextlib
import hashlib
import io
import importlib.machinery
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
WRAPPER_PATH = REPO_ROOT / "security-onion" / "bin" / "export-incident-evidence"
COLLECTOR_PATH = BIN_DIR / "collect-investigation-pivots.py"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

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


class InvestigationQueryContractTests(unittest.TestCase):
    def test_authorizes_base_and_evidence_discovered_observables(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())

        provenance = request["queries"][0]["observable_provenance"]
        self.assertEqual(provenance["ips"][0]["source"], "trusted_context")
        self.assertEqual(provenance["domains"][0], {
            "kind": "domains",
            "value": "example.test",
            "source": "prior_evidence",
            "evidence_ref": "elastic:prior-query:hit-1",
        })
        self.assertEqual(
            request["authorization"]["manifest_digest"],
            canonical_digest({
                key: value
                for key, value in request["authorization"].items()
                if key != "manifest_digest"
            }),
        )

    def test_model_cannot_supply_dsl_indices_fields_or_shell(self) -> None:
        for field, value in (
            ("query_dsl", {"match_all": {}}),
            ("indices", ["*"]),
            ("fields", ["*"]),
            ("shell", "id"),
        ):
            candidate = proposal()
            candidate["queries"][0][field] = value
            with self.subTest(field=field), self.assertRaises(
                InvestigationQueryContractError
            ):
                authorize_investigation_query_request(candidate, context())

    def test_untrusted_new_observable_and_out_of_envelope_window_fail(self) -> None:
        candidate = proposal()
        candidate["queries"][0]["observables"]["domains"] = ["untrusted.test"]
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "outside its trusted authorization context",
        ):
            authorize_investigation_query_request(candidate, context())

        candidate = proposal()
        candidate["queries"][0]["window"]["end"] = "2026-07-24T17:00:00.000Z"
        with self.assertRaisesRegex(InvestigationQueryContractError, "time envelope"):
            authorize_investigation_query_request(candidate, context())

    def test_anchor_index_cannot_expand_the_exact_positive_control_scope(self) -> None:
        candidate_context = context()
        candidate_context["anchor"]["index"] = (
            ".ds-logs-suricata.alerts-so-2026.07.24-000001,"
            "logs-endpoint.events.process-default"
        )

        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "anchor index",
        ):
            authorize_investigation_query_request(proposal(), candidate_context)

    def test_real_oql_and_compiled_dsl_are_built_locally(self) -> None:
        query = authorize_investigation_query_request(
            proposal(), context()
        )["queries"][0]
        rendered = oql_equivalent(query)
        dsl = build_query_dsl(query)

        self.assertIn('dns.question.name:"example.test"', rendered)
        self.assertIn("| sortby @timestamp^", rendered)
        self.assertNotIn("==", rendered)
        self.assertEqual(
            dsl["sort"][0]["@timestamp"]["order"],
            "asc",
        )
        self.assertEqual(
            dsl["_source"],
            PACKS["dns_activity"]["fields"],
        )

    def test_role_aware_event_tuple_is_provenance_bound_and_anded(self) -> None:
        request = authorize_investigation_query_request(
            role_aware_proposal(),
            role_aware_context(),
        )
        query = request["queries"][0]
        expected_tuple = role_aware_context()["permitted_event_tuples"][0][
            "event_tuple"
        ]
        self.assertEqual(query["event_tuple"], expected_tuple)
        self.assertEqual(
            query["event_tuple_provenance"],
            request["authorization"]["event_tuples"][0],
        )

        dsl = build_query_dsl(query)
        tuple_filter = dsl["query"]["bool"]["filter"][3]["bool"]["filter"]
        self.assertEqual(
            tuple_filter,
            [
                (
                    {"term": {EVENT_TUPLE_PATHS[field][0]: value}}
                    if len(EVENT_TUPLE_PATHS[field]) == 1
                    else {
                        "bool": {
                            "should": [
                                {"term": {path: value}}
                                for path in EVENT_TUPLE_PATHS[field]
                            ],
                            "minimum_should_match": 1,
                        }
                    }
                )
                for field, value in expected_tuple.items()
            ],
        )
        kql = kql_equivalent(query)
        oql = oql_equivalent(query)
        for text in (
            'source.ip : "192.0.2.10"',
            'destination.ip : "198.51.100.20"',
            "source.port : 49152",
            "destination.port : 443",
            'network.transport : "tcp"',
            'network.protocol : "tls"',
            'network.community_id : "1:trusted-flow="',
            'rule.id : "2016150"',
            'rule.uuid : "2016150"',
        ):
            self.assertIn(text, kql)
            self.assertIn(text.replace(" : ", ":"), oql)

    def test_event_tuple_cannot_swap_roles_or_cross_product_trusted_rows(self) -> None:
        candidate = role_aware_proposal()
        candidate["queries"][0]["event_tuple"].update({
            "source_ip": "198.51.100.20",
            "destination_ip": "192.0.2.10",
        })
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "trusted role-aware event tuple",
        ):
            authorize_investigation_query_request(candidate, role_aware_context())

        candidate_context = role_aware_context()
        candidate_context["permitted_event_tuples"].append({
            "event_tuple": {
                "source_ip": "203.0.113.30",
                "destination_ip": "192.0.2.10",
                "destination_port": 53,
                "transport": "udp",
                "protocol": "dns",
            },
            "role_semantics": "packet_direction",
            "source": "trusted_context",
            "evidence_ref": "context:event-tuple:second-flow",
        })
        candidate_context["permitted_observables"]["ips"].append("203.0.113.30")
        candidate = role_aware_proposal()
        candidate["queries"][0]["observables"]["ips"].append("203.0.113.30")
        candidate["queries"][0]["event_tuple"] = {
            "source_ip": "203.0.113.30",
            "destination_ip": "198.51.100.20",
        }
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "trusted role-aware event tuple",
        ):
            authorize_investigation_query_request(candidate, candidate_context)

    def test_event_tuple_rejects_unauthorized_or_unprojected_constraints(self) -> None:
        candidate = role_aware_proposal()
        candidate["queries"][0]["event_tuple"]["destination_port"] = 8443
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "trusted role-aware event tuple",
        ):
            authorize_investigation_query_request(candidate, role_aware_context())

        candidate = role_aware_proposal()
        candidate["queries"][0]["event_tuple"]["community_id"] = (
            '1:trusted-flow=" OR *'
        )
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "community_id is invalid",
        ):
            authorize_investigation_query_request(candidate, role_aware_context())

        candidate = role_aware_proposal()
        candidate["queries"][0]["event_tuple"] = {
            "destination_port": 443,
            "transport": "tcp",
        }
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "source or destination IP role",
        ):
            authorize_investigation_query_request(candidate, role_aware_context())

        candidate = role_aware_proposal()
        candidate["queries"][0]["pack"] = "system_auth"
        candidate["queries"][0]["event_tuple"] = {"rule_id": "2016150"}
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "unavailable in pack",
        ):
            authorize_investigation_query_request(candidate, role_aware_context())

    def test_system_auth_and_zeek_protocol_packs_compile_exact_fields(self) -> None:
        auth_proposal = proposal()
        auth_proposal["queries"][0].update(
            {
                "dialect": "elastic",
                "pack": "system_auth",
                "observables": {
                    "ips": ["192.0.2.10"],
                    "domains": [],
                    "hosts": [],
                    "users": [],
                },
                "aggregation": "events",
            }
        )
        auth_query = authorize_investigation_query_request(
            auth_proposal,
            context(),
        )["queries"][0]
        auth_dsl = build_query_dsl(auth_query)
        self.assertEqual(
            auth_dsl["_source"],
            PACKS["system_auth"]["fields"],
        )
        self.assertNotIn("message", auth_dsl["_source"])
        self.assertIn(
            {"term": {"event.dataset": "system.auth"}},
            auth_dsl["query"]["bool"]["filter"][1]["bool"]["should"],
        )

        tls_context = context()
        tls_proposal = proposal()
        tls_proposal["queries"][0].update(
            {
                "pack": "zeek_tls",
                "observables": {
                    "ips": [],
                    "domains": ["example.test"],
                    "hosts": [],
                    "users": [],
                },
                "aggregation": "events",
            }
        )
        tls_query = authorize_investigation_query_request(
            tls_proposal,
            tls_context,
        )["queries"][0]
        tls_dsl = build_query_dsl(tls_query)
        observable_terms = tls_dsl["query"]["bool"]["filter"][2]["bool"][
            "should"
        ]
        self.assertIn(
            {"term": {"ssl.server_name": "example.test"}},
            observable_terms,
        )
        self.assertNotIn(
            {"term": {"dns.query.name": "example.test"}},
            observable_terms,
        )

    def test_pack_rejects_observable_kinds_it_cannot_query(self) -> None:
        candidate_context = context()
        candidate_context["permitted_observables"] = {
            "ips": [],
            "domains": [],
            "hosts": ["host-only"],
            "users": [],
        }
        candidate_context["discovered_observables"] = []
        candidate = proposal()
        candidate["queries"][0].update({
            "pack": "zeek_tls",
            "observables": {
                "ips": [],
                "domains": [],
                "hosts": ["host-only"],
                "users": [],
            },
        })

        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "unsupported by pack zeek_tls: hosts",
        ):
            authorize_investigation_query_request(
                candidate,
                candidate_context,
            )

    def test_empty_boolean_and_coverage_ambiguity_fail_closed(self) -> None:
        query = authorize_investigation_query_request(
            proposal(),
            context(),
        )["queries"][0]
        empty_query = copy.deepcopy(query)
        empty_query["observables"] = {
            "ips": [],
            "domains": [],
            "hosts": [],
            "users": [],
        }
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "no observable query clauses",
        ):
            build_query_dsl(empty_query)

        self.assertEqual(
            result_coverage(
                query,
                status="ok",
                total_hits=50,
                total_hits_relation="eq",
                returned_hits=25,
            )["coverage_status"],
            "bounded_sample",
        )
        incomplete = result_coverage(
            query,
            status="timeout",
            total_hits=0,
            total_hits_relation="eq",
            returned_hits=0,
        )
        self.assertEqual(incomplete["coverage_status"], "partial")
        self.assertFalse(incomplete["zero_hits"])

    def test_cross_sensor_packet_tuple_compiles_only_community_id_join(self) -> None:
        candidate = role_aware_proposal()
        candidate["queries"][0]["pack"] = "network_flow"
        request = authorize_investigation_query_request(
            candidate,
            role_aware_context(),
        )
        query = request["queries"][0]

        self.assertEqual(
            query["match_semantics"],
            "community_id_cross_sensor",
        )
        tuple_filter = build_query_dsl(query)["query"]["bool"]["filter"][3]
        self.assertEqual(
            tuple_filter,
            {
                "bool": {
                    "filter": [{
                        "term": {
                            "network.community_id": "1:trusted-flow=",
                        }
                    }]
                }
            },
        )

        missing_join = role_aware_proposal()
        missing_join["queries"][0]["pack"] = "network_flow"
        missing_join["queries"][0]["event_tuple"].pop("community_id")
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "requires community_id",
        ):
            authorize_investigation_query_request(
                missing_join,
                role_aware_context(),
            )

    def test_anchor_nearest_uses_trusted_anchor_and_is_elastic_only(self) -> None:
        candidate = proposal()
        candidate["queries"][0].update({
            "dialect": "elastic",
            "aggregation": "anchor_nearest",
        })
        query = authorize_investigation_query_request(
            candidate,
            context(),
        )["queries"][0]
        dsl = build_query_dsl(query)

        self.assertEqual(query["anchor_time"], context()["anchor_time"])
        self.assertEqual(query["match_semantics"], "observable_exact_any_field")
        self.assertEqual(
            dsl["query"]["function_score"]["gauss"]["@timestamp"]["origin"],
            context()["anchor_time"],
        )
        self.assertEqual(dsl["sort"][0], {"_score": "desc"})

        candidate["queries"][0]["dialect"] = "oql"
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "only through compiled Elastic DSL",
        ):
            authorize_investigation_query_request(candidate, context())

    def test_response_dsl_scope_and_projection_tampering_fail_closed(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())
        response = valid_response(request)
        self.assertIs(validate_investigation_query_response(response, request), response)

        changed_dsl = copy.deepcopy(response)
        changed_dsl["results"][0]["query_dsl"]["query"] = {"match_all": {}}
        with self.assertRaisesRegex(InvestigationQueryContractError, "DSL"):
            validate_investigation_query_response(changed_dsl, request)

        extra_source = copy.deepcopy(response)
        extra_source["results"][0]["hits"][0]["source"]["secret"] = "not projected"
        with self.assertRaisesRegex(InvestigationQueryContractError, "projection"):
            validate_investigation_query_response(extra_source, request)

    def test_response_event_tuple_hit_mismatch_fails_closed(self) -> None:
        request = authorize_investigation_query_request(
            role_aware_proposal(),
            role_aware_context(),
        )
        response = valid_response(request)
        response["results"][0]["hits"][0] = {
            "id": "hit-1",
            "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
            "source": {
                "@timestamp": "2026-07-24T11:30:00.000Z",
                "event": {"dataset": "suricata.alert"},
                "source": {"ip": "192.0.2.10", "port": 49152},
                "destination": {"ip": "198.51.100.20", "port": 443},
                "network": {
                    "transport": "tcp",
                    "protocol": "tls",
                    "community_id": "1:trusted-flow=",
                },
                "rule": {"id": "2016150"},
            },
        }
        self.assertIs(
            validate_investigation_query_response(response, request),
            response,
        )
        response["results"][0]["hits"][0]["source"]["destination"]["port"] = 8443
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "event tuple",
        ):
            validate_investigation_query_response(response, request)

    def test_response_rejects_forged_time_dataset_and_observable(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())
        response = valid_response(request)

        forged_time = copy.deepcopy(response)
        forged_time["results"][0]["hits"][0]["source"]["@timestamp"] = (
            "2026-07-24T12:30:00.000Z"
        )
        with self.assertRaisesRegex(InvestigationQueryContractError, "window"):
            validate_investigation_query_response(forged_time, request)

        forged_dataset = copy.deepcopy(response)
        forged_dataset["results"][0]["hits"][0]["source"]["event"]["dataset"] = (
            "zeek.http"
        )
        with self.assertRaisesRegex(InvestigationQueryContractError, "dataset"):
            validate_investigation_query_response(forged_dataset, request)

        substituted = copy.deepcopy(response)
        substituted["results"][0]["hits"][0]["source"]["dns"]["question"]["name"] = (
            "unrelated.test"
        )
        with self.assertRaisesRegex(InvestigationQueryContractError, "observable"):
            validate_investigation_query_response(substituted, request)

        incomplete_shards = copy.deepcopy(response)
        incomplete_shards["results"][0]["shards"].update({
            "total": 10,
            "successful": 1,
            "failed": 0,
        })
        with self.assertRaisesRegex(InvestigationQueryContractError, "shard coverage"):
            validate_investigation_query_response(incomplete_shards, request)

    def test_false_control_is_authenticated_and_does_not_skip_other_control(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())
        response = valid_response(request)
        positive = response["controls"]["positive_anchor"]
        positive.update({
            "passed": False,
            "total_hits": 0,
            "returned_hits": 0,
            "hits": [],
        })
        response.update({"complete": False, "partial": True})
        response["semantic_validity"].update({
            "controls_valid": False,
            "semantic_valid": False,
        })

        self.assertIs(validate_investigation_query_response(response, request), response)

        # The negative control must still be authenticated even though the
        # independently valid positive control returned passed=false.
        response["controls"]["negative_filter"]["query_dsl"] = {"match_all": {}}
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "negative_filter.*DSL",
        ):
            validate_investigation_query_response(response, request)

    def test_control_rejects_forged_digest_and_nonexact_positive_scope(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())
        response = valid_response(request)
        response["controls"]["positive_anchor"]["index_scope"] = ALERT_INDEX_SCOPE
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "positive_anchor.*index scope",
        ):
            validate_investigation_query_response(response, request)

        response = valid_response(request)
        response["controls"]["negative_filter"]["passed"] = False
        response["controls"]["negative_filter"]["query_digest"] = "0" * 64
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "negative_filter.*digest",
        ):
            validate_investigation_query_response(response, request)


class SecurityOnionInvestigationPivotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.wrapper = load_source_module("investigation_pivot_wrapper_test", WRAPPER_PATH)

    def test_wrapper_pack_and_observable_contract_matches_client(self) -> None:
        self.assertEqual(self.wrapper.PACKS, PACKS)
        self.assertEqual(self.wrapper.OBSERVABLE_FIELDS, OBSERVABLE_FIELDS)
        self.assertEqual(self.wrapper.EVENT_TUPLE_FIELDS, EVENT_TUPLE_FIELDS)
        self.assertEqual(self.wrapper.EVENT_TUPLE_PATHS, EVENT_TUPLE_PATHS)
        self.assertEqual(
            PACKS["system_auth"]["indices"],
            ["logs-system.auth-*"],
        )
        self.assertEqual(
            PACKS["zeek_tls"]["datasets"],
            ["zeek.ssl"],
        )
        self.assertIn("dns.query.name", PACKS["dns_activity"]["fields"])
        self.assertIn("ssl.server_name", OBSERVABLE_FIELDS["domains"])

    def test_wrapper_independently_validates_exact_authorized_request(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())
        self.assertEqual(self.wrapper.validated_pivot_request(request), request)

        candidate = copy.deepcopy(request)
        candidate["queries"][0]["index"] = "*"
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                self.wrapper.validated_pivot_request(candidate)

    def test_wrapper_event_tuple_parity_and_tampering_fail_closed(self) -> None:
        request = authorize_investigation_query_request(
            role_aware_proposal(),
            role_aware_context(),
        )
        self.assertEqual(self.wrapper.validated_pivot_request(request), request)
        query = request["queries"][0]
        self.assertEqual(
            self.wrapper.pivot_query_dsl(query),
            build_query_dsl(query),
        )
        self.assertEqual(
            self.wrapper.pivot_kql_equivalent(query),
            kql_equivalent(query),
        )
        self.assertEqual(
            self.wrapper.pivot_oql_equivalent(query),
            oql_equivalent(query),
        )

        tampered = copy.deepcopy(request)
        tampered["queries"][0]["event_tuple"]["destination_port"] = 8443
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                self.wrapper.validated_pivot_request(tampered)

    def test_wrapper_executes_compiled_oql_equivalent_not_caller_query(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())
        query = request["queries"][0]
        payload = {
            "took": 3,
            "timed_out": False,
            "_shards": {
                "total": 2,
                "successful": 2,
                "skipped": 0,
                "failed": 0,
            },
            "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
        }
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(payload).encode(),
            stderr=b"",
        )
        with mock.patch.object(
            self.wrapper,
            "run_bounded_command",
            return_value=completed,
        ) as run:
            result = self.wrapper.execute_pivot_query(query)

        submitted = json.loads(run.call_args.args[0][3])
        self.assertEqual(submitted, build_query_dsl(query))
        self.assertEqual(result["execution_semantics"], "compiled_oql_equivalent")
        self.assertIn("event.dataset:", result["oql_equivalent"])
        self.assertNotIn("==", result["oql_equivalent"])
        self.assertEqual(
            result["result_coverage"]["coverage_status"],
            "exact_zero",
        )
        self.assertTrue(result["result_coverage"]["zero_hits"])

    def test_wrapper_count_is_exact_aggregate_not_truncated_sample(self) -> None:
        candidate = proposal()
        candidate["queries"][0]["aggregation"] = "count"
        query = authorize_investigation_query_request(
            candidate,
            context(),
        )["queries"][0]
        response = {
            "status": "ok",
            "semantic_valid": True,
            "total_hits": 37,
            "total_hits_relation": "eq",
            "returned_hits": 0,
            "truncated": True,
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
            "hits": [],
        }
        with mock.patch.object(
            self.wrapper,
            "execute_search",
            return_value=response,
        ):
            result = self.wrapper.execute_pivot_query(query)

        self.assertFalse(result["truncated"])
        self.assertEqual(
            result["result_coverage"]["coverage_status"],
            "exact_aggregate",
        )
        self.assertFalse(
            result["result_coverage"]["event_bodies_complete"],
        )

    def test_wrapper_controls_bind_positive_to_exact_index(self) -> None:
        anchor = context()["anchor"]

        def fake_search(body: dict, scope: list[str]) -> dict:
            if scope == [anchor["index"]]:
                return {
                    "status": "ok",
                    "total_hits_relation": "eq",
                    "total_hits": 1,
                    "returned_hits": 1,
                    "hits": [{
                        "id": anchor["id"],
                        "index": anchor["index"],
                        "source": {},
                    }],
                }
            return {
                "status": "ok",
                "total_hits_relation": "eq",
                "total_hits": 0,
                "returned_hits": 0,
                "hits": [],
            }

        with mock.patch.object(
            self.wrapper,
            "execute_search",
            side_effect=fake_search,
        ) as execute:
            controls = self.wrapper.execute_controls(anchor)

        self.assertTrue(controls["positive_anchor"]["passed"])
        self.assertTrue(controls["negative_filter"]["passed"])
        self.assertEqual(execute.call_args_list[0].args[1], [anchor["index"]])
        self.assertEqual(execute.call_args_list[1].args[1], ALERT_INDEX_SCOPE)

    def test_bounded_wrapper_helper_stops_oversized_stdout(self) -> None:
        with self.assertRaises(self.wrapper.BoundedCommandError) as caught:
            self.wrapper.run_bounded_command(
                [
                    sys.executable,
                    "-c",
                    "import os; os.write(1, b'x' * 65536)",
                ],
                timeout_seconds=5,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )

        self.assertEqual(caught.exception.reason, "output_limit")

    def test_wrapper_accepts_real_nested_projection_and_rejects_substitution(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())
        query = request["queries"][0]
        source = {
            "@timestamp": "2026-07-24T11:30:00.000Z",
            "event": {"dataset": "zeek.dns"},
            "source": {"ip": "192.0.2.10"},
            "dns": {"question": {"name": "example.test"}},
        }
        self.assertTrue(self.wrapper.valid_pivot_hit_source(source, query))

        replaced = copy.deepcopy(source)
        replaced["source"]["ip"] = "192.0.2.99"
        replaced["dns"]["question"]["name"] = "unrelated.test"
        self.assertFalse(self.wrapper.valid_pivot_hit_source(replaced, query))

        unprojected = copy.deepcopy(source)
        unprojected["event"]["original"] = "sensitive raw event"
        self.assertFalse(self.wrapper.valid_pivot_hit_source(unprojected, query))

    def test_wrapper_authenticates_every_role_aware_tuple_field_in_hits(self) -> None:
        request = authorize_investigation_query_request(
            role_aware_proposal(),
            role_aware_context(),
        )
        query = request["queries"][0]
        source = {
            "@timestamp": "2026-07-24T11:30:00.000Z",
            "event": {"dataset": "suricata.alert"},
            "source": {"ip": "192.0.2.10", "port": 49152},
            "destination": {"ip": "198.51.100.20", "port": 443},
            "network": {
                "transport": "tcp",
                "protocol": "tls",
                "community_id": "1:trusted-flow=",
            },
            "rule": {"id": "2016150"},
        }
        self.assertTrue(self.wrapper.valid_pivot_hit_source(source, query))

        for path, replacement in (
            (("source", "ip"), "198.51.100.20"),
            (("destination", "port"), 8443),
            (("network", "transport"), "udp"),
            (("network", "protocol"), "dns"),
            (("network", "community_id"), "1:other-flow="),
            (("rule", "id"), "9999999"),
        ):
            candidate = copy.deepcopy(source)
            candidate[path[0]][path[1]] = replacement
            with self.subTest(path=path):
                self.assertFalse(
                    self.wrapper.valid_pivot_hit_source(candidate, query)
                )

    def test_wrapper_accepts_rule_uuid_and_reversed_zeek_flow_via_community_id(self) -> None:
        alert_query = authorize_investigation_query_request(
            role_aware_proposal(),
            role_aware_context(),
        )["queries"][0]
        alert_source = {
            "@timestamp": "2026-07-24T11:30:00.000Z",
            "event": {"dataset": "suricata.alert"},
            "source": {"ip": "192.0.2.10", "port": 49152},
            "destination": {"ip": "198.51.100.20", "port": 443},
            "network": {
                "transport": "tcp",
                "protocol": "tls",
                "community_id": "1:trusted-flow=",
            },
            "rule": {"uuid": "2016150"},
        }
        self.assertTrue(
            self.wrapper.valid_pivot_hit_source(
                alert_source,
                alert_query,
            )
        )

        candidate = role_aware_proposal()
        candidate["queries"][0]["pack"] = "network_flow"
        flow_query = authorize_investigation_query_request(
            candidate,
            role_aware_context(),
        )["queries"][0]
        reversed_zeek = {
            "@timestamp": "2026-07-24T11:30:00.000Z",
            "event": {"dataset": "zeek.conn"},
            "source": {"ip": "198.51.100.20", "port": 443},
            "destination": {"ip": "192.0.2.10", "port": 49152},
            "network": {
                "transport": "tcp",
                "protocol": "tls",
                "community_id": "1:trusted-flow=",
            },
        }
        self.assertTrue(
            self.wrapper.valid_pivot_hit_source(
                reversed_zeek,
                flow_query,
            )
        )


class InvestigationPivotCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.collector = load_source_module("investigation_pivot_collector_test", COLLECTOR_PATH)

    def test_collector_returns_model_evidence_and_full_query_audit(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())
        response = valid_response(request)
        with mock.patch.object(
            self.collector,
            "_transport",
            return_value=response,
        ):
            artifact = self.collector.collect_investigation_pivots(
                proposal(),
                context(),
                config_path={},
                persist=False,
            )

        self.assertTrue(artifact["complete"])
        self.assertEqual(artifact["model_evidence"]["results"][0]["query_id"], "query-1")
        audit = artifact["query_audit"][0]
        self.assertEqual(audit["query_dsl"], build_query_dsl(request["queries"][0]))
        self.assertEqual(audit["index_scope"], PACKS["dns_activity"]["indices"])
        self.assertEqual(
            artifact["audit"]["security_onion_response_digest"],
            canonical_digest(response),
        )

    def test_model_evidence_withholds_hits_when_controls_fail(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())
        response = valid_response(request)
        response["complete"] = False
        response["partial"] = True
        response["controls"]["positive_anchor"]["passed"] = False
        response["semantic_validity"]["controls_valid"] = False
        response["semantic_validity"]["semantic_valid"] = False

        evidence = self.collector._model_evidence(response)

        self.assertFalse(evidence["controls_valid"])
        self.assertEqual(evidence["results"][0]["hits"], [])
        self.assertTrue(
            any(
                gap["query_id"] == "broker-controls"
                for gap in evidence["evidence_gaps"]
            )
        )


if __name__ == "__main__":
    unittest.main()
