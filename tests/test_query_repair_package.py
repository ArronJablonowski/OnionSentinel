from __future__ import annotations

import copy
import unittest

from n8n.onion_sentinel.analysis.query import repair


class QueryRepairPackageTests(unittest.TestCase):
    class ContractError(ValueError):
        pass

    def setUp(self) -> None:
        self.original = {
            "query_id": "repair-1",
            "backend": "elastic",
            "purpose": "Correlate the trusted flow",
            "pack": "zeek_conn",
            "window": {
                "start": "2026-07-24T18:00:00.000Z",
                "end": "2026-07-24T19:00:00.000Z",
            },
            "observables": {
                "ips": ["192.0.2.10", "198.51.100.20"],
                "domains": [],
                "hosts": [],
                "users": [],
            },
            "size": 100,
            "aggregation": "timeline",
            "event_tuple": {
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
            },
            "observable_scope_source": "trusted_event_tuple_intersection",
        }

    def dependencies(self, normalize_request=None) -> repair.Dependencies:
        def default_normalizer(raw, **_kwargs):
            return copy.deepcopy(raw)

        return repair.Dependencies(
            normalize_request=normalize_request or default_normalizer,
            normalize_event_tuple=lambda value: copy.deepcopy(value),
            pack_event_tuple_fields=lambda _pack: {"source_ip", "destination_ip"},
            prompt_error_category=lambda _reason: "invalid_response",
            prompt_error_digest=lambda _reason: "error-digest",
            canonical_digest=lambda _value: "scope-digest",
        )

    def test_recover_observables_intersects_only_unambiguous_trusted_values(self) -> None:
        authorization = {
            "permitted_observables": {
                "ips": ["192.0.2.10"],
                "domains": ["Example.COM"],
                "hosts": [],
                "users": [],
            }
        }
        recovered = repair.recover_observables(
            ["192.0.2.10", {"value": "example.com"}, "203.0.113.99"],
            authorization,
        )
        self.assertEqual(recovered["ips"], ["192.0.2.10"])
        self.assertEqual(recovered["domains"], ["Example.COM"])
        self.assertNotIn("203.0.113.99", str(recovered))

        authorization["permitted_observables"]["hosts"] = ["example.com"]
        self.assertIsNone(
            repair.recover_observables(["example.com"], authorization)
        )

    def test_scope_drops_executable_syntax_and_uses_trusted_tuple_intersection(self) -> None:
        observed_raw = {}

        def normalize_request(raw, **_kwargs):
            observed_raw.update(copy.deepcopy(raw))
            normalized = copy.deepcopy(raw)
            normalized["parameters"].setdefault("size", 100)
            normalized["parameters"].setdefault("aggregation", "timeline")
            return normalized

        raw = repair.request_from_scope(self.original)
        raw["parameters"]["observables"] = []
        raw["parameters"]["query_dsl"] = {"match_all": {}}
        authorization = {
            "permitted_observables": copy.deepcopy(self.original["observables"])
        }
        recovered = repair.scope(
            raw,
            round_number=1,
            position=1,
            authorization_context=authorization,
            dependencies=self.dependencies(normalize_request),
            error_type=self.ContractError,
        )
        self.assertIsNotNone(recovered)
        self.assertNotIn("query_dsl", observed_raw["parameters"])
        self.assertEqual(
            recovered["observable_scope_source"],
            "trusted_event_tuple_intersection",
        )
        self.assertEqual(recovered["observables"], self.original["observables"])

    def test_scope_rejects_partly_untrusted_event_tuple(self) -> None:
        raw = repair.request_from_scope(self.original)
        raw["parameters"]["observables"] = []
        raw["parameters"]["event_tuple"]["destination_ip"] = "203.0.113.99"
        authorization = {
            "permitted_observables": copy.deepcopy(self.original["observables"])
        }
        self.assertIsNone(
            repair.scope(
                raw,
                round_number=1,
                position=1,
                authorization_context=authorization,
                dependencies=self.dependencies(),
                error_type=self.ContractError,
            )
        )

    def test_validate_allows_narrowing_but_rejects_authority_widening(self) -> None:
        narrowed = repair.request_from_scope(self.original)
        narrowed["parameters"]["window"]["start"] = "2026-07-24T18:05:00.000Z"
        narrowed["parameters"]["observables"]["ips"] = ["192.0.2.10"]
        narrowed["parameters"]["size"] = 50
        repair.validate(narrowed, self.original, error_type=self.ContractError)

        mutations = {
            "backend": lambda item: item.update(backend="oql"),
            "window": lambda item: item["parameters"]["window"].update(
                start="2026-07-24T17:59:00.000Z"
            ),
            "observable": lambda item: item["parameters"]["observables"]["ips"].append(
                "203.0.113.99"
            ),
            "size": lambda item: item["parameters"].update(size=101),
            "tuple": lambda item: item["parameters"]["event_tuple"].update(
                destination_ip="203.0.113.99"
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                candidate = repair.request_from_scope(self.original)
                mutate(candidate)
                with self.assertRaises(self.ContractError):
                    repair.validate(
                        candidate, self.original, error_type=self.ContractError
                    )

    def test_request_from_scope_is_deep_copied(self) -> None:
        request = repair.request_from_scope(self.original)
        request["parameters"]["observables"]["ips"].append("203.0.113.99")
        self.assertNotIn("203.0.113.99", self.original["observables"]["ips"])

    def test_failures_collects_only_repairable_broker_contract_statuses(self) -> None:
        found = repair.failures(
            {
                "results": [
                    {"query_id": "ok", "status": "success"},
                    {"query_id": "outer", "status": "invalid", "error": "bad"},
                    {
                        "trusted_query_audit": [
                            {"query_id": "audit", "status": "contract_error"}
                        ],
                        "evidence": {
                            "results": [
                                {"query_id": "evidence", "status": "invalid_response"}
                            ]
                        },
                    },
                ]
            }
        )
        self.assertEqual(set(found), {"outer", "audit", "evidence"})
        self.assertEqual(found["outer"], "bad")
        self.assertNotIn("ok", found)

    def test_prompt_entry_exposes_field_names_and_digests_not_raw_error(self) -> None:
        entry = repair.prompt_entry(
            self.original,
            reason="secret backend exception",
            trigger="broker_contract_failure",
            dependencies=self.dependencies(),
        )
        self.assertEqual(entry["error"], "invalid_response")
        self.assertEqual(entry["error_sha256"], "error-digest")
        self.assertEqual(entry["scope_digest"], "scope-digest")
        self.assertEqual(
            entry["original_event_tuple_fields"],
            ["destination_ip", "source_ip"],
        )
        self.assertNotIn("secret backend exception", str(entry))


if __name__ == "__main__":
    unittest.main()
