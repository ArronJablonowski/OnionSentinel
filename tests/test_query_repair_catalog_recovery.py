"""Characterize fail-closed trusted observable catalog recovery."""
from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from n8n.onion_sentinel.analysis.query import repair_catalog


class TrackingDict(dict):
    def __init__(self, *args: object, trace: list[object], label: str, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.trace = trace
        self.label = label

    def get(self, key: object, default: object = None) -> object:
        self.trace.append(("get", self.label, key, default))
        return super().get(key, default)


class QueryRepairCatalogRecoveryTests(unittest.TestCase):
    def test_authorization_admission_precedes_all_helpers(self) -> None:
        for authorization in (None, [], "authorization", 7):
            with self.subTest(authorization=authorization):
                with (
                    patch.object(repair_catalog, "_raw_values") as raw_values,
                    patch.object(repair_catalog, "_trusted_catalog") as catalog,
                ):
                    self.assertIsNone(
                        repair_catalog.recover("value", authorization)
                    )
                    raw_values.assert_not_called()
                    catalog.assert_not_called()

        trace: list[object] = []
        authorization = TrackingDict(
            {"permitted_observables": []}, trace=trace, label="authorization"
        )
        self.assertIsNone(repair_catalog.recover("value", authorization))
        self.assertEqual(
            trace, [("get", "authorization", "permitted_observables", None)]
        )

    def test_helper_order_identity_and_raw_value_bounds_are_exact(self) -> None:
        value = {"nested": ["192.0.2.1"]}
        permitted = {"ips": ["192.0.2.1"]}
        authorization = {"permitted_observables": permitted}
        calls: list[object] = []

        def raw_values(actual):
            calls.append(("raw", actual))
            return set()

        def trusted_catalog(actual):
            calls.append(("catalog", actual))
            return {}

        with (
            patch.object(repair_catalog, "_raw_values", raw_values),
            patch.object(repair_catalog, "_trusted_catalog", trusted_catalog),
        ):
            self.assertIsNone(repair_catalog.recover(value, authorization))
        self.assertEqual(calls, [("raw", value)])
        self.assertIs(calls[0][1], value)

        calls.clear()
        with (
            patch.object(
                repair_catalog, "_raw_values", return_value={str(i) for i in range(33)}
            ),
            patch.object(repair_catalog, "_trusted_catalog", trusted_catalog),
        ):
            self.assertIsNone(repair_catalog.recover(value, authorization))
        self.assertEqual(calls, [])

        calls.clear()
        with (
            patch.object(repair_catalog, "_raw_values", return_value={"value"}),
            patch.object(repair_catalog, "_trusted_catalog", trusted_catalog),
        ):
            self.assertIsNone(repair_catalog.recover(value, authorization))
        self.assertEqual(calls, [("catalog", permitted)])
        self.assertIs(calls[0][1], permitted)

    def test_exact_then_normalized_lookup_ambiguity_and_order_are_preserved(self) -> None:
        authorization = {
            "permitted_observables": {
                "ips": ["192.0.2.1", "192.0.2.2"],
                "domains": ["Example.COM", "ambiguous.test"],
                "hosts": ["ambiguous.test"],
                "users": ["Alice"],
            }
        }
        recovered = repair_catalog.recover(
            ["example.com.", "192.0.2.2", "192.0.2.1", "ambiguous.test", "Alice"],
            authorization,
        )

        self.assertEqual(recovered, {
            "ips": ["192.0.2.1", "192.0.2.2"],
            "domains": ["Example.COM"],
            "hosts": [],
            "users": ["Alice"],
        })

        trace: list[object] = []
        catalog = TrackingDict(
            {
                "Exact.": [("domains", "Exact.")],
                "exact": [("domains", "normalized")],
            },
            trace=trace,
            label="catalog",
        )
        with (
            patch.object(repair_catalog, "_raw_values", return_value={"Exact."}),
            patch.object(repair_catalog, "_trusted_catalog", return_value=catalog),
        ):
            recovered = repair_catalog.recover("ignored", {
                "permitted_observables": {}
            })
        self.assertEqual(recovered["domains"], ["Exact."])
        self.assertEqual(trace, [("get", "catalog", "Exact.", [])])

    def test_total_bound_exception_propagation_and_non_mutation_are_exact(self) -> None:
        permitted = {
            "ips": [f"192.0.2.{index}" for index in range(1, 10)],
            "domains": [], "hosts": [], "users": [],
        }
        authorization = {"permitted_observables": permitted}
        value = list(permitted["ips"])
        snapshot = copy.deepcopy((value, authorization))
        self.assertIsNone(repair_catalog.recover(value, authorization))
        self.assertEqual((value, authorization), snapshot)

        class ExplodingAuthorization(dict):
            def get(self, key: object, default: object = None) -> object:
                raise RuntimeError("authorization access failed")

        with self.assertRaisesRegex(RuntimeError, "authorization access failed"):
            repair_catalog.recover("value", ExplodingAuthorization())

        marker = LookupError("catalog construction failed")
        with (
            patch.object(repair_catalog, "_raw_values", return_value={"value"}),
            patch.object(repair_catalog, "_trusted_catalog", side_effect=marker),
        ):
            with self.assertRaisesRegex(LookupError, "catalog construction failed"):
                repair_catalog.recover(
                    "value", {"permitted_observables": {}}
                )


if __name__ == "__main__":
    unittest.main()
