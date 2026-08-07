"""Direct contracts for provider-neutral Security Onion query proposals."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.query import security_onion  # noqa: E402


class QueryContractError(ValueError):
    pass


POLICY = security_onion.Policy(
    purposes=frozenset({"establish_timeline", "validate_detection"}),
    packs=frozenset({"alert_context", "zeek_tls"}),
    aggregations=frozenset({"events", "count", "anchor_nearest"}),
)


def dependencies(*, adjusted: bool = False) -> security_onion.Dependencies:
    def normalize_window(value, envelope):
        result = dict(value)
        audit = {"adjusted": adjusted, "reasons": []}
        if adjusted:
            audit.update({
                "reasons": ["clipped_to_trusted_time_envelope"],
                "executed_window": dict(result),
            })
        return result, audit

    def project_tuple(value, pack, context):
        return {"source_ip": value["source_ip"]}, {
            "schema": "projection-v1",
            "pack": pack,
            "context_present": context is not None,
        }

    def positive(value, default, maximum, _label):
        result = default if value is None else int(value)
        if result < 1 or result > maximum:
            raise QueryContractError("query size is outside policy")
        return result

    return security_onion.Dependencies(
        normalize_window=normalize_window,
        project_event_tuple=project_tuple,
        positive_integer=positive,
    )


def parameters() -> dict:
    return {
        "pack": "alert_context",
        "window": {
            "start": "2026-07-24T00:00:00.000Z",
            "end": "2026-07-24T01:00:00.000Z",
        },
        "observables": {
            "ips": ["192.0.2.10"],
            "domains": [],
            "hosts": [],
            "users": [],
        },
        "size": 25,
        "aggregation": "events",
    }


class SecurityOnionQueryPackageTests(unittest.TestCase):
    def normalize(self, value: dict, **kwargs):
        return security_onion.normalize(
            value,
            purpose=kwargs.pop("purpose", "establish_timeline"),
            backend=kwargs.pop("backend", "elastic"),
            time_envelope=kwargs.pop("time_envelope", None),
            authorization_context=kwargs.pop("authorization_context", None),
            policy=POLICY,
            dependencies=kwargs.pop("dependencies", dependencies()),
            error_type=QueryContractError,
            **kwargs,
        )

    def test_normalizes_reviewed_schema_and_defaults_aggregation(self) -> None:
        value = parameters()
        value.pop("aggregation")
        normalized, audit = self.normalize(value)
        self.assertEqual(normalized["aggregation"], "events")
        self.assertEqual(normalized["size"], 25)
        self.assertEqual(normalized["observables"]["ips"], ["192.0.2.10"])
        self.assertEqual(audit, {})

    def test_rejects_unreviewed_purpose_pack_and_aggregation(self) -> None:
        cases = (
            ({}, {"purpose": "execute_arbitrary_query"}, "purpose"),
            ({"pack": "raw_indices"}, {}, "pack"),
            ({"aggregation": "script"}, {}, "aggregation"),
        )
        for overrides, keywords, message in cases:
            value = parameters()
            value.update(overrides)
            with self.subTest(message=message), self.assertRaisesRegex(
                QueryContractError, message
            ):
                self.normalize(value, **keywords)

    def test_anchor_nearest_requires_compiled_elastic(self) -> None:
        value = parameters()
        value["aggregation"] = "anchor_nearest"
        with self.assertRaisesRegex(QueryContractError, "compiled Elastic DSL"):
            self.normalize(value, backend="oql")

    def test_observables_are_exact_bounded_and_nonempty(self) -> None:
        invalid = (
            {"ips": [], "domains": [], "hosts": [], "users": []},
            {"ips": [str(index) for index in range(9)]},
            {"ips": ["192.0.2.10"], "commands": ["whoami"]},
            {"ips": "192.0.2.10"},
        )
        for observables in invalid:
            value = parameters()
            value["observables"] = observables
            with self.subTest(observables=observables), self.assertRaises(
                QueryContractError
            ):
                self.normalize(value)

        value = parameters()
        value["observables"] = {
            "ips": ["192.0.2.1", "192.0.2.2"],
            "domains": ["a.example", "b.example"],
            "hosts": ["one", "two"],
            "users": ["alpha", "beta", "gamma"],
        }
        with self.assertRaisesRegex(QueryContractError, "8 total"):
            self.normalize(value)

    def test_preserves_window_and_event_tuple_projection_audit(self) -> None:
        value = parameters()
        value["event_tuple"] = {"source_ip": "192.0.2.10", "rule_id": "1"}
        normalized, audit = self.normalize(
            value,
            authorization_context={"permitted_event_tuples": []},
            dependencies=dependencies(adjusted=True),
        )
        self.assertEqual(normalized["event_tuple"], {"source_ip": "192.0.2.10"})
        self.assertIn("window_adjustment", audit)
        self.assertEqual(audit["event_tuple_projection"]["pack"], "alert_context")
        self.assertTrue(audit["event_tuple_projection"]["context_present"])


if __name__ == "__main__":
    unittest.main()
