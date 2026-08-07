"""Direct contracts for common investigation query request envelopes."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.query import request  # noqa: E402


class QueryContractError(ValueError):
    pass


POLICY = request.Policy(
    backends=frozenset({"elastic", "osquery", "enrichment"}),
    parameter_keys={
        "elastic": frozenset({"pack", "window", "observables", "size"}),
        "osquery": frozenset({"target_alias", "query"}),
        "enrichment": frozenset({"indicator_type", "indicator"}),
    },
)


def dependencies(calls: list | None = None) -> request.Dependencies:
    def normalize_parameters(backend, parameters, purpose, envelope, context):
        if calls is not None:
            calls.append((backend, parameters, purpose, envelope, context))
        return {"accepted": sorted(parameters)}, {"backend_policy": backend}

    return request.Dependencies(normalize_parameters=normalize_parameters)


def proposal(**overrides):
    value = {
        "query_id": "timeline-1",
        "backend": "elastic",
        "purpose": "Establish the event timeline.",
        "parameters": {"pack": "alert_context", "size": 25},
    }
    value.update(overrides)
    return value


class QueryRequestPackageTests(unittest.TestCase):
    def normalize(self, value, **kwargs):
        return request.normalize(
            value,
            round_number=kwargs.pop("round_number", 2),
            position=kwargs.pop("position", 3),
            time_envelope=kwargs.pop("time_envelope", {"trusted": "window"}),
            authorization_context=kwargs.pop(
                "authorization_context", {"trusted": "context"}
            ),
            policy=POLICY,
            dependencies=kwargs.pop("dependencies", dependencies()),
            error_type=QueryContractError,
            **kwargs,
        )

    def test_routes_exact_projected_parameters_and_preserves_audit(self) -> None:
        calls: list = []
        value = proposal(parameters={
            "pack": "alert_context",
            "size": 25,
            "target_alias": "cross-backend-shape",
        })
        normalized = self.normalize(value, dependencies=dependencies(calls))
        self.assertEqual(normalized["query_id"], "timeline-1")
        self.assertEqual(normalized["parameters"], {"accepted": ["pack", "size"]})
        self.assertEqual(
            normalized["normalization"]["dropped_cross_backend_parameters"],
            ["target_alias"],
        )
        self.assertEqual(calls[0], (
            "elastic", {"pack": "alert_context", "size": 25},
            "Establish the event timeline.", {"trusted": "window"},
            {"trusted": "context"},
        ))

    def test_invalid_query_id_gets_deterministic_round_position_fallback(self) -> None:
        normalized = self.normalize(proposal(query_id="unsafe query id"))
        self.assertEqual(normalized["query_id"], "round-2-query-3")

    def test_rejects_unknown_top_level_or_executable_parameter_fields(self) -> None:
        with self.assertRaisesRegex(QueryContractError, "query fields"):
            self.normalize(proposal(command="whoami"))
        with self.assertRaisesRegex(QueryContractError, "elastic parameters"):
            self.normalize(proposal(parameters={"query_dsl": {"match_all": {}}}))

    def test_requires_object_backend_purpose_and_parameter_object(self) -> None:
        cases = (
            ([], "must be an object"),
            (proposal(backend="shell"), "backend"),
            (proposal(purpose=""), "purpose"),
            (proposal(parameters=[]), "parameters must be an object"),
        )
        for value, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                QueryContractError, message
            ):
                self.normalize(value)

    def test_parameter_projection_is_backend_specific_and_ordered(self) -> None:
        projected, dropped = request.project_parameters(
            "osquery",
            {"query": "SELECT 1;", "target_alias": "host", "pack": "ignored"},
            policy=POLICY,
            error_type=QueryContractError,
        )
        self.assertEqual(projected, {
            "query": "SELECT 1;", "target_alias": "host"
        })
        self.assertEqual(dropped, ["pack"])


if __name__ == "__main__":
    unittest.main()
