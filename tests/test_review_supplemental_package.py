"""Direct contracts for bounded reviewer supplemental reconciliation."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.review import supplemental  # noqa: E402


class Harness:
    def __init__(self, *, models=1, rounds=1, queries=2):
        self.models = models
        self.rounds = rounds
        self.queries = queries

    def remaining_model_calls(self): return self.models
    def remaining_query_rounds(self): return self.rounds
    def remaining_queries(self): return self.queries
    def query_rounds_used(self): return 3


def dependencies(observed: dict) -> supplemental.Dependencies:
    def pop_requests(value):
        requests = value.pop("investigation_query_requests", [])
        return requests if isinstance(requests, list) else []

    def query_loop(package, _response, _args, _settings, _role, **kwargs):
        observed.update(kwargs)
        review_input = kwargs["model_input_builder"](package, 1)
        final = kwargs["model_executor"]("codex", review_input, None, {})
        final["investigation_query_requests"] = [{"query": "recursive"}]
        final["_investigation_query_audit"] = {"terminal_requests_ignored": 2}
        return final

    return supplemental.Dependencies(
        pop_query_requests=pop_requests,
        canonical_digest=lambda value: f"digest-{len(repr(value))}",
        independent_package=lambda package, **kwargs: {
            **package, "hosted": kwargs.get("hosted", False),
        },
        route_is_hosted=lambda _route, _settings: True,
        analyze_route=lambda *_args, **_kwargs: {
            "review": "fresh", "hosted": bool(_args[1].get("hosted")),
        },
        validate_reviewer=lambda value, _package: dict(value),
        validate_response=lambda value, _package: dict(value),
        apply_query_loop=query_loop,
        max_queries_per_round=4,
    )


def execute(response: dict, harness, observed: dict | None = None):
    return supplemental.execute(
        {}, response, None, {}, "incident-responder", "codex", Path("review.md"),
        live_osquery_config=None, enrichment_config=None,
        security_onion_config_path=Path("security.json"),
        investigation_pivot_dir=Path("pivots"), harness_runtime=harness,
        deps=dependencies(observed if observed is not None else {}),
    )


class ReviewSupplementalPackageTests(unittest.TestCase):
    def test_executes_one_bounded_blind_reconciliation(self) -> None:
        observed: dict = {}
        final, audit = execute({
            "investigation_query_requests": [{"query": "pivot"}],
            "evidence_gaps": ["Need endpoint process attribution"],
        }, Harness(queries=2), observed)
        self.assertTrue(audit["executed"])
        self.assertEqual(audit["reason"], "Need endpoint process attribution")
        self.assertEqual(audit["recursive_requests_ignored"], 3)
        self.assertEqual(observed["max_rounds_override"], 1)
        self.assertEqual(observed["max_queries_total_override"], 2)
        self.assertTrue(observed["model_call_independent_review"])
        self.assertFalse(final["second_opinion_recommended"])
        self.assertTrue(final["hosted"])

    def test_requires_material_discriminator(self) -> None:
        original = {"investigation_query_requests": [{"query": "pivot"}]}
        final, audit = execute(original, Harness())
        self.assertIs(final, original)
        self.assertFalse(audit["executed"])
        self.assertIn("lacked a material", audit["reason"])

    def test_fails_closed_when_model_budget_is_exhausted(self) -> None:
        _, audit = execute({
            "investigation_query_requests": [{}], "evidence_gaps": ["gap"],
        }, Harness(models=0))
        self.assertEqual(audit["reason"], "no model-call budget remains for reconciliation")

    def test_hypothesis_discriminator_is_bounded(self) -> None:
        reason = supplemental.pivot_reason({
            "investigation_query_requests": [{}],
            "hypotheses": [{"next_discriminator": "x" * 600}],
        })
        self.assertEqual(len(reason), 500)


if __name__ == "__main__":
    unittest.main()
