"""Direct contracts for live endpoint OSQuery request normalization."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.query import endpoint  # noqa: E402


class QueryContractError(ValueError):
    pass


class OsqueryContractError(ValueError):
    pass


def dependencies(*, reject: bool = False) -> endpoint.Dependencies:
    def normalize_query(value: str) -> str:
        if reject:
            raise OsqueryContractError("only one read-only SELECT is allowed")
        return " ".join(value.split())

    return endpoint.Dependencies(
        normalize_query=normalize_query,
        query_error=OsqueryContractError,
    )


class EndpointQueryPackageTests(unittest.TestCase):
    def test_normalizes_bounded_target_and_provider_validated_query(self) -> None:
        result = endpoint.normalize(
            {
                "target_alias": " workstation-1 ",
                "query": "SELECT  *\nFROM processes;",
            },
            dependencies=dependencies(),
            error_type=QueryContractError,
        )
        self.assertEqual(result, {
            "target_alias": "workstation-1",
            "query": "SELECT * FROM processes;",
        })

    def test_requires_both_target_and_query(self) -> None:
        for value in ({}, {"target_alias": "host"}, {"query": "SELECT 1;"}):
            with self.subTest(value=value), self.assertRaisesRegex(
                QueryContractError, "target_alias.*read-only SELECT"
            ):
                endpoint.normalize(
                    value, dependencies=dependencies(),
                    error_type=QueryContractError,
                )

    def test_translates_provider_rejection_to_query_contract(self) -> None:
        with self.assertRaisesRegex(QueryContractError, "read-only SELECT"):
            endpoint.normalize(
                {"target_alias": "host", "query": "DELETE FROM processes;"},
                dependencies=dependencies(reject=True),
                error_type=QueryContractError,
            )


if __name__ == "__main__":
    unittest.main()
