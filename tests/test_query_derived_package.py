"""Direct contracts for governed PCAP/Zeek-derived evidence requests."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.query import derived  # noqa: E402


class QueryContractError(ValueError):
    pass


class FilterContractError(ValueError):
    pass


POLICY = derived.Policy(
    operations=frozenset({"zeek_connections", "pcap_summary"}),
    filters_by_operation={
        "zeek_connections": frozenset({"source_ip", "destination_ip"}),
        "pcap_summary": frozenset({"source_ip", "destination_port"}),
    },
)


def dependencies(*, fail: bool = False) -> derived.Dependencies:
    def normalize_filters(operation, filters):
        if fail:
            raise FilterContractError("provider rejected filters")
        return {key: str(value).strip() for key, value in filters.items()}

    def positive(value, default, maximum, _label):
        result = default if value in (None, "") else int(value)
        if result < 1 or result > maximum:
            raise QueryContractError("limit outside policy")
        return result

    return derived.Dependencies(
        normalize_filters=normalize_filters,
        filter_error=FilterContractError,
        positive_integer=positive,
    )


class DerivedQueryPackageTests(unittest.TestCase):
    def normalize(self, parameters, *, deps=None):
        return derived.normalize(
            parameters,
            policy=POLICY,
            dependencies=deps or dependencies(),
            error_type=QueryContractError,
        )

    def test_normalizes_reviewed_operation_filters_and_limit(self) -> None:
        result = self.normalize({
            "operation": "ZEEK_CONNECTIONS",
            "filters": {"source_ip": " 192.0.2.10 "},
            "indicator": "example.test",
        })
        self.assertEqual(result, {
            "operation": "zeek_connections",
            "filters": {"source_ip": "192.0.2.10"},
            "indicator": "example.test",
            "limit": 10,
        })

    def test_rejects_unreviewed_operation_and_operation_specific_filter(self) -> None:
        with self.assertRaisesRegex(QueryContractError, "unsupported.*operation"):
            self.normalize({"operation": "raw_packets"})
        with self.assertRaisesRegex(QueryContractError, "unsupported.*filters"):
            self.normalize({
                "operation": "zeek_connections",
                "filters": {"destination_port": 443},
            })

    def test_rejects_nonobject_nested_and_overlarge_filters(self) -> None:
        cases = (
            "source.ip:192.0.2.10",
            {"source_ip": {"script": "whoami"}},
            {"source_ip": ["192.0.2.10"]},
            {f"field-{index}": index for index in range(17)},
        )
        for filters in cases:
            with self.subTest(filters=filters), self.assertRaises(QueryContractError):
                self.normalize({"operation": "zeek_connections", "filters": filters})

    def test_translates_provider_filter_error_without_bypassing_policy(self) -> None:
        with self.assertRaisesRegex(QueryContractError, "provider rejected filters"):
            self.normalize(
                {"operation": "zeek_connections", "filters": {"source_ip": "x"}},
                deps=dependencies(fail=True),
            )

    def test_limit_remains_bounded(self) -> None:
        for limit in (0, 21):
            with self.subTest(limit=limit), self.assertRaisesRegex(
                QueryContractError, "outside policy"
            ):
                self.normalize({"operation": "pcap_summary", "limit": limit})


if __name__ == "__main__":
    unittest.main()
