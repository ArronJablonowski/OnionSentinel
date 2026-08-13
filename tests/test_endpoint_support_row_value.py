"""Characterize support-binding row and observable admission."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.evidence import endpoint  # noqa: E402


class TracedDict(dict):
    def __init__(self, *args: object, label: str, calls: list[tuple[str, object]], **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.label = label
        self.calls = calls

    def get(self, key: object, default: object = None) -> object:
        self.calls.append((f"{self.label}.get", key))
        return super().get(key, default)

    def __contains__(self, key: object) -> bool:
        self.calls.append((f"{self.label}.contains", key))
        return super().__contains__(key)

    def __getitem__(self, key: object) -> object:
        self.calls.append((f"{self.label}.getitem", key))
        return super().__getitem__(key)


class TracedRows(list):
    def __init__(self, values: list[object], calls: list[tuple[str, object]]) -> None:
        super().__init__(values)
        self.calls = calls

    def __getitem__(self, index: object) -> object:
        self.calls.append(("rows.getitem", index))
        return super().__getitem__(index)


class ExplodingValue:
    def __init__(self, calls: list[str], *, truth: bool = True) -> None:
        self.calls = calls
        self.truth = truth

    def __bool__(self) -> bool:
        self.calls.append("bool")
        return self.truth

    def __str__(self) -> str:
        self.calls.append("str")
        raise RuntimeError("value stringification failed")


def support(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "row_index": 0,
        "column": "name",
        "observable_kind": "host",
    }
    value.update(overrides)
    return value


class EndpointSupportRowValueCharacterizationTests(unittest.TestCase):
    def test_field_access_precedes_index_admission_and_short_circuits_rows(self) -> None:
        calls: list[tuple[str, object]] = []
        result = TracedDict(
            {"rows": TracedRows([{"name": "host-a"}], calls)},
            label="result",
            calls=calls,
        )
        binding = TracedDict(
            support(row_index=True), label="support", calls=calls
        )

        self.assertIsNone(endpoint._support_row_value(binding, result))
        self.assertEqual(calls, [
            ("result.get", "rows"),
            ("support.get", "row_index"),
            ("support.get", "column"),
            ("support.get", "observable_kind"),
        ])

    def test_index_row_column_and_kind_admission_is_fail_closed(self) -> None:
        valid_rows = [{"name": "host-a"}]
        cases = (
            (support(row_index=-1), valid_rows),
            (support(row_index=1), valid_rows),
            (support(row_index=0.0), valid_rows),
            (support(), tuple(valid_rows)),
            (support(), ["not-a-row"]),
            (support(column="missing"), valid_rows),
            (support(observable_kind="process"), valid_rows),
        )
        for binding, rows in cases:
            with self.subTest(binding=binding, rows=rows):
                self.assertIsNone(endpoint._support_row_value(
                    binding, {"rows": rows}
                ))

    def test_selected_row_access_count_and_observable_normalization_are_exact(self) -> None:
        calls: list[tuple[str, object]] = []
        row = TracedDict(
            {"name": "  HoSt.Example...  "}, label="row", calls=calls
        )
        rows = TracedRows([row], calls)

        self.assertEqual(
            endpoint._support_row_value(support(), {"rows": rows}),
            ("host", "host.example"),
        )
        self.assertEqual(calls, [
            ("rows.getitem", 0),
            ("rows.getitem", 0),
            ("row.contains", "name"),
            ("rows.getitem", 0),
            ("row.getitem", "name"),
        ])

        cases = (
            ("domain", "  Example.COM. ", "example.com"),
            ("user", "  Alice. ", "alice"),
            ("ip", "  ABCD::EF. ", "ABCD::EF"),
            ("port", "  HTTPS. ", "HTTPS"),
            ("host", None, ""),
            ("host", 0, ""),
        )
        for kind, raw, expected in cases:
            with self.subTest(kind=kind, raw=raw):
                self.assertEqual(
                    endpoint._support_row_value(
                        support(observable_kind=kind), {"rows": [{"name": raw}]}
                    ),
                    (kind, expected),
                )

    def test_value_truthiness_and_stringification_exceptions_keep_precedence(self) -> None:
        calls: list[str] = []
        value = ExplodingValue(calls)
        binding = support()
        result = {"rows": [{"name": value}]}
        before_binding = deepcopy(binding)
        before_rows = list(result["rows"])

        with self.assertRaisesRegex(RuntimeError, "stringification failed"):
            endpoint._support_row_value(binding, result)

        self.assertEqual(calls, ["bool", "str"])
        self.assertEqual(binding, before_binding)
        self.assertEqual(result["rows"], before_rows)


if __name__ == "__main__":
    unittest.main()
