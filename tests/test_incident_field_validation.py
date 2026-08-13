"""Characterize Incident Responder top-level field validation."""
from __future__ import annotations

import copy
from dataclasses import replace
import unittest

from n8n.onion_sentinel.analysis.conclusions import incident_report
from tests.test_conclusion_incident_report_package import dependencies


class OrderedFields:
    def __init__(self, values: list[str], trace: list[object], label: str) -> None:
        self.values = values
        self.trace = trace
        self.label = label

    def __iter__(self):
        for value in self.values:
            self.trace.append(("field", self.label, value))
            yield value


class TrackingReport(dict):
    def __init__(self, *args: object, trace: list[object], **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.trace = trace

    def __contains__(self, key: object) -> bool:
        self.trace.append(("contains", key))
        return super().__contains__(key)

    def get(self, key: object, default: object = None) -> object:
        self.trace.append(("get", key, default))
        return super().get(key, default)


class TrackingText(str):
    def __new__(cls, value: str, trace: list[object], label: str):
        instance = super().__new__(cls, value)
        instance.trace = trace
        instance.label = label
        return instance

    def strip(self, *args: object, **kwargs: object) -> str:
        self.trace.append(("strip", self.label))
        return super().strip(*args, **kwargs)


class TrackingList(list):
    def __init__(self, values: list[object], trace: list[object], label: str) -> None:
        super().__init__(values)
        self.trace = trace
        self.label = label

    def __iter__(self):
        self.trace.append(("iter", self.label))
        return super().__iter__()


class IncidentFieldValidationTests(unittest.TestCase):
    def test_phase_order_access_counts_and_short_circuiting_are_exact(self) -> None:
        trace: list[object] = []
        fields = replace(
            dependencies(),
            text_fields=OrderedFields(
                ["valid_text", "invalid_text", "missing_text"],
                trace,
                "text",
            ),
            list_fields=OrderedFields(
                [
                    "missing_list",
                    "not_list",
                    "bad_items",
                    "factual_timeline",
                    "valid_items",
                ],
                trace,
                "list",
            ),
        )
        report = TrackingReport(
            {
                "valid_text": " present ",
                "invalid_text": 7,
                "not_list": "not-a-list",
                "bad_items": TrackingList(
                    [
                        TrackingText("good", trace, "good"),
                        9,
                        TrackingText("unreached", trace, "unreached"),
                    ],
                    trace,
                    "bad_items",
                ),
                "factual_timeline": TrackingList(
                    [object()], trace, "factual_timeline"
                ),
                "valid_items": TrackingList(
                    [TrackingText(" value ", trace, "valid")],
                    trace,
                    "valid_items",
                ),
            },
            trace=trace,
        )

        result = incident_report._field_validation(report, fields)

        self.assertEqual(result, ["invalid_text", "not_list", "bad_items[]"])
        self.assertEqual(
            trace,
            [
                ("field", "text", "valid_text"),
                ("contains", "valid_text"),
                ("get", "valid_text", None),
                ("get", "valid_text", None),
                ("field", "text", "invalid_text"),
                ("contains", "invalid_text"),
                ("get", "invalid_text", None),
                ("field", "text", "missing_text"),
                ("contains", "missing_text"),
                ("field", "list", "missing_list"),
                ("contains", "missing_list"),
                ("field", "list", "not_list"),
                ("contains", "not_list"),
                ("get", "not_list", None),
                ("field", "list", "bad_items"),
                ("contains", "bad_items"),
                ("get", "bad_items", None),
                ("iter", "bad_items"),
                ("strip", "good"),
                ("field", "list", "factual_timeline"),
                ("contains", "factual_timeline"),
                ("get", "factual_timeline", None),
                ("field", "list", "valid_items"),
                ("contains", "valid_items"),
                ("get", "valid_items", None),
                ("iter", "valid_items"),
                ("strip", "valid"),
            ],
        )

    def test_empty_text_and_list_item_rules_preserve_exact_markers(self) -> None:
        fields = replace(
            dependencies(),
            text_fields=("empty", "whitespace"),
            list_fields=("empty_items", "non_string_items", "factual_timeline"),
        )
        report = {
            "empty": "",
            "whitespace": " \t\n",
            "empty_items": ["valid", ""],
            "non_string_items": [None],
            "factual_timeline": [None, "", {}],
        }
        self.assertEqual(
            incident_report._field_validation(report, fields),
            ["empty", "whitespace", "empty_items[]", "non_string_items[]"],
        )

    def test_iterator_and_mapping_exceptions_propagate_at_the_same_boundary(self) -> None:
        class ExplodingFields:
            def __iter__(self):
                yield "first"
                raise LookupError("field iteration failed")

        fields = replace(
            dependencies(),
            text_fields=ExplodingFields(),
            list_fields=(),
        )
        with self.assertRaisesRegex(LookupError, "field iteration failed"):
            incident_report._field_validation({"first": "valid"}, fields)

        class ExplodingReport(dict):
            def get(self, key: object, default: object = None) -> object:
                raise RuntimeError("report get failed")

        fields = replace(dependencies(), text_fields=("value",), list_fields=())
        with self.assertRaisesRegex(RuntimeError, "report get failed"):
            incident_report._field_validation(
                ExplodingReport(value="present"), fields
            )

    def test_input_is_not_mutated(self) -> None:
        fields = replace(
            dependencies(),
            text_fields=("text",),
            list_fields=("items", "factual_timeline"),
        )
        report = {
            "text": "value",
            "items": ["one", "two"],
            "factual_timeline": [{"timestamp": "not-validated-here"}],
        }
        snapshot = copy.deepcopy(report)
        self.assertEqual(incident_report._field_validation(report, fields), [])
        self.assertEqual(report, snapshot)


if __name__ == "__main__":
    unittest.main()
