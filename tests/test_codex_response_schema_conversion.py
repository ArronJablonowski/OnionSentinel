"""Characterize strict Codex response-schema conversion."""
from __future__ import annotations

import copy
import unittest

from n8n.onion_sentinel.analysis.providers import codex


class TrackingDict(dict):
    def __init__(self, *args: object, trace: list[object], label: str, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.trace = trace
        self.label = label

    def items(self):
        self.trace.append(("items", self.label))
        return super().items()


class CodexResponseSchemaConversionTests(unittest.TestCase):
    def test_special_key_precedence_and_scalar_types_are_exact(self) -> None:
        template = {
            "duplicate_of": False,
            "enum_key": True,
            "boolean_key": 1,
            "confidence_score": "ignored",
            "ttl_days": 0,
            "review_evidence_hash": None,
            "plain_bool": True,
            "plain_int": 7,
            "plain_float": 1.5,
            "plain_text": None,
        }
        schema = codex.response_schema(
            template,
            structured_enums={
                "duplicate_of": ["enum-must-not-win"],
                "enum_key": ["one", "two"],
            },
            boolean_keys=frozenset({"duplicate_of", "enum_key", "boolean_key"}),
        )
        properties = schema["properties"]
        self.assertEqual(properties["duplicate_of"], {"type": ["string", "null"]})
        self.assertEqual(properties["enum_key"], {"type": "string", "enum": ["one", "two"]})
        self.assertEqual(properties["boolean_key"], {"type": "boolean"})
        self.assertEqual(properties["confidence_score"], {
            "type": "number", "minimum": 0.0, "maximum": 1.0,
        })
        self.assertEqual(properties["ttl_days"], {
            "type": "integer", "minimum": 7, "maximum": 365,
        })
        self.assertEqual(properties["review_evidence_hash"], {
            "type": "string", "pattern": "^[a-f0-9]{64}$",
        })
        self.assertEqual(properties["plain_bool"], {"type": "boolean"})
        self.assertEqual(properties["plain_int"], {"type": "integer"})
        self.assertEqual(properties["plain_float"], {"type": "number"})
        self.assertEqual(properties["plain_text"], {"type": "string"})

    def test_nested_iteration_key_stringification_and_list_behavior_are_exact(self) -> None:
        trace: list[object] = []
        child = TrackingDict(
            {2: [True, "ignored"], "empty": []}, trace=trace, label="child"
        )
        root = TrackingDict(
            {"child": child, "rows": [{"value": 1}, {"ignored": 2}]},
            trace=trace,
            label="root",
        )
        schema = codex.response_schema(
            root, structured_enums={}, boolean_keys=frozenset()
        )
        self.assertEqual(trace, [("items", "root"), ("items", "child")])
        self.assertEqual(schema["required"], ["child", "rows"])
        self.assertEqual(schema["properties"]["child"]["required"], ["2", "empty"])
        self.assertEqual(
            schema["properties"]["child"]["properties"]["2"],
            {"type": "array", "items": {"type": "boolean"}},
        )
        self.assertEqual(
            schema["properties"]["child"]["properties"]["empty"],
            {"type": "array", "items": {"type": "string"}},
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertFalse(schema["properties"]["child"]["additionalProperties"])
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(schema["title"], "Onion Sentinel structured analysis response")

    def test_mapping_iteration_exception_propagates(self) -> None:
        class ExplodingDict(dict):
            def items(self):
                raise LookupError("schema items failed")

        with self.assertRaisesRegex(LookupError, "schema items failed"):
            codex.response_schema(
                ExplodingDict(value=1),
                structured_enums={},
                boolean_keys=frozenset(),
            )

    def test_inputs_are_not_mutated_and_enum_list_is_reused(self) -> None:
        enum_values = ["first", "second"]
        enums = {"status": enum_values}
        template = {"status": "first", "nested": {"values": [1]}}
        template_snapshot = copy.deepcopy(template)
        enums_snapshot = copy.deepcopy(enums)
        schema = codex.response_schema(
            template, structured_enums=enums, boolean_keys=frozenset()
        )
        self.assertIs(schema["properties"]["status"]["enum"], enum_values)
        self.assertEqual(template, template_snapshot)
        self.assertEqual(enums, enums_snapshot)


if __name__ == "__main__":
    unittest.main()
