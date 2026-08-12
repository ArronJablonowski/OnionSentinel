"""Characterize investigation hit-source dotted-path traversal."""

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
SCRIPT = BIN / "investigation_query_response_source.py"
sys.path.insert(0, str(BIN))


def load_module():
    spec = importlib.util.spec_from_file_location(
        "investigation_query_response_source_paths_characterized",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


SOURCE = load_module()


class InvestigationQuerySourcePathTests(unittest.TestCase):
    def test_nested_dictionary_path_returns_the_terminal_scalar(self):
        source = {"event": {"dataset": "zeek.connection"}}

        self.assertEqual(
            SOURCE._path_values(source, "event.dataset"),
            ["zeek.connection"],
        )
        self.assertEqual(SOURCE._path_values(source, "event.missing"), [])
        self.assertEqual(SOURCE._path_values(source, "missing.dataset"), [])

    def test_dictionary_array_values_preserve_order_and_duplicates(self):
        source = {
            "related": {
                "ip": ["10.0.0.1", "10.0.0.2", "10.0.0.1", None]
            }
        }

        self.assertEqual(
            SOURCE._path_values(source, "related.ip"),
            ["10.0.0.1", "10.0.0.2", "10.0.0.1", None],
        )

    def test_arrays_of_objects_are_traversed_for_each_path_component(self):
        source = {
            "network": [
                {"transport": "tcp"},
                {"transport": ["udp", "icmp"]},
                {"other": "ignored"},
                "ignored",
                None,
            ]
        }

        self.assertEqual(
            SOURCE._path_values(source, "network.transport"),
            ["tcp", "udp", "icmp"],
        )

    def test_list_nodes_scan_immediate_dictionary_children_not_deeper_lists(self):
        source = {
            "outer": [
                [{"value": "one-list-level"}],
                {"value": "direct"},
                [[{"value": "two-list-levels-not-recursed"}]],
            ]
        }

        self.assertEqual(
            SOURCE._path_values(source, "outer.value"),
            ["one-list-level", "direct"],
        )

    def test_terminal_mappings_and_lists_are_filtered_but_other_objects_remain(self):
        marker = ("tuple", 1)
        source = {
            "values": [
                {"mapping": True},
                ["nested-list"],
                marker,
                0,
                False,
                "",
                None,
            ]
        }

        self.assertEqual(
            SOURCE._path_values(source, "values"),
            [marker, 0, False, "", None],
        )

    def test_empty_path_components_are_literal_dictionary_keys(self):
        source = {
            "": "root-empty",
            "a": {
                "": {"b": "middle-empty"},
                "b": {"": "trailing-empty"},
            },
        }

        self.assertEqual(SOURCE._path_values(source, ""), ["root-empty"])
        self.assertEqual(SOURCE._path_values(source, "a..b"), ["middle-empty"])
        self.assertEqual(SOURCE._path_values(source, "a.b."), ["trailing-empty"])

    def test_outer_list_is_accepted_by_runtime_traversal_despite_dict_annotation(self):
        source = [
            {"event": {"dataset": "one"}},
            {"event": {"dataset": "two"}},
            "ignored",
        ]

        self.assertEqual(
            SOURCE._path_values(source, "event.dataset"),
            ["one", "two"],
        )

    def test_non_string_path_retains_native_attribute_error(self):
        with self.assertRaisesRegex(AttributeError, "split"):
            SOURCE._path_values({"a": 1}, None)

    def test_large_breadth_and_depth_are_not_silently_truncated(self):
        source: object = {"leaf": list(range(300))}
        parts = ["root"] * 30 + ["leaf"]
        for _part in reversed(parts[:-1]):
            source = {"root": source}

        self.assertEqual(
            SOURCE._path_values(source, ".".join(parts)),
            list(range(300)),
        )

    def test_traversal_is_read_only(self):
        source = {
            "items": [
                {"field": [1, 2]},
                {"field": 3},
            ]
        }
        before = copy.deepcopy(source)

        self.assertEqual(SOURCE._path_values(source, "items.field"), [1, 2, 3])
        self.assertEqual(source, before)


if __name__ == "__main__":
    unittest.main()
