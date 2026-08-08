#!/usr/bin/env python3
"""Direct contracts for Resource Library mutation dispatch."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_request_routes import classify_post_route  # noqa: E402
from portal_resource_library_write import (  # noqa: E402
    ResourceLibraryWriteCallbacks,
    prepare_resource_library_write,
)


def route(path: str):
    return classify_post_route(
        path,
        cti_program_path="/api/cyber-threat-intel/program",
        prompt_paths=frozenset(),
    )


def callbacks(calls: list[tuple]) -> ResourceLibraryWriteCallbacks:
    return ResourceLibraryWriteCallbacks(
        remove=lambda *args: (calls.append(("remove", *args)) or True, {"ok": True}),
        set_tags=lambda *args: (calls.append(("tags", *args)) or True, {"ok": True}),
        rename=lambda *args: (calls.append(("rename", *args)) or True, {"ok": True}),
        set_favorite=lambda *args: (
            calls.append(("favorite", *args)) or True, {"ok": True}
        ),
    )


class ResourceLibraryWriteTests(unittest.TestCase):
    def test_other_route_is_declined_without_dispatch(self) -> None:
        calls: list[tuple] = []
        result = prepare_resource_library_write(
            route("/api/soc-alerts/status"), "{}", callbacks=callbacks(calls),
        )
        self.assertIsNone(result)
        self.assertEqual(calls, [])

    def test_all_classified_mutations_normalize_their_payloads(self) -> None:
        cases = (
            (
                "/api/resource-library/remove",
                '{"id":" abc ","source":" /tmp/source "}',
                ("remove", "abc", "/tmp/source"),
            ),
            (
                "/api/resource-library/tags",
                '{"id":"abc","tags":["one","two"]}',
                ("tags", "abc", ["one", "two"]),
            ),
            (
                "/api/resource-library/rename",
                '{"id":"abc","source":"old","new_name":" New Name "}',
                ("rename", "abc", "old", "New Name"),
            ),
            (
                "/api/resource-library/favorite",
                '{"id":"abc","favorite":1}',
                ("favorite", "abc", True),
            ),
        )
        for path, raw, expected in cases:
            with self.subTest(path=path):
                calls: list[tuple] = []
                result = prepare_resource_library_write(
                    route(path), raw, callbacks=callbacks(calls),
                )
                self.assertEqual(result.status, 200)
                self.assertEqual(calls, [expected])

    def test_non_object_json_falls_back_to_empty_mutation_payload(self) -> None:
        calls: list[tuple] = []
        result = prepare_resource_library_write(
            route("/api/resource-library/remove"),
            "[]",
            callbacks=callbacks(calls),
        )
        self.assertEqual(result.status, 200)
        self.assertEqual(calls, [("remove", "", "")])

    def test_mutation_failure_maps_to_bad_request(self) -> None:
        bound = callbacks([])
        bound = ResourceLibraryWriteCallbacks(
            remove=lambda _id, _source: (
                False, {"ok": False, "error": "Resource not found"},
            ),
            set_tags=bound.set_tags,
            rename=bound.rename,
            set_favorite=bound.set_favorite,
        )
        result = prepare_resource_library_write(
            route("/api/resource-library/remove"), "{}", callbacks=bound,
        )
        self.assertEqual(result.status, 400)
        self.assertEqual(result.payload["error"], "Resource not found")


if __name__ == "__main__":
    unittest.main()
