#!/usr/bin/env python3
"""Trace modularization seams to executable behavior contracts."""
from __future__ import annotations

import ast
import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = (
    REPO_ROOT / "operations" / "quality" / "modularization-characterization.json"
)
EXPECTED_SEAMS = {
    "provider_adapter",
    "query_engine",
    "review_pipeline",
    "conclusion_pipeline",
    "result_unit_of_work",
    "scheduler_job_repository",
    "harness_repository_run",
    "portal_route_service",
    "dashboard_page_component",
    "alert_store_route_service",
}


def declared_test_symbols(path: Path) -> set[tuple[str, str]]:
    """Return class/test pairs declared in one unittest source file."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    symbols: set[tuple[str, str]] = set()
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if child.name.startswith("test_"):
                    symbols.add((node.name, child.name))
    return symbols


class ModularizationCharacterizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))

    def test_matrix_covers_every_architecture_seam_and_path_category(self) -> None:
        self.assertEqual(
            self.matrix["schema"],
            "onion-sentinel-modularization-characterization-v1",
        )
        self.assertEqual(set(self.matrix["seams"]), EXPECTED_SEAMS)
        categories = self.matrix["requirements"]["categories"]
        minimum = self.matrix["requirements"]["minimum_tests_per_category"]
        self.assertEqual(categories, ["positive", "negative", "failure"])
        self.assertGreaterEqual(minimum, 1)
        for seam, coverage in self.matrix["seams"].items():
            with self.subTest(seam=seam):
                self.assertEqual(set(coverage), set(categories))
                for category in categories:
                    self.assertGreaterEqual(len(coverage[category]), minimum)

    def test_every_characterization_reference_names_a_real_unittest(self) -> None:
        cache: dict[Path, set[tuple[str, str]]] = {}
        seen: set[str] = set()
        for seam, coverage in self.matrix["seams"].items():
            for category, references in coverage.items():
                for reference in references:
                    with self.subTest(
                        seam=seam,
                        category=category,
                        reference=reference,
                    ):
                        parts = reference.split("::")
                        self.assertEqual(len(parts), 3)
                        relative, class_name, test_name = parts
                        self.assertNotIn(reference, seen)
                        seen.add(reference)
                        path = REPO_ROOT / relative
                        self.assertTrue(path.is_file())
                        cache.setdefault(path, declared_test_symbols(path))
                        self.assertIn((class_name, test_name), cache[path])

    def test_characterization_uses_bounded_repository_fixtures_only(self) -> None:
        serialized = json.dumps(self.matrix, sort_keys=True)
        self.assertNotIn("/Users/", serialized)
        self.assertNotIn("192.168.", serialized)
        self.assertNotIn("10.77.", serialized)
        self.assertNotIn("10.88.", serialized)
        self.assertNotIn("credential", serialized.lower())
        for coverage in self.matrix["seams"].values():
            for references in coverage.values():
                for reference in references:
                    self.assertTrue(reference.startswith("tests/test_"))


if __name__ == "__main__":
    unittest.main()
