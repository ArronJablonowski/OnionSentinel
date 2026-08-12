from __future__ import annotations

import ast
import copy
import datetime as dt
import importlib.machinery
import importlib.util
import inspect
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n/bin/collect-endpoint-software-inventory.py"
COLLECTION = ROOT / "n8n/bin/endpoint_inventory_collection.py"
BIN = ROOT / "n8n/bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))


def load_collector():
    loader = importlib.machinery.SourceFileLoader(
        "endpoint_inventory_collection_architecture", str(SCRIPT)
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def function_metrics(name: str, path: Path = SCRIPT) -> tuple[int, int]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    target = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )

    class Complexity(ast.NodeVisitor):
        def __init__(self):
            self.value = 1

        def visit_FunctionDef(self, node):
            return

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_If(self, node):
            self.value += 1
            self.generic_visit(node)

        visit_For = visit_If
        visit_While = visit_If

        def visit_Try(self, node):
            self.value += len(node.handlers)
            self.generic_visit(node)

        def visit_BoolOp(self, node):
            self.value += max(0, len(node.values) - 1)
            self.generic_visit(node)

        def visit_IfExp(self, node):
            self.value += 1
            self.generic_visit(node)

        def visit_ListComp(self, node):
            self.value += sum(
                1 + len(generator.ifs) for generator in node.generators
            )
            self.generic_visit(node)

        visit_SetComp = visit_ListComp
        visit_GeneratorExp = visit_ListComp
        visit_DictComp = visit_ListComp

    visitor = Complexity()
    for child in target.body:
        visitor.visit(child)
    return target.end_lineno - target.lineno + 1, visitor.value


class EndpointInventoryCollectionArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.collector = load_collector()

    @staticmethod
    def config() -> dict:
        return {
            "enabled": True,
            "allowed_target_aliases": ["studio-a", "studio-b"],
            "scheduled_inventory_approval": {
                "approved": True,
                "target_aliases": ["studio-a", "studio-b"],
            },
        }

    def test_signature_and_quality_boundaries_are_exact(self) -> None:
        signature = inspect.signature(self.collector.collect)
        self.assertEqual(list(signature.parameters), ["config", "previous_cache"])
        self.assertIsNone(signature.parameters["previous_cache"].default)
        self.assertEqual(str(signature.return_annotation), "dict[str, Any]")
        lines, complexity = function_metrics("collect")
        self.assertLessEqual(lines, 35)
        self.assertLessEqual(complexity, 5)
        for name in (
            "record",
            "_approved_aliases",
            "_prior_record_index",
            "_identity_rows",
            "_target_identity",
            "_operating_system",
            "_project_application",
            "_project_homebrew",
            "_target_rows",
            "_target_records",
            "_target_receipt",
            "_normalized_records",
            "collect_inventory",
        ):
            lines, complexity = function_metrics(name, COLLECTION)
            self.assertLessEqual(lines, 50)
            self.assertLessEqual(complexity, 10)
        self.assertLessEqual(len(COLLECTION.read_text().splitlines()), 600)
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text()
        self.assertIn(
            'cp "$REPO_DIR/n8n/bin/endpoint_inventory_collection.py" '
            '"$STACK_DIR/bin/endpoint_inventory_collection.py"',
            installer,
        )

    def test_pagination_and_cli_phases_meet_quality_boundaries(self) -> None:
        for name in (
            "_admitted_page_cursor",
            "_append_inventory_page",
            "_paged_rows",
            "_parse_args",
            "main",
        ):
            lines, complexity = function_metrics(name)
            self.assertLessEqual(lines, 50)
            self.assertLessEqual(complexity, 10)

    def test_query_projection_deduplication_order_and_inputs_are_exact(self) -> None:
        config = self.config()
        previous = {
            "schema": self.collector.SCHEMA,
            "updated_at": "2026-08-01T00:00:00.000Z",
            "records": [
                {"evidence_id": "prior", "first_seen": "2026-07-01T00:00:00Z"},
                "ignored",
            ],
        }
        before = copy.deepcopy((config, previous))
        trace: list = []
        prior_ids: list[int] = []

        def approved(supplied_config, alias):
            trace.append(["approved", copy.deepcopy(supplied_config), alias])
            return True

        def query(supplied_config, alias, sql, purpose, case_id):
            trace.append(["query", supplied_config is config, alias, sql, purpose, case_id])
            if "system_info" in sql:
                return [{"hostname": f"{alias}.example."}]
            if "os_version" in sql:
                return [{
                    "name": "macOS",
                    "version": "26.0",
                    "build": "25A1",
                    "platform": "darwin",
                }]
            raise AssertionError(sql)

        def paged(supplied_config, alias, table, columns, case_id):
            trace.append([
                "paged", supplied_config is config, alias, table, columns, case_id,
            ])
            if table == "apps":
                return [
                    {
                        "name": "Duplicate",
                        "path": f"/Applications/{alias}/Duplicate.app",
                        "bundle_short_version": "1",
                    },
                    {"name": "", "path": f"/Applications/{alias}/Empty.app"},
                ]
            return [{
                "name": f"Brew-{alias}",
                "path": f"/opt/homebrew/{alias}",
                "version": "2",
            }]

        def record(**values):
            trace.append(["record", copy.deepcopy(values)])
            prior_ids.append(id(values["previous"]))
            evidence_id = "duplicate" if values["product"] == "Duplicate" else values["product"]
            return {
                "evidence_id": evidence_id,
                "asset_ref": values["hostname"],
                "product": values["product"],
                "version": values["version"],
                "category": values["category"],
                "path": values["path"],
                "previous_keys": sorted(values["previous"]),
            }

        moment = dt.datetime(2026, 8, 12, 18, 0, tzinfo=dt.timezone.utc)
        with (
            mock.patch.object(self.collector, "scheduled_inventory_approved", approved),
            mock.patch.object(self.collector, "_query", query),
            mock.patch.object(self.collector, "_paged_rows", paged),
            mock.patch.object(self.collector, "_record", record),
            mock.patch.object(self.collector, "utc_now", return_value=moment),
            mock.patch.object(
                self.collector, "timestamp", return_value="2026-08-12T18:00:00.000Z"
            ),
        ):
            result = self.collector.collect(config, previous)

        self.assertEqual((config, previous), before)
        self.assertEqual(
            [item[:3] for item in trace if item[0] in {"approved", "query", "paged"}],
            [
                ["approved", config, "studio-a"],
                ["approved", config, "studio-b"],
                ["query", True, "studio-a"],
                ["query", True, "studio-a"],
                ["paged", True, "studio-a"],
                ["paged", True, "studio-a"],
                ["query", True, "studio-b"],
                ["query", True, "studio-b"],
                ["paged", True, "studio-b"],
                ["paged", True, "studio-b"],
            ],
        )
        query_calls = [item for item in trace if item[0] == "query"]
        self.assertEqual(
            [(item[3], item[4], item[5]) for item in query_calls],
            [
                (
                    "SELECT hostname FROM system_info LIMIT 1;",
                    "Bind scheduled software inventory to the endpoint hostname",
                    "scheduled-endpoint-software-20260812",
                ),
                (
                    "SELECT name,version,build,platform,arch FROM os_version LIMIT 1;",
                    "Record the endpoint operating system version",
                    "scheduled-endpoint-software-20260812",
                ),
            ] * 2,
        )
        paged_calls = [item for item in trace if item[0] == "paged"]
        self.assertEqual(
            [(item[3], item[4], item[5]) for item in paged_calls],
            [
                ("apps", self.collector.APPS_COLUMNS, "scheduled-endpoint-software-20260812"),
                ("homebrew_packages", self.collector.BREW_COLUMNS, "scheduled-endpoint-software-20260812"),
            ] * 2,
        )
        record_calls = [item[1] for item in trace if item[0] == "record"]
        self.assertEqual(len(record_calls), 4)
        self.assertEqual(len(set(prior_ids)), 1)
        self.assertTrue(all(item["previous"] == {"prior": previous["records"][0]} for item in record_calls))
        self.assertEqual(
            [(item["hostname"], item["product"], item["category"], item["os_version"])
             for item in record_calls],
            [
                ("studio-a.example", "Duplicate", "application", "macOS 26.0 (build 25A1)"),
                ("studio-a.example", "Brew-studio-a", "package:homebrew", "macOS 26.0 (build 25A1)"),
                ("studio-b.example", "Duplicate", "application", "macOS 26.0 (build 25A1)"),
                ("studio-b.example", "Brew-studio-b", "package:homebrew", "macOS 26.0 (build 25A1)"),
            ],
        )
        self.assertEqual(
            result,
            {
                "schema": self.collector.SCHEMA,
                "version": 1,
                "updated_at": "2026-08-12T18:00:00.000Z",
                "complete": True,
                "targets": [
                    {
                        "asset_ref": "b78f41e3c190126e4647e242",
                        "status": "ok",
                        "records": 2,
                        "observed_at": "2026-08-12T18:00:00.000Z",
                    },
                    {
                        "asset_ref": "a1cbe8e341ca9b81d0f0fd70",
                        "status": "ok",
                        "records": 2,
                        "observed_at": "2026-08-12T18:00:00.000Z",
                    },
                ],
                "records": [
                    {
                        "evidence_id": "Brew-studio-a",
                        "asset_ref": "studio-a.example",
                        "product": "Brew-studio-a",
                        "version": "2",
                        "category": "package:homebrew",
                        "path": "/opt/homebrew/studio-a",
                        "previous_keys": ["prior"],
                    },
                    {
                        "evidence_id": "Brew-studio-b",
                        "asset_ref": "studio-b.example",
                        "product": "Brew-studio-b",
                        "version": "2",
                        "category": "package:homebrew",
                        "path": "/opt/homebrew/studio-b",
                        "previous_keys": ["prior"],
                    },
                    {
                        "evidence_id": "duplicate",
                        "asset_ref": "studio-b.example",
                        "product": "Duplicate",
                        "version": "1",
                        "category": "application",
                        "path": "/Applications/studio-b/Duplicate.app",
                        "previous_keys": ["prior"],
                    },
                ],
            },
        )

    def test_admission_and_identity_failures_stop_at_exact_boundaries(self) -> None:
        with self.assertRaisesRegex(
            self.collector.EndpointInventoryError,
            "no scheduled inventory endpoint alias is approved",
        ):
            self.collector.collect({"scheduled_inventory_approval": {}})

        config = self.config()
        with (
            mock.patch.object(
                self.collector,
                "scheduled_inventory_approved",
                side_effect=[True, False],
            ) as approved,
            mock.patch.object(self.collector, "_query") as query,
            self.assertRaisesRegex(
                self.collector.EndpointInventoryError,
                "scheduled inventory approval is incomplete",
            ),
        ):
            self.collector.collect(config)
        self.assertEqual(approved.call_count, 2)
        query.assert_not_called()

        with (
            mock.patch.object(
                self.collector, "scheduled_inventory_approved", return_value=True
            ),
            mock.patch.object(
                self.collector,
                "_query",
                side_effect=[[], [{"name": "macOS", "version": "26"}]],
            ) as query,
            mock.patch.object(self.collector, "_paged_rows") as paged,
            self.assertRaisesRegex(
                self.collector.EndpointInventoryError,
                "endpoint identity or operating system is ambiguous",
            ),
        ):
            self.collector.collect(config)
        self.assertEqual(query.call_count, 2)
        paged.assert_not_called()

    def test_invalid_hostname_fails_before_pagination(self) -> None:
        config = self.config()
        with (
            mock.patch.object(
                self.collector, "scheduled_inventory_approved", return_value=True
            ),
            mock.patch.object(
                self.collector,
                "_query",
                side_effect=[
                    [{"hostname": "bad host"}],
                    [{"name": "macOS", "version": "26"}],
                ],
            ),
            mock.patch.object(self.collector, "_paged_rows") as paged,
            self.assertRaisesRegex(
                self.collector.EndpointInventoryError,
                "endpoint returned an invalid hostname",
            ),
        ):
            self.collector.collect(config)
        paged.assert_not_called()


if __name__ == "__main__":
    unittest.main()
