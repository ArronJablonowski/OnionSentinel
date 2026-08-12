from __future__ import annotations

import ast
import copy
import importlib.machinery
import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n/bin/pcap_processor_contract.py"
WORKFLOW = ROOT / "n8n/bin/pcap_geoip_workflow.py"
BIN = ROOT / "n8n/bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))


def load_contract():
    loader = importlib.machinery.SourceFileLoader(
        "maxmind_geoip_summary_architecture", str(SCRIPT)
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


class FakeCandidates:
    def __init__(self, rows):
        self.rows = copy.deepcopy(rows)
        self.calls = []

    def most_common(self, fields, limit):
        self.calls.append([fields, limit])
        return copy.deepcopy(self.rows[:limit])


class FakeReader:
    def __init__(
        self,
        database_type,
        records,
        *,
        metadata_error=None,
        close_error=None,
    ):
        self.database_type = database_type
        self.records = records
        self.metadata_error = metadata_error
        self.close_error = close_error
        self.calls = []
        self.closed = False

    def metadata(self):
        self.calls.append(["metadata"])
        if self.metadata_error is not None:
            raise self.metadata_error
        return types.SimpleNamespace(database_type=self.database_type)

    def get(self, address):
        self.calls.append(["get", address])
        value = self.records[address]
        if isinstance(value, BaseException):
            raise value
        return copy.deepcopy(value)

    def close(self):
        self.calls.append(["close"])
        if self.close_error is not None:
            raise self.close_error
        self.closed = True


class MaxmindGeoipSummaryArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_contract()

    def test_signature_and_quality_boundaries_are_exact(self) -> None:
        lines, complexity = function_metrics("maxmind_geoip_summary")
        self.assertLessEqual(lines, 35)
        self.assertLessEqual(complexity, 5)
        for name in (
            "_normalized_paths",
            "_initial_summary",
            "_candidate_contexts",
            "_ready_paths",
            "_reader_module",
            "_open_readers",
            "_lookup_record",
            "_lookup_address",
            "_lookup_candidates",
            "_close_readers",
            "_finalize_summary",
            "summarize_geoip",
        ):
            lines, complexity = function_metrics(name, WORKFLOW)
            self.assertLessEqual(lines, 50)
            self.assertLessEqual(complexity, 10)
        self.assertLessEqual(len(WORKFLOW.read_text().splitlines()), 600)
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text()
        self.assertIn(
            'cp "$REPO_DIR/n8n/bin/pcap_geoip_workflow.py" '
            '"$STACK_DIR/bin/pcap_geoip_workflow.py"',
            installer,
        )

    def test_missing_paths_preserve_status_order_and_reason(self) -> None:
        candidates = FakeCandidates([
            {"ip": "8.8.8.8", "role": "destination", "count": 3},
            {"ip": "10.0.0.1", "role": "source", "count": 20},
        ])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                "country": root / "country.mmdb",
                "unknown": root / "ignored.mmdb",
                "asn": root / "asn.mmdb",
            }
            before = copy.deepcopy(paths)
            result = self.contract.maxmind_geoip_summary(candidates, paths)

        self.assertEqual(paths, before)
        self.assertEqual(
            candidates.calls,
            [[("ip", "role"), self.contract.MAXMIND_GEOIP_MAX_LOOKUPS * 2]],
        )
        self.assertEqual(result["public_ip_candidates"], 1)
        self.assertEqual(list(result["databases"]), ["asn", "country"])
        self.assertTrue(
            all(status["state"] == "missing" for status in result["databases"].values())
        )
        self.assertEqual(
            result["reason"], "No configured MaxMind MMDB files are installed"
        )
        self.assertFalse(result["available"])
        self.assertEqual(result["lookups_attempted"], 0)
        self.assertEqual(result["records"], [])

    def test_ready_databases_merge_and_account_in_fixed_lookup_order(self) -> None:
        rows = [
            {"ip": "8.8.8.8", "role": "destination", "count": 3},
            {"ip": "8.8.8.8", "role": "source", "count": 2},
            {"ip": "1.1.1.1", "role": "destination", "count": 4},
            {"ip": "10.0.0.1", "role": "source", "count": 100},
        ]
        candidates = FakeCandidates(rows)
        readers = {
            "asn": FakeReader(
                "GeoLite2-ASN",
                {
                    "8.8.8.8": {
                        "autonomous_system_number": 15169,
                        "autonomous_system_organization": "Google LLC",
                    },
                    "1.1.1.1": None,
                },
            ),
            "city": FakeReader(
                "GeoLite2-City",
                {
                    "8.8.8.8": RuntimeError("synthetic city lookup failure"),
                    "1.1.1.1": {
                        "city": {"names": {"en": "Sydney"}},
                        "location": {"time_zone": "Australia/Sydney"},
                    },
                },
            ),
            "country": FakeReader(
                "GeoLite2-Country",
                {
                    "8.8.8.8": {
                        "country": {"iso_code": "US", "names": {"en": "United States"}}
                    },
                    "1.1.1.1": {
                        "country": {"iso_code": "AU", "names": {"en": "Australia"}}
                    },
                },
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {}
            for database_type in ("country", "asn", "city"):
                path = root / f"{database_type}.mmdb"
                path.write_bytes(b"synthetic")
                paths[database_type] = path

            def open_database(path):
                database_type = Path(path).stem
                return readers[database_type]

            fake_module = types.SimpleNamespace(open_database=open_database)
            before = copy.deepcopy((rows, paths))
            with mock.patch.dict(sys.modules, {"maxminddb": fake_module}):
                result = self.contract.maxmind_geoip_summary(candidates, paths)

        self.assertEqual((rows, paths), before)
        self.assertTrue(result["available"])
        self.assertEqual(result["network_access"], "none-offline-database-only")
        self.assertEqual(result["public_ip_candidates"], 2)
        self.assertEqual(result["lookups_attempted"], 6)
        self.assertEqual(result["records_found"], 2)
        self.assertEqual(result["records_not_found"], 1)
        self.assertEqual(result["lookup_errors"], 1)
        self.assertEqual(
            [record["ip"] for record in result["records"]],
            ["8.8.8.8", "1.1.1.1"],
        )
        first, second = result["records"]
        self.assertEqual(first["roles"], ["destination", "source"])
        self.assertEqual(first["packet_observations"], 5)
        self.assertEqual(first["database_sources"], ["asn", "country"])
        self.assertEqual(first["autonomous_system_number"], 15169)
        self.assertEqual(first["country_iso_code"], "US")
        self.assertEqual(second["database_sources"], ["city", "country"])
        self.assertEqual(second["city"], "Sydney")
        self.assertEqual(second["country_iso_code"], "AU")
        self.assertEqual(result["databases"]["asn"]["records_not_found"], 1)
        self.assertEqual(result["databases"]["city"]["lookup_errors"], 1)
        self.assertTrue(all(reader.closed for reader in readers.values()))
        for reader in readers.values():
            self.assertEqual(reader.calls[-1], ["close"])

    def test_reader_import_and_open_failures_have_exact_safe_reasons(self) -> None:
        candidates = FakeCandidates([])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "city.mmdb"
            path.write_bytes(b"synthetic")
            with mock.patch.dict(sys.modules, {"maxminddb": None}):
                missing_reader = self.contract.maxmind_geoip_summary(candidates, path)
            self.assertEqual(
                missing_reader["reason"],
                "maxminddb Python reader is not installed in the Onion Sentinel runtime",
            )

            fake_module = types.SimpleNamespace(
                open_database=mock.Mock(side_effect=RuntimeError("unsafe\nopen detail"))
            )
            with mock.patch.dict(sys.modules, {"maxminddb": fake_module}):
                unreadable = self.contract.maxmind_geoip_summary(candidates, path)

        self.assertFalse(unreadable["available"])
        self.assertEqual(unreadable["databases"]["city"]["state"], "unreadable")
        self.assertEqual(
            unreadable["databases"]["city"]["error"], "unsafe open detail"
        )
        self.assertEqual(
            unreadable["reason"], "Configured MaxMind MMDB files could not be opened"
        )

    def test_projection_failure_still_closes_every_open_reader(self) -> None:
        candidates = FakeCandidates([
            {"ip": "8.8.8.8", "role": "destination", "count": 1}
        ])
        reader = FakeReader("GeoLite2-City", {"8.8.8.8": {"city": {}}})
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "city.mmdb"
            path.write_bytes(b"synthetic")
            fake_module = types.SimpleNamespace(open_database=lambda _path: reader)
            with (
                mock.patch.dict(sys.modules, {"maxminddb": fake_module}),
                mock.patch.object(
                    self.contract,
                    "compact_maxmind_record",
                    side_effect=ValueError("synthetic compact failure"),
                ),
                self.assertRaisesRegex(ValueError, "synthetic compact failure"),
            ):
                self.contract.maxmind_geoip_summary(candidates, path)

        self.assertTrue(reader.closed)
        self.assertEqual(reader.calls[-1], ["close"])

    def test_metadata_failure_records_unreadable_and_closes_open_reader(self) -> None:
        candidates = FakeCandidates([])
        reader = FakeReader(
            "GeoLite2-City",
            {},
            metadata_error=RuntimeError("unsafe\nmetadata detail"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "city.mmdb"
            path.write_bytes(b"synthetic")
            fake_module = types.SimpleNamespace(open_database=lambda _path: reader)
            with mock.patch.dict(sys.modules, {"maxminddb": fake_module}):
                result = self.contract.maxmind_geoip_summary(candidates, path)

        self.assertFalse(result["available"])
        self.assertEqual(
            result["reason"], "Configured MaxMind MMDB files could not be opened"
        )
        self.assertEqual(result["databases"]["city"]["state"], "unreadable")
        self.assertEqual(
            result["databases"]["city"]["error"], "unsafe metadata detail"
        )
        self.assertEqual(reader.calls, [["metadata"], ["close"]])
        self.assertTrue(reader.closed)

    def test_metadata_status_sanitization_failure_closes_open_reader(self) -> None:
        candidates = FakeCandidates([])
        reader = FakeReader("GeoLite2-City", {})
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "city.mmdb"
            path.write_bytes(b"synthetic")
            fake_module = types.SimpleNamespace(open_database=lambda _path: reader)

            def sanitize(value, limit):
                if limit == 120:
                    raise ValueError("synthetic status sanitization failure")
                return str(value)

            with (
                mock.patch.dict(sys.modules, {"maxminddb": fake_module}),
                mock.patch.object(
                    self.contract,
                    "sanitize_evidence_text",
                    side_effect=sanitize,
                ),
                self.assertRaisesRegex(
                    ValueError, "synthetic status sanitization failure"
                ),
            ):
                self.contract.maxmind_geoip_summary(candidates, path)

        self.assertEqual(reader.calls, [["metadata"], ["close"]])
        self.assertTrue(reader.closed)

    def test_metadata_failure_close_error_uses_managed_cleanup_policy(self) -> None:
        candidates = FakeCandidates([])
        reader = FakeReader(
            "GeoLite2-City",
            {},
            metadata_error=RuntimeError("synthetic metadata failure"),
            close_error=RuntimeError("synthetic close failure"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "city.mmdb"
            path.write_bytes(b"synthetic")
            fake_module = types.SimpleNamespace(open_database=lambda _path: reader)
            with (
                mock.patch.dict(sys.modules, {"maxminddb": fake_module}),
                self.assertRaisesRegex(RuntimeError, "synthetic close failure") as raised,
            ):
                self.contract.maxmind_geoip_summary(candidates, path)

        self.assertIsNone(raised.exception.__context__)
        self.assertEqual(reader.calls, [["metadata"], ["close"]])
        self.assertFalse(reader.closed)

    def test_mixed_open_and_metadata_failures_preserve_ready_reader(self) -> None:
        candidates = FakeCandidates([
            {"ip": "8.8.8.8", "role": "destination", "count": 2}
        ])
        metadata_failed = FakeReader(
            "GeoLite2-Country",
            {},
            metadata_error=RuntimeError("country metadata failed"),
        )
        ready = FakeReader(
            "GeoLite2-City",
            {"8.8.8.8": {"city": {"names": {"en": "Mountain View"}}}},
        )
        open_calls = []

        def open_database(path):
            database_type = Path(path).stem
            open_calls.append(database_type)
            if database_type == "asn":
                raise RuntimeError("asn open failed")
            return {"country": metadata_failed, "city": ready}[database_type]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {}
            for database_type in ("country", "asn", "city"):
                path = root / f"{database_type}.mmdb"
                path.write_bytes(b"synthetic")
                paths[database_type] = path
            fake_module = types.SimpleNamespace(open_database=open_database)
            with mock.patch.dict(sys.modules, {"maxminddb": fake_module}):
                result = self.contract.maxmind_geoip_summary(candidates, paths)

        self.assertEqual(open_calls, ["country", "asn", "city"])
        self.assertEqual(result["databases"]["asn"]["state"], "unreadable")
        self.assertEqual(result["databases"]["asn"]["error"], "asn open failed")
        self.assertEqual(result["databases"]["country"]["state"], "unreadable")
        self.assertEqual(
            result["databases"]["country"]["error"], "country metadata failed"
        )
        self.assertEqual(result["databases"]["city"]["state"], "ready")
        self.assertEqual(result["lookups_attempted"], 1)
        self.assertEqual(result["records"][0]["database_sources"], ["city"])
        self.assertEqual(metadata_failed.calls, [["metadata"], ["close"]])
        self.assertTrue(metadata_failed.closed)
        self.assertEqual(
            ready.calls, [["metadata"], ["get", "8.8.8.8"], ["close"]]
        )
        self.assertTrue(ready.closed)

    def test_close_failure_propagates_and_stops_later_cleanup(self) -> None:
        candidates = FakeCandidates([])
        first = FakeReader(
            "GeoLite2-City",
            {},
            close_error=RuntimeError("first close failed"),
        )
        second = FakeReader("GeoLite2-Country", {})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {}
            for database_type in ("city", "country"):
                path = root / f"{database_type}.mmdb"
                path.write_bytes(b"synthetic")
                paths[database_type] = path
            readers = {"city": first, "country": second}
            fake_module = types.SimpleNamespace(
                open_database=lambda path: readers[Path(path).stem]
            )
            with (
                mock.patch.dict(sys.modules, {"maxminddb": fake_module}),
                self.assertRaisesRegex(RuntimeError, "first close failed"),
            ):
                self.contract.maxmind_geoip_summary(candidates, paths)

        self.assertEqual(first.calls, [["metadata"], ["close"]])
        self.assertEqual(second.calls, [["metadata"]])
        self.assertFalse(first.closed)
        self.assertFalse(second.closed)

    def test_close_failure_retains_body_failure_as_exception_context(self) -> None:
        candidates = FakeCandidates([
            {"ip": "8.8.8.8", "role": "destination", "count": 1}
        ])
        reader = FakeReader(
            "GeoLite2-City",
            {"8.8.8.8": {"city": {}}},
            close_error=RuntimeError("synthetic close failure"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "city.mmdb"
            path.write_bytes(b"synthetic")
            fake_module = types.SimpleNamespace(open_database=lambda _path: reader)
            with (
                mock.patch.dict(sys.modules, {"maxminddb": fake_module}),
                mock.patch.object(
                    self.contract,
                    "compact_maxmind_record",
                    side_effect=ValueError("synthetic body failure"),
                ),
                self.assertRaisesRegex(RuntimeError, "synthetic close failure") as raised,
            ):
                self.contract.maxmind_geoip_summary(candidates, path)

        self.assertIsInstance(raised.exception.__context__, ValueError)
        self.assertEqual(str(raised.exception.__context__), "synthetic body failure")
        self.assertEqual(
            reader.calls,
            [["metadata"], ["get", "8.8.8.8"], ["close"]],
        )


if __name__ == "__main__":
    unittest.main()
