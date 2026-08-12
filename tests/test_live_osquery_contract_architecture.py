"""Characterize the shared live-OSQuery contract before decomposition."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import inspect
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
CONTRACT = BIN / "live_osquery_contract.py"
CONTRACT_FILES = (
    "live_osquery_contract_schema.py",
    "live_osquery_contract_query.py",
    "live_osquery_contract_request.py",
    "live_osquery_contract_result.py",
    "live_osquery_contract.py",
)
MAC_INSTALLER = BIN / "install-macstudio-stack.zsh"
RELAY_INSTALLER = ROOT / "relay" / "bin" / "install-pi-relay.sh"
SECURITY_ONION_INSTALLER = (
    ROOT / "security-onion" / "bin" / "install-security-onion-wrapper.sh"
)


def load_contract(name: str = "live_osquery_contract_characterization"):
    spec = importlib.util.spec_from_file_location(name, CONTRACT)
    if spec is None or spec.loader is None:
        raise AssertionError("live OSQuery contract cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    with _temporary_sys_path(BIN):
        spec.loader.exec_module(module)
    return module


class _temporary_sys_path:
    def __init__(self, path: Path):
        self.path = str(path)

    def __enter__(self):
        sys.path.insert(0, self.path)

    def __exit__(self, exc_type, exc, traceback):
        sys.path.remove(self.path)


class LiveOsqueryContractCharacterizationTests(unittest.TestCase):
    def test_legacy_module_namespace_and_signatures_are_frozen(self):
        contract = load_contract()
        self.assertEqual(
            sorted(name for name in vars(contract) if not name.startswith("__")),
            [
                "ALLOWED_TABLES",
                "ALLOWED_TABLE_COLUMNS",
                "Any",
                "DEFAULT_ROWS",
                "Iterable",
                "LiveOsqueryContractError",
                "MAX_PURPOSE_CHARS",
                "MAX_QUERY_CHARS",
                "MAX_REPORTED_ROWS",
                "MAX_REQUESTS",
                "MAX_RESPONSE_BYTES",
                "MAX_RESULT_DURATION_MS",
                "MAX_ROWS",
                "MAX_TARGET_ALIASES",
                "SCHEMA",
                "TARGET_OSQUERY_VERSION",
                "TARGET_PLATFORM",
                "_ALIAS",
                "_FORBIDDEN_QUERY_SHAPES",
                "_FORBIDDEN_SQL",
                "_FORBIDDEN_TARGETS",
                "_FROM_CLAUSE",
                "_FUNCTION_CALL",
                "_RESULT_STATUSES",
                "_SAFE_PROJECTION_ITEM",
                "_SELECT_PROJECTION",
                "_SQL_IDENTIFIER",
                "_SQL_KEYWORDS",
                "_SQL_STRING_LITERAL",
                "_TABLE_REFERENCE",
                "_TERMINAL_LIMIT",
                "_bounded_text",
                "annotations",
                "bounded_json_bytes",
                "hashlib",
                "json",
                "normalize_query",
                "normalize_request",
                "normalize_requests",
                "normalize_target_aliases",
                "projected_columns",
                "query_row_limit",
                "re",
                "validate_result_artifact",
                "validate_transport_payload",
            ],
        )
        expected = {
            "_bounded_text": "(value: 'Any', *, label: 'str', maximum: 'int', required: 'bool' = True) -> 'str'",
            "bounded_json_bytes": "(value: 'Any', maximum: 'int' = 4194304) -> 'bytes'",
            "normalize_query": "(value: 'Any') -> 'str'",
            "normalize_request": "(value: 'Any', *, allowed_aliases: 'Iterable[Any]') -> 'dict[str, Any]'",
            "normalize_requests": "(values: 'Any', *, allowed_aliases: 'Iterable[Any]') -> 'list[dict[str, Any]]'",
            "normalize_target_aliases": "(values: 'Iterable[Any]') -> 'list[str]'",
            "projected_columns": "(value: 'Any') -> 'tuple[str, ...]'",
            "query_row_limit": "(value: 'Any') -> 'int'",
            "validate_result_artifact": "(value: 'Any', *, expected_requests: 'Iterable[Any] | None' = None) -> 'dict[str, Any]'",
            "validate_transport_payload": "(value: 'Any', *, allowed_aliases: 'Iterable[Any]') -> 'dict[str, Any]'",
        }
        self.assertEqual(
            {name: str(inspect.signature(getattr(contract, name))) for name in expected},
            expected,
        )

    def test_schema_limits_and_table_policy_are_frozen(self):
        contract = load_contract("live_osquery_contract_policy_characterization")
        self.assertEqual(
            {
                "schema": contract.SCHEMA,
                "max_requests": contract.MAX_REQUESTS,
                "max_query_chars": contract.MAX_QUERY_CHARS,
                "max_purpose_chars": contract.MAX_PURPOSE_CHARS,
                "max_rows": contract.MAX_ROWS,
                "default_rows": contract.DEFAULT_ROWS,
                "max_response_bytes": contract.MAX_RESPONSE_BYTES,
                "max_target_aliases": contract.MAX_TARGET_ALIASES,
                "max_result_duration_ms": contract.MAX_RESULT_DURATION_MS,
                "max_reported_rows": contract.MAX_REPORTED_ROWS,
                "target_platform": contract.TARGET_PLATFORM,
                "target_osquery_version": contract.TARGET_OSQUERY_VERSION,
            },
            {
                "schema": "onion-sentinel-live-osquery-v1",
                "max_requests": 8,
                "max_query_chars": 4096,
                "max_purpose_chars": 500,
                "max_rows": 200,
                "default_rows": 100,
                "max_response_bytes": 4 * 1024 * 1024,
                "max_target_aliases": 64,
                "max_result_duration_ms": 10 * 60 * 1000,
                "max_reported_rows": 1_000_000,
                "target_platform": "darwin",
                "target_osquery_version": "5.15.0",
            },
        )
        policy = {
            table: sorted(columns)
            for table, columns in sorted(contract.ALLOWED_TABLE_COLUMNS.items())
        }
        digest = hashlib.sha256(
            json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(
            digest,
            "c09b1947ef25c17d5db743f0d1a16247eca4abb460ae5de563d89c80a8dd8c46",
        )
        self.assertEqual(contract.ALLOWED_TABLES, frozenset(policy))

    def test_success_outputs_and_failure_order_are_frozen(self):
        contract = load_contract("live_osquery_contract_behavior_characterization")
        aliases = contract.normalize_target_aliases(
            [" Mac-01 ", "mac-01", "srv.example", ""]
        )
        request = contract.normalize_request(
            {
                "target_alias": "MAC-01",
                "query": " SELECT pid, name FROM processes WHERE name = 'launchd' ",
                "purpose": " Confirm the observed process ",
            },
            allowed_aliases=aliases,
        )
        self.assertEqual(aliases, ["mac-01", "srv.example"])
        self.assertEqual(
            request,
            {
                "target_alias": "mac-01",
                "query": "SELECT pid, name FROM processes WHERE name = 'launchd' LIMIT 100;",
                "purpose": "Confirm the observed process",
                "query_digest": "3cfd6d94ba0979c0e8565019ae1066a9887d357495deeb52be40d3f844ccccfb",
            },
        )
        artifact = contract.validate_result_artifact(
            {
                "schema": contract.SCHEMA,
                "case_id": "case-178",
                "generated_at": "2026-08-12T08:00:00Z",
                "read_only": True,
                "complete": True,
                "results": [
                    {
                        **request,
                        "status": "ok",
                        "rows": [{"pid": 1, "name": "launchd"}],
                        "total_rows": 1,
                        "truncated": False,
                        "duration_ms": 27,
                        "error": "",
                    }
                ],
            },
            expected_requests=[request],
        )
        self.assertEqual(
            contract.bounded_json_bytes(artifact),
            json.dumps(artifact, separators=(",", ":"), ensure_ascii=True).encode(),
        )
        failures = (
            (lambda: contract.normalize_query("DELETE FROM processes"), "only SELECT queries are allowed"),
            (lambda: contract.normalize_query("SELECT pid FROM processes UNION SELECT uid FROM users"), "compound queries, CTEs, subqueries, and derived tables are forbidden"),
            (lambda: contract.normalize_query("SELECT random() FROM processes"), "SQL function calls are forbidden"),
            (lambda: contract.normalize_target_aliases(["*"]), "wildcard or all-endpoint targets are forbidden"),
            (lambda: contract.validate_result_artifact({"schema": "wrong"}), f"result schema must be {contract.SCHEMA}"),
        )
        for invoke, message in failures:
            with self.subTest(message=message):
                with self.assertRaisesRegex(
                    contract.LiveOsqueryContractError,
                    f"^{__import__('re').escape(message)}$",
                ):
                    invoke()


class LiveOsqueryContractArchitectureTests(unittest.TestCase):
    def test_facade_and_owner_modules_obey_size_and_dependency_boundaries(self):
        expected_imports = {
            "live_osquery_contract_schema.py": set(),
            "live_osquery_contract_query.py": {"live_osquery_contract_schema"},
            "live_osquery_contract_request.py": {
                "live_osquery_contract_query",
                "live_osquery_contract_schema",
            },
            "live_osquery_contract_result.py": {
                "live_osquery_contract_query",
                "live_osquery_contract_schema",
            },
            "live_osquery_contract.py": {
                "live_osquery_contract_query",
                "live_osquery_contract_request",
                "live_osquery_contract_result",
                "live_osquery_contract_schema",
            },
        }
        for name in CONTRACT_FILES:
            with self.subTest(name=name):
                source = (BIN / name).read_text(encoding="utf-8")
                limit = 250 if name == "live_osquery_contract.py" else 800
                self.assertLessEqual(len(source.splitlines()), limit)
                tree = ast.parse(source)
                local_imports = {
                    node.module
                    for node in ast.walk(tree)
                    if isinstance(node, ast.ImportFrom)
                    and node.module
                    and node.module.startswith("live_osquery_contract")
                }
                self.assertEqual(local_imports, expected_imports[name])

    def test_contract_imports_from_an_isolated_flat_dependency_unit(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            for name in CONTRACT_FILES:
                (target / name).write_bytes((BIN / name).read_bytes())
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    (
                        "import sys; sys.path.insert(0, sys.argv[1]); "
                        "import live_osquery_contract as c; "
                        "assert c.normalize_query('SELECT pid FROM processes') == "
                        "'SELECT pid FROM processes LIMIT 100;'"
                    ),
                    directory,
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_all_three_installers_copy_the_complete_contract_unit(self):
        installers = {
            "mac": MAC_INSTALLER.read_text(encoding="utf-8"),
            "relay": RELAY_INSTALLER.read_text(encoding="utf-8"),
            "security_onion": SECURITY_ONION_INSTALLER.read_text(encoding="utf-8"),
        }
        for boundary, installer in installers.items():
            for name in CONTRACT_FILES:
                with self.subTest(boundary=boundary, name=name):
                    self.assertIn(f"n8n/bin/{name}", installer)
        self.assertIn('$STACK_DIR/bin/live_osquery_contract.py', installers["mac"])
        self.assertIn(
            "/opt/so-alert-relay/app/live_osquery_contract.py",
            installers["relay"],
        )
        self.assertIn(
            "/usr/local/lib/onion-sentinel/live_osquery_contract.py",
            installers["security_onion"],
        )


if __name__ == "__main__":
    unittest.main()
