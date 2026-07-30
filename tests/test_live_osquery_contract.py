import importlib.machinery
import importlib.util
import datetime as dt
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
SO_WRAPPER = ROOT / "security-onion" / "bin" / "run-live-osquery"
RELAY_AUTHORIZED_KEY = (
    ROOT / "relay" / "config" / "authorized_keys.live-osquery.example"
)
RELAY_INSTALLER = ROOT / "relay" / "bin" / "install-pi-relay.sh"
RELAY_SUDOERS = ROOT / "relay" / "sudoers" / "so-live-osquery"
RELAY_LAUNCHER = ROOT / "relay" / "bin" / "run-live-osquery-broker"
RELAY_BROKER = ROOT / "relay" / "app" / "live_osquery_broker.py"
sys.path.insert(0, str(BIN))
sys.path.insert(0, str(ROOT / "relay" / "app"))

from live_osquery_contract import (  # noqa: E402
    LiveOsqueryContractError,
    normalize_query,
    normalize_requests,
    validate_result_artifact,
)
from live_osquery_client import (  # noqa: E402
    LiveOsqueryClientError,
    harness_operator_approved,
    load_live_osquery_config,
)


def load_security_onion_wrapper():
    loader = importlib.machinery.SourceFileLoader("run_live_osquery", str(SO_WRAPPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def load_relay_broker():
    loader = importlib.machinery.SourceFileLoader(
        "live_osquery_broker_test",
        str(RELAY_BROKER),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class LiveOsqueryContractTests(unittest.TestCase):
    def test_normalizes_read_only_select_and_adds_bound(self):
        self.assertEqual(
            normalize_query(" SELECT pid, name FROM processes "),
            "SELECT pid, name FROM processes LIMIT 100;",
        )

    def test_rejects_joins_even_between_allowlisted_tables(self):
        with self.assertRaises(LiveOsqueryContractError):
            normalize_query(
                "SELECT p.pid, p.name, s.remote_address "
                "FROM processes p JOIN process_open_sockets s ON p.pid = s.pid LIMIT 25;"
            )

    def test_rejects_mutations_comments_unknown_tables_and_excessive_limits(self):
        rejected = (
            "DELETE FROM processes;",
            "SELECT * FROM processes -- bypass",
            "SELECT * FROM socket_events;",
            "SELECT * FROM processes LIMIT 201;",
            "SELECT * FROM processes UNION SELECT * FROM users;",
            "WITH p AS (SELECT * FROM processes) SELECT * FROM p;",
            "SELECT * FROM processes, users;",
        )
        for query in rejected:
            with self.subTest(query=query):
                with self.assertRaises(LiveOsqueryContractError):
                    normalize_query(query)

    def test_rejects_quoted_tables_functions_and_projection_aliases(self):
        rejected = (
            'SELECT * FROM processes JOIN "shell_history" ON 1=1 LIMIT 1;',
            "SELECT * FROM processes JOIN `ssh_keys` ON 1=1 LIMIT 1;",
            "SELECT * FROM processes JOIN [file] ON 1=1 LIMIT 1;",
            "SELECT randomblob(1000000000) FROM processes LIMIT 1;",
            "SELECT zeroblob(1000000000) FROM processes LIMIT 1;",
            "SELECT printf('%1000000000s', name) FROM processes LIMIT 1;",
            'SELECT "8.8.8.8" AS "source.ip" FROM processes LIMIT 1;',
            "SELECT '8.8.8.8' AS source_ip FROM processes LIMIT 1;",
            "SELECT name AS source_ip FROM processes LIMIT 1;",
            "SELECT * FROM processes LIMIT 200, 1000000;",
            "SELECT * FROM processes LIMIT 1 + 1000000;",
            "SELECT * FROM processes LIMIT 10 OFFSET 1000000;",
        )
        for query in rejected:
            with self.subTest(query=query):
                with self.assertRaises(LiveOsqueryContractError):
                    normalize_query(query)

    def test_allows_single_table_native_columns_and_string_predicates(self):
        self.assertEqual(
            normalize_query(
                "SELECT pid, name, path FROM processes "
                "WHERE name = 'launchd' LIMIT 20"
            ),
            "SELECT pid, name, path FROM processes "
            "WHERE name = 'launchd' LIMIT 20;",
        )

    def test_rejects_wildcard_or_unconfigured_endpoint_targets(self):
        for alias in ("*", "all", "unknown-endpoint"):
            with self.subTest(alias=alias):
                with self.assertRaises(LiveOsqueryContractError):
                    normalize_requests(
                        [
                            {
                                "target_alias": alias,
                                "query": "SELECT * FROM system_info;",
                                "purpose": "inventory",
                            }
                        ],
                        allowed_aliases=["workstation-01"],
                    )

    def test_binds_every_result_to_the_exact_submitted_request(self):
        requests = normalize_requests(
            [
                {
                    "target_alias": "workstation-01",
                    "query": "SELECT pid, name FROM processes LIMIT 10;",
                    "purpose": "correlate running processes",
                }
            ],
            allowed_aliases=["workstation-01"],
        )
        artifact = {
            "schema": "onion-sentinel-live-osquery-v1",
            "case_id": "case-1",
            "generated_at": "2026-07-23T00:00:00Z",
            "read_only": True,
            "complete": True,
            "results": [
                {
                    **requests[0],
                    "status": "ok",
                    "rows": [{"pid": "42", "name": "launchd"}],
                    "total_rows": 1,
                    "truncated": False,
                    "duration_ms": 50,
                    "error": "",
                }
            ],
        }
        normalized = validate_result_artifact(
            json.loads(json.dumps(artifact)),
            expected_requests=requests,
        )
        self.assertTrue(normalized["complete"])
        self.assertEqual(normalized["results"][0]["rows"][0]["pid"], "42")

        substituted = json.loads(json.dumps(artifact))
        substituted["results"][0]["target_alias"] = "workstation-02"
        with self.assertRaises(LiveOsqueryContractError):
            validate_result_artifact(substituted, expected_requests=requests)

        missing = json.loads(json.dumps(artifact))
        missing["results"] = []
        with self.assertRaises(LiveOsqueryContractError):
            validate_result_artifact(missing, expected_requests=requests)


class SecurityOnionLiveOsqueryResponseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wrapper = load_security_onion_wrapper()

    def test_reads_query_level_execution_counters(self):
        state = self.wrapper._query_state(
            {
                "data": {
                    "status": "completed",
                    "queries": [
                        {
                            "status": "completed",
                            "successful": 1,
                            "failed": 0,
                            "pending": 0,
                            "responded": 1,
                        }
                    ],
                }
            }
        )
        self.assertEqual(state, ("completed", 1, 0, 0, 1))

    def test_reads_current_elastic_result_shape(self):
        rows, total = self.wrapper._result_rows(
            {
                "data": {
                    "edges": [
                        {
                            "_source": {
                                "agent": {"id": "must-not-leak"},
                                "action_id": "must-not-leak",
                                "osquery": {"pid": "42", "name": "launchd"},
                            }
                        }
                    ],
                    "total": 1,
                }
            }
        )
        self.assertEqual(rows, [{"pid": "42", "name": "launchd"}])
        self.assertEqual(total, 1)

    def test_accepts_legacy_nested_columns_shape(self):
        rows, total = self.wrapper._result_rows(
            {
                "data": {
                    "edges": [
                        {"_source": {"osquery": {"columns": {"uid": "501"}}}}
                    ],
                    "total": {"value": 1},
                }
            }
        )
        self.assertEqual(rows, [{"uid": "501"}])
        self.assertEqual(total, 1)

    def test_allows_only_explicit_loopback_http_or_verified_https(self):
        base = {
            "enabled": True,
            "kibana_url": "http://127.0.0.1:5601",
            "allow_loopback_http": True,
            "verify_tls": False,
            "target_aliases": {"endpoint-a": "agent-id"},
        }
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "config.json"
            path.write_text(json.dumps(base), encoding="utf-8")
            with mock.patch.object(
                self.wrapper,
                "_require_secure_regular_file",
            ):
                loaded = self.wrapper._load_config(path)
                self.assertEqual(loaded["kibana_url"], "http://127.0.0.1:5601")

                external = dict(base, kibana_url="http://192.168.1.7:5601")
                path.write_text(json.dumps(external), encoding="utf-8")
                with self.assertRaisesRegex(
                    self.wrapper.LiveQueryError,
                    "loopback-only",
                ):
                    self.wrapper._load_config(path)

                unverified = dict(
                    base,
                    kibana_url="https://127.0.0.1:5601",
                    verify_tls=False,
                )
                path.write_text(json.dumps(unverified), encoding="utf-8")
                with self.assertRaisesRegex(
                    self.wrapper.LiveQueryError,
                    "TLS verification",
                ):
                    self.wrapper._load_config(path)

    def test_expired_global_deadline_never_dispatches_http(self):
        with mock.patch.object(
            self.wrapper,
            "_http_json",
            side_effect=AssertionError("HTTP should not run after deadline"),
        ):
            result = self.wrapper._run_query(
                target_alias="endpoint-a",
                agent_id="agent-id",
                query="SELECT hostname FROM system_info LIMIT 1;",
                purpose="deadline test",
                config={
                    "kibana_url": "http://127.0.0.1:5601",
                    "query_timeout_seconds": 60,
                    "poll_seconds": 0.5,
                },
                authorization="ApiKey redacted",
                context=None,
                deadline=0.0,
            )
        self.assertEqual(result["status"], "timeout")
        self.assertIn("global batch deadline", result["error"])


class LiveOsqueryClientConfigTests(unittest.TestCase):
    def test_time_bounded_operator_approval_is_alias_scoped(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            identity = root / "identity"
            known_hosts = root / "known_hosts"
            identity.write_text("private-key-placeholder", encoding="utf-8")
            known_hosts.write_text("host-key-placeholder", encoding="utf-8")
            config_path = root / "live-osquery.json"
            config_path.write_text(
                json.dumps(
                    {
                        "enabled": True,
                        "relay_host": "10.88.8.8",
                        "relay_user": "aj",
                        "identity_file": str(identity),
                        "known_hosts": str(known_hosts),
                        "allowed_target_aliases": ["endpoint-a"],
                        "allowed_agent_roles": ["incident-responder"],
                        "harness_operator_approval": {
                            "approved": True,
                            "expires_at": "2099-01-01T00:00:00Z",
                            "target_aliases": ["endpoint-a"],
                        },
                    }
                ),
                encoding="utf-8",
            )
            config_path.chmod(0o600)
            config = load_live_osquery_config(config_path)

        self.assertTrue(
            harness_operator_approved(
                config,
                "endpoint-a",
                now=dt.datetime(2098, 1, 1, tzinfo=dt.timezone.utc),
            )
        )
        self.assertFalse(
            harness_operator_approved(
                config,
                "endpoint-b",
                now=dt.datetime(2098, 1, 1, tzinfo=dt.timezone.utc),
            )
        )
        self.assertFalse(
            harness_operator_approved(
                config,
                "endpoint-a",
                now=dt.datetime(2100, 1, 1, tzinfo=dt.timezone.utc),
            )
        )

    def test_config_rejects_insecure_mode_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            source = root / "source.json"
            source.write_text("{}", encoding="utf-8")
            source.chmod(0o644)
            with self.assertRaisesRegex(
                LiveOsqueryClientError,
                "mode 0600",
            ):
                load_live_osquery_config(source)
            source.chmod(0o600)
            link = root / "link.json"
            link.symlink_to(source)
            with self.assertRaisesRegex(
                LiveOsqueryClientError,
                "regular file",
            ):
                load_live_osquery_config(link)


class LiveOsqueryDeploymentContractTests(unittest.TestCase):
    def test_mac_forced_key_runs_only_broker_as_service_account(self):
        authorized_key = RELAY_AUTHORIZED_KEY.read_text(encoding="utf-8")
        self.assertIn(
            'command="/opt/so-alert-relay/bin/run-live-osquery-broker"',
            authorized_key,
        )
        for restriction in (
            "no-agent-forwarding",
            "no-X11-forwarding",
            "no-port-forwarding",
            "no-pty",
            "no-user-rc",
        ):
            self.assertIn(restriction, authorized_key)

    def test_pre_sudo_launcher_rejects_supplied_ssh_command(self):
        completed = subprocess.run(
            [str(RELAY_LAUNCHER)],
            env={**os.environ, "SSH_ORIGINAL_COMMAND": "id"},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("commands are not accepted", completed.stderr)

    def test_relay_config_requires_root_service_group_mode_0640(self):
        broker = load_relay_broker()
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "live-osquery.json"
            path.write_text('{"enabled":true}', encoding="utf-8")
            secure = SimpleNamespace(
                st_uid=0,
                st_gid=4242,
                st_mode=stat.S_IFREG | 0o640,
                st_size=path.stat().st_size,
            )
            with (
                mock.patch.object(Path, "lstat", return_value=secure),
                mock.patch.object(broker.os, "getegid", return_value=4242),
            ):
                self.assertTrue(broker._load_config(path)["enabled"])

            wrong_mode = SimpleNamespace(
                **{**secure.__dict__, "st_mode": stat.S_IFREG | 0o600}
            )
            with (
                mock.patch.object(Path, "lstat", return_value=wrong_mode),
                mock.patch.object(broker.os, "getegid", return_value=4242),
                self.assertRaisesRegex(broker.BrokerError, "mode 0640"),
            ):
                broker._load_config(path)

    def test_installer_validates_dedicated_live_osquery_sudoers_rule(self):
        installer = RELAY_INSTALLER.read_text(encoding="utf-8")
        self.assertIn(
            'RELAY_ADMIN_USER="${ONION_SENTINEL_RELAY_ADMIN_USER:-${SUDO_USER:-}}"',
            installer,
        )
        self.assertIn(
            'sed "s/__RELAY_ADMIN_USER__/${RELAY_ADMIN_USER}/g"',
            installer,
        )
        self.assertIn(
            'install -o root -g root -m 0440 "$LIVE_OSQUERY_SUDOERS_TMP" '
            "/etc/sudoers.d/92-so-alert-relay-live-osquery",
            installer,
        )
        self.assertIn(
            "visudo -cf /etc/sudoers.d/92-so-alert-relay-live-osquery",
            installer,
        )

        sudoers = RELAY_SUDOERS.read_text(encoding="utf-8")
        self.assertIn("__RELAY_ADMIN_USER__ ALL=(soalert) NOPASSWD:", sudoers)
        self.assertNotIn("aj ALL=", sudoers)
        self.assertIn(
            "/usr/bin/python3 /opt/so-alert-relay/app/live_osquery_broker.py",
            sudoers,
        )
        self.assertIn(
            'install -o root -g root -m 0755 '
            '"$REPO_DIR/relay/bin/run-live-osquery-broker" '
            "/opt/so-alert-relay/bin/run-live-osquery-broker",
            installer,
        )


if __name__ == "__main__":
    unittest.main()
