import importlib.machinery
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
SO_WRAPPER = ROOT / "security-onion" / "bin" / "run-live-osquery"
RELAY_AUTHORIZED_KEY = (
    ROOT / "relay" / "config" / "authorized_keys.live-osquery.example"
)
RELAY_INSTALLER = ROOT / "relay" / "bin" / "install-pi-relay.sh"
RELAY_SUDOERS = ROOT / "relay" / "sudoers" / "so-live-osquery"
sys.path.insert(0, str(BIN))

from live_osquery_contract import (  # noqa: E402
    LiveOsqueryContractError,
    normalize_query,
    normalize_requests,
    validate_result_artifact,
)


def load_security_onion_wrapper():
    loader = importlib.machinery.SourceFileLoader("run_live_osquery", str(SO_WRAPPER))
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

    def test_allows_bounded_join_between_allowlisted_tables(self):
        query = normalize_query(
            "SELECT p.pid, p.name, s.remote_address "
            "FROM processes p JOIN process_open_sockets s ON p.pid = s.pid LIMIT 25;"
        )
        self.assertTrue(query.endswith("LIMIT 25;"))

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


class LiveOsqueryDeploymentContractTests(unittest.TestCase):
    def test_mac_forced_key_runs_only_broker_as_service_account(self):
        authorized_key = RELAY_AUTHORIZED_KEY.read_text(encoding="utf-8")
        self.assertIn(
            'command="sudo -n -u soalert /usr/bin/python3 '
            '/opt/so-alert-relay/app/live_osquery_broker.py"',
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


if __name__ == "__main__":
    unittest.main()
