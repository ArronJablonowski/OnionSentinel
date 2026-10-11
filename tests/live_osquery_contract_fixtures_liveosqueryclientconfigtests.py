from __future__ import annotations

from live_osquery_contract_fixtures import (
    BIN,
    BoundedProcessError,
    LiveOsqueryClientError,
    LiveOsqueryContractError,
    Path,
    RELAY_AUTHORIZED_KEY,
    RELAY_BROKER,
    RELAY_INSTALLER,
    RELAY_LAUNCHER,
    RELAY_SUDOERS,
    ROOT,
    SO_AUTHORIZED_KEY,
    SO_CONFIG_EXAMPLE,
    SO_INSTALLER,
    SO_LAUNCHER,
    SO_WRAPPER,
    SimpleNamespace,
    ThreadPoolExecutor,
    _persist_live_osquery_artifact,
    capability_descriptor,
    collect_live_osquery,
    dt,
    harness_operator_approved,
    importlib,
    io,
    json,
    load_live_osquery_config,
    load_relay_broker,
    load_security_onion_wrapper,
    mock,
    normalize_query,
    normalize_requests,
    os,
    scheduled_inventory_approved,
    stat,
    subprocess,
    sys,
    tempfile,
    time,
    unittest,
    urllib,
    validate_result_artifact,
)

class LiveOsqueryClientConfigTestsFixtures(unittest.TestCase):
    @staticmethod
    def scheduled_config(temp_name: str) -> dict[str, object]:
        return {
            "enabled": True,
            "allowed_target_aliases": ["endpoint-a"],
            "scheduled_inventory_approval": {
                "approved": True,
                "target_aliases": ["endpoint-a"],
            },
            "relay_host": "relay.invalid",
            "relay_user": "broker",
            "identity_file": Path(temp_name) / "identity",
            "known_hosts": Path(temp_name) / "known_hosts",
            "connect_timeout_seconds": 5,
            "timeout_seconds": 30,
            "port": 22,
            "artifact_dir": Path(temp_name) / "artifacts",
        }


