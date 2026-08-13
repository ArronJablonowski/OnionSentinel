from __future__ import annotations

import ast
import copy
import datetime as dt
import importlib.machinery
import importlib.util
import inspect
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
PROMOTER_PATH = BIN / "promote-dhcp-asset.py"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))


def load_module():
    name = "dhcp_asset_promotion_projection_target"
    loader = importlib.machinery.SourceFileLoader(name, str(PROMOTER_PATH))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


PROMOTER = load_module()


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(PROMOTER_PATH.read_text(encoding="utf-8"))
    target = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    complexity = 1
    for node in ast.walk(target):
        if node is target:
            continue
        if isinstance(node, (ast.If, ast.For, ast.While, ast.IfExp, ast.Assert)):
            complexity += 1
        elif isinstance(node, ast.Try):
            complexity += len(node.handlers)
        elif isinstance(node, ast.BoolOp):
            complexity += max(0, len(node.values) - 1)
        elif isinstance(node, ast.comprehension):
            complexity += 1 + len(node.ifs)
    return target.end_lineno - target.lineno + 1, complexity


class TracedEnvironmentPath:
    def __init__(self, calls, text):
        self.calls = calls
        self.text = text
        self.info = SimpleNamespace(st_mode=0o100600, st_uid=9001, st_size=1)

    def lstat(self):
        self.calls.append("lstat")
        return self.info

    def read_text(self, *, encoding):
        self.calls.append(("read_text", encoding))
        return self.text


class DhcpAssetPromotionProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = dt.datetime(2026, 8, 12, 18, tzinfo=dt.timezone.utc)

    def valid_args(self, **overrides):
        values = {
            "discovery_id": "a" * 20,
            "expected_ip": "192.0.2.25",
            "expected_mac": "00:11:22:33:44:55",
            "expected_hostname": "reviewed-client",
            "asset_id": "reviewed-client",
            "hostname": "",
            "role": "Reviewed LAN client",
            "platform": "",
            "owner_ref": "operator-reviewed",
            "criticality": "unknown",
            "accept_locally_administered_mac": False,
            "confirm": "PROMOTE:" + "a" * 20,
            "env": Path("/synthetic/.env"),
            "export": Path("/synthetic/export.json"),
            "api_url": "http://asset-store.test/root/",
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def reviewed_item(self, **overrides):
        item = {
            "discovery_id": "a" * 20,
            "current_ip": "192.0.2.25",
            "mac_address": "00:11:22:33:44:55",
            "hostname": "reviewed-client",
            "last_seen": "2026-08-12T17:55:00Z",
            "lease_expires_at": "2026-08-12T19:00:00Z",
            "observation_count": 12,
        }
        item.update(overrides)
        return item

    def state(self, observations=None):
        return {
            "schema": "onion-sentinel-dhcp-asset-observations-v1",
            "observations": [self.reviewed_item()] if observations is None else observations,
        }

    def test_public_signatures_are_stable(self) -> None:
        expected = {
            "env_token": "(path: 'Path') -> 'str'",
            "reviewed_observation": "(state: 'dict', *, discovery_id: 'str', expected_ip: 'str', expected_mac: 'str', expected_hostname: 'str', now: 'dt.datetime') -> 'dict'",
            "promote": "(args: 'argparse.Namespace', now: 'dt.datetime') -> 'tuple[dict, Path]'",
        }
        self.assertEqual(
            {
                name: str(inspect.signature(getattr(PROMOTER, name)))
                for name in expected
            },
            expected,
        )

    def test_decomposed_promotion_phases_stay_within_budget(self) -> None:
        for name in (
            "_validate_environment",
            "_environment_values",
            "_asset_store_write_token",
            "env_token",
            "_matched_observation",
            "_observation_identity",
            "_validate_observation_identity",
            "_validate_observation_freshness",
            "reviewed_observation",
            "_normalized_discovery",
            "_normalized_expected_mac",
            "_promotion_identity",
            "_open_legacy_lock",
            "_validate_authoritative_overlap",
            "_reviewed_legacy_inventory",
            "_promoted_asset",
            "_updated_inventory",
            "_backup_inventory",
            "_legacy_result",
            "_legacy_promotion",
            "_database_payload",
            "_database_result",
            "_database_promotion",
            "promote",
        ):
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)

    def test_env_token_preserves_metadata_short_circuit_and_parse_order(self) -> None:
        calls = []
        path = TracedEnvironmentPath(
            calls,
            "# ignored\nmissing-delimiter\n"
            " N8N_POST_COMMIT_TOKEN = " + "f" * 32 + " \n"
            "ASSET_STORE_WRITE_TOKEN=" + "a" * 32 + "\n"
            "ASSET_STORE_WRITE_TOKEN=" + "b" * 32 + "\n",
        )

        def traced(name, result):
            return lambda value: calls.append((name, value)) or result

        with (
            mock.patch.object(PROMOTER.stat, "S_ISREG", side_effect=traced("S_ISREG", True)),
            mock.patch.object(PROMOTER.stat, "S_ISLNK", side_effect=traced("S_ISLNK", False)),
            mock.patch.object(PROMOTER.stat, "S_IMODE", side_effect=traced("S_IMODE", 0o600)),
            mock.patch.object(PROMOTER.os, "geteuid", side_effect=lambda: calls.append("geteuid") or 9001),
        ):
            self.assertEqual(PROMOTER.env_token(path), "b" * 32)

        self.assertEqual(
            calls,
            [
                "lstat",
                ("S_ISREG", 0o100600),
                ("S_ISLNK", 0o100600),
                "geteuid",
                ("S_IMODE", 0o100600),
                ("read_text", "utf-8"),
            ],
        )

        calls = []
        path = TracedEnvironmentPath(calls, "N8N_POST_COMMIT_TOKEN=" + "z" * 32)
        with mock.patch.object(
            PROMOTER.stat,
            "S_ISREG",
            side_effect=lambda value: calls.append(("S_ISREG", value)) or False,
        ), self.assertRaisesRegex(ValueError, "owner-controlled"):
            PROMOTER.env_token(path)
        self.assertEqual(calls, ["lstat", ("S_ISREG", 0o100600)])

    def test_env_token_preserves_fallback_and_length_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("N8N_POST_COMMIT_TOKEN=" + "z" * 32 + "\n", encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(PROMOTER.env_token(path), "z" * 32)
            path.write_text("ASSET_STORE_WRITE_TOKEN=short\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing or too short"):
                PROMOTER.env_token(path)

    def test_reviewed_observation_preserves_identity_normalization_and_return(self) -> None:
        item = self.reviewed_item(
            current_ip="2001:0db8:0:0:0:0:0:25",
            mac_address=" 00:11:22:33:44:55 ",
            hostname=" Reviewed-Client.EXAMPLE. ",
        )
        state = self.state([None, item, "ignored"])
        before = copy.deepcopy(state)
        result = PROMOTER.reviewed_observation(
            state,
            discovery_id="a" * 20,
            expected_ip="2001:db8::25",
            expected_mac="00:11:22:33:44:55",
            expected_hostname="reviewed-client.example",
            now=self.now,
        )
        self.assertIs(result, item)
        self.assertEqual(state, before)

    def test_reviewed_observation_schema_match_and_identity_errors_are_exact(self) -> None:
        cases = [
            ({}, "failed schema validation"),
            ({"schema": "onion-sentinel-dhcp-asset-observations-v1", "observations": {}}, "failed schema validation"),
            ({"schema": "onion-sentinel-dhcp-asset-observations-v1", "observations": [None] * 5001}, "failed schema validation"),
            (self.state([]), "missing or ambiguous"),
            (self.state([self.reviewed_item(), self.reviewed_item()]), "missing or ambiguous"),
        ]
        for state, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                PROMOTER.reviewed_observation(
                    state,
                    discovery_id="a" * 20,
                    expected_ip="192.0.2.25",
                    expected_mac="00:11:22:33:44:55",
                    expected_hostname="reviewed-client",
                    now=self.now,
                )

        for field, value in (
            ("current_ip", "192.0.2.26"),
            ("mac_address", "00:11:22:33:44:56"),
            ("hostname", "changed-client"),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(
                ValueError, "changed after operator review"
            ):
                PROMOTER.reviewed_observation(
                    self.state([self.reviewed_item(**{field: value})]),
                    discovery_id="a" * 20,
                    expected_ip="192.0.2.25",
                    expected_mac="00:11:22:33:44:55",
                    expected_hostname="reviewed-client",
                    now=self.now,
                )

    def test_reviewed_observation_preserves_lease_freshness_boundary(self) -> None:
        old = "2026-08-11T17:59:59Z"
        future_lease = self.reviewed_item(last_seen=old, lease_expires_at="2026-08-12T18:00:01Z")
        self.assertIs(
            PROMOTER.reviewed_observation(
                self.state([future_lease]),
                discovery_id="a" * 20,
                expected_ip="192.0.2.25",
                expected_mac="00:11:22:33:44:55",
                expected_hostname="reviewed-client",
                now=self.now,
            ),
            future_lease,
        )
        expired = self.reviewed_item(last_seen=old, lease_expires_at="2026-08-12T17:59:59Z")
        with self.assertRaisesRegex(ValueError, "stale DHCP identity"):
            PROMOTER.reviewed_observation(
                self.state([expired]),
                discovery_id="a" * 20,
                expected_ip="192.0.2.25",
                expected_mac="00:11:22:33:44:55",
                expected_hostname="reviewed-client",
                now=self.now,
            )
        at_boundary = self.reviewed_item(last_seen="2026-08-11T18:00:00Z", lease_expires_at="")
        self.assertIs(
            PROMOTER.reviewed_observation(
                self.state([at_boundary]),
                discovery_id="a" * 20,
                expected_ip="192.0.2.25",
                expected_mac="00:11:22:33:44:55",
                expected_hostname="reviewed-client",
                now=self.now,
            ),
            at_boundary,
        )

    def test_promote_preserves_input_validation_precedence_before_io(self) -> None:
        cases = [
            ({"discovery_id": "bad", "confirm": "bad"}, "invalid DHCP discovery id"),
            ({"confirm": "bad"}, "explicit PROMOTE"),
            ({"expected_ip": "not-an-ip"}, "not-an-ip"),
            ({"expected_mac": "not-a-mac"}, "expected MAC address is invalid"),
            ({"expected_mac": "01:11:22:33:44:55"}, "multicast MAC"),
            ({"expected_mac": "02:11:22:33:44:55"}, "locally administered MAC"),
        ]
        for overrides, message in cases:
            with self.subTest(message=message), mock.patch.object(
                PROMOTER, "env_token", side_effect=AssertionError("I/O must not run")
            ), self.assertRaisesRegex(ValueError, message):
                PROMOTER.promote(self.valid_args(**overrides), self.now)

    def test_database_promotion_preserves_calls_payload_and_result_projection(self) -> None:
        args = self.valid_args(
            discovery_id=" A" + "A" * 19 + " ",
            confirm="PROMOTE:" + "a" * 20,
            expected_ip=" 192.0.2.025 ",
            expected_mac="00-11-22-33-44-55",
            expected_hostname=" Reviewed-Client. ",
            hostname=" Published-Client. ",
        )
        args.expected_ip = " 192.0.2.25 "
        calls = []
        token = "t" * 32
        snapshot = {"schema": "snapshot", "assets": []}

        def api(url, **kwargs):
            calls.append(("api", url, kwargs))
            if url.endswith("/assets/promote-dhcp"):
                return {"ok": True, "observation_fingerprint": "fingerprint"}
            return {"ok": True, "inventory": snapshot}

        with (
            mock.patch.object(PROMOTER, "env_token", side_effect=lambda path: calls.append(("token", path)) or token),
            mock.patch.object(PROMOTER, "api_json", side_effect=api),
            mock.patch.object(PROMOTER, "validate_asset_inventory", side_effect=lambda value: calls.append(("validate", value))),
            mock.patch.object(PROMOTER, "atomic_write", side_effect=lambda path, value: calls.append(("write", path, value))),
        ):
            result, export = PROMOTER.promote(args, self.now)

        expected_payload = {
            "discovery_id": "a" * 20,
            "expected_ip": "192.0.2.25",
            "expected_mac": "00:11:22:33:44:55",
            "expected_hostname": "reviewed-client",
            "asset_id": "reviewed-client",
            "hostname": "published-client",
            "role": "Reviewed LAN client",
            "platform": "",
            "owner_ref": "operator-reviewed",
            "operator_ref": "operator-reviewed",
            "criticality": "unknown",
            "reason": "operator-approved DHCP promotion",
            "confirm": "PROMOTE:" + "a" * 20,
            "accept_locally_administered_mac": False,
        }
        self.assertEqual(
            calls,
            [
                ("token", args.env),
                ("api", "http://asset-store.test/root/assets/promote-dhcp", {"token": token, "payload": expected_payload}),
                ("api", "http://asset-store.test/root/assets/snapshot", {}),
                ("validate", snapshot),
                ("write", args.export, snapshot),
            ],
        )
        self.assertEqual(
            result,
            {
                "asset_id": "reviewed-client",
                "discovery_id": "a" * 20,
                "ip_address": "192.0.2.25",
                "mac_address": "00:11:22:33:44:55",
                "mac_address_scope": "globally_administered",
                "hostname": "published-client",
                "observation_fingerprint": "fingerprint",
            },
        )
        self.assertIs(export, args.export)

    def test_database_snapshot_failure_never_validates_or_exports(self) -> None:
        calls = []

        def api(url, **kwargs):
            calls.append((url, kwargs))
            return {"ok": True} if url.endswith("/assets/promote-dhcp") else {"ok": True, "inventory": []}

        with (
            mock.patch.object(PROMOTER, "env_token", return_value="t" * 32),
            mock.patch.object(PROMOTER, "api_json", side_effect=api),
            mock.patch.object(PROMOTER, "validate_asset_inventory") as validate,
            mock.patch.object(PROMOTER, "atomic_write") as write,
            self.assertRaisesRegex(ValueError, "snapshot is unavailable"),
        ):
            PROMOTER.promote(self.valid_args(), self.now)
        self.assertEqual(len(calls), 2)
        validate.assert_not_called()
        write.assert_not_called()

    def test_legacy_promotion_preserves_backup_projection_and_atomic_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory_path = root / "asset_inventory.json"
            state_path = root / "dhcp-observations.json"
            inventory = {
                "schema": "onion-sentinel-asset-inventory-v1",
                "version": 1,
                "generated_at": "2026-08-01T00:00:00Z",
                "assets": [],
            }
            inventory_bytes = (json.dumps(inventory, sort_keys=True) + "\n").encode()
            inventory_path.write_bytes(inventory_bytes)
            state_path.write_text(json.dumps(self.state()), encoding="utf-8")
            inventory_path.chmod(0o600)
            state_path.chmod(0o600)
            state_before = state_path.read_bytes()
            args = self.valid_args(inventory=inventory_path, state=state_path)
            del args.env
            del args.export
            del args.api_url

            result, backup = PROMOTER.promote(args, self.now)

            updated = json.loads(inventory_path.read_text(encoding="utf-8"))
            asset = updated["assets"][0]
            self.assertEqual(backup.read_bytes(), inventory_bytes)
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
            self.assertEqual(state_path.read_bytes(), state_before)
            self.assertEqual(
                backup.name,
                "asset_inventory.json.pre-dhcp-promotion-20260812T180000Z",
            )
            self.assertEqual(updated["generated_at"], "2026-08-12T18:00:00.000Z")
            self.assertEqual(
                asset,
                {
                    "asset_id": "reviewed-client",
                    "valid_from": "2026-08-12T18:00:00.000Z",
                    "valid_until": None,
                    "identifiers": {
                        "ip_addresses": ["192.0.2.25"],
                        "mac_addresses": ["00:11:22:33:44:55"],
                        "hostnames": ["reviewed-client"],
                    },
                    "role": "Reviewed LAN client",
                    "platform": "",
                    "owner_ref": "operator-reviewed",
                    "criticality": "unknown",
                    "expected_services": [],
                    "expected_behaviors": [],
                    "source_type": "operator-approved-dhcp",
                    "source_ref": "DHCP discovery " + "a" * 20 + "; approved 2026-08-12T18:00:00.000Z",
                    "confidence": "medium",
                    "share_with_hosted_models": False,
                },
            )
            self.assertEqual(
                result,
                {
                    "asset_id": "reviewed-client",
                    "discovery_id": "a" * 20,
                    "ip_address": "192.0.2.25",
                    "mac_address": "00:11:22:33:44:55",
                    "mac_address_scope": "globally_administered",
                    "hostname": "reviewed-client",
                    "observation_count": 12,
                },
            )

    def test_legacy_overlap_checks_ip_mac_and_nonempty_reviewed_hostname(self) -> None:
        identifiers = {
            "ip": ["192.0.2.25"],
            "mac": ["00:11:22:33:44:55"],
            "hostname": ["reviewed-client"],
        }
        for field in ("ip", "mac", "hostname"):
            selected = {name: values if name == field else [] for name, values in identifiers.items()}
            validated = {"assets": [{"asset_id": "existing", "identifiers": selected}]}
            args = self.valid_args(inventory=Path("inventory.json"), state=Path("state.json"))
            del args.env
            del args.export
            del args.api_url
            fake_lock = mock.MagicMock()
            fake_lock.__enter__.return_value.fileno.return_value = 17
            with (
                self.subTest(field=field),
                mock.patch.object(PROMOTER.os, "open", return_value=9),
                mock.patch.object(PROMOTER.os, "fchmod"),
                mock.patch.object(PROMOTER.os, "fdopen", return_value=fake_lock),
                mock.patch.object(PROMOTER.fcntl, "flock"),
                mock.patch.object(PROMOTER, "controlled_json", side_effect=[{"assets": []}, self.state()]),
                mock.patch.object(PROMOTER, "reviewed_observation", return_value=self.reviewed_item()),
                mock.patch.object(PROMOTER, "validate_asset_inventory", return_value=validated),
                self.assertRaisesRegex(ValueError, "overlaps authoritative asset existing"),
            ):
                PROMOTER.promote(args, self.now)


if __name__ == "__main__":
    unittest.main()
