#!/usr/bin/env python3
"""Characterization for complete, read-only Relay node readiness."""
from __future__ import annotations

import importlib.util
import importlib
import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "relay" / "app" / "relay_readiness.py"
INSTALLER = ROOT / "relay" / "bin" / "install-pi-relay.sh"
HEALTH_CONTRACT = ROOT / "relay" / "app" / "relay_health_contract.py"
RELAY_README = ROOT / "relay" / "README.md"
RELIABILITY_RUNBOOK = ROOT / "docs" / "reliability-and-slo-runbook.md"
RECOVERY_RUNBOOK = ROOT / "docs" / "disaster-recovery-runbook.md"


def load_module():
    if not SCRIPT.is_file():
        return None
    spec = importlib.util.spec_from_file_location("relay_readiness", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RelayReadinessTests(unittest.TestCase):
    def require_module(self):
        module = load_module()
        self.assertIsNotNone(module, "Relay read-only readiness module is missing")
        return module

    def test_probe_covers_every_arr_33_health_domain(self) -> None:
        module = self.require_module()
        self.assertEqual(
            module.CHECK_IDS,
            (
                "power",
                "thermal",
                "filesystem",
                "storage",
                "services",
                "routes",
                "ssh",
                "brokers",
            ),
        )

    def test_power_thermal_and_kernel_failures_are_categorical_and_sanitized(self) -> None:
        module = self.require_module()
        sentinel = "do-not-project-this-kernel-line"

        def run(command):
            if any(item.endswith("vcgencmd") for item in command):
                return subprocess.CompletedProcess(command, 0, "throttled=0x50005\n", "")
            return subprocess.CompletedProcess(
                command,
                0,
                f"EXT4-fs error {sentinel}\nBuffer I/O error\n",
                "",
            )

        with tempfile.TemporaryDirectory() as tmp:
            thermal = Path(tmp) / "temp"
            thermal.write_text("85000\n", encoding="utf-8")
            checks = module.evaluate_platform_health(run, thermal)
        rendered = json.dumps(checks)
        self.assertIn("power_throttled", rendered)
        self.assertIn("temperature_high", rendered)
        self.assertIn("filesystem_errors", rendered)
        self.assertNotIn(sentinel, rendered)

    def test_service_and_route_checks_use_only_fixed_read_only_commands(self) -> None:
        module = self.require_module()
        commands = []

        def run(command):
            commands.append(tuple(command))
            if "show" in command:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    "LoadState=loaded\nResult=success\n",
                    "",
                )
            return subprocess.CompletedProcess(command, 0, "active\n", "")

        config = {
            "security_onion": {"host": "192.0.2.10"},
            "alert_ingest": {"enabled": True, "host": "198.51.100.10"},
            "pcap_broker": {"enabled": False},
        }
        service = module.evaluate_service_health(run)
        routes = module.evaluate_route_health(config, run)
        self.assertEqual(service["status"], "pass")
        self.assertEqual(routes["status"], "pass")
        self.assertTrue(commands)
        self.assertFalse(any(command[0].endswith("ssh") for command in commands))
        self.assertFalse(any(command[0].endswith("ping") for command in commands))
        self.assertTrue(all("--help" not in command for command in commands))

    def test_readiness_does_not_latch_its_own_previous_failure(self) -> None:
        module = self.require_module()

        def run(command):
            if "show" in command:
                prior_result = (
                    "exit-code"
                    if command[-1] == "so-storage-health.service"
                    else "success"
                )
                return subprocess.CompletedProcess(
                    command,
                    0,
                    f"LoadState=loaded\nResult={prior_result}\n",
                    "",
                )
            return subprocess.CompletedProcess(command, 0, "active\n", "")

        self.assertEqual(module.evaluate_service_health(run)["status"], "pass")

    def test_ssh_readiness_checks_metadata_without_reading_private_key_content(self) -> None:
        module = self.require_module()
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            key = directory / "relay-key"
            hosts = directory / "known-hosts"
            key.write_text("PRIVATE-SENTINEL", encoding="utf-8")
            hosts.write_text("host ssh-ed25519 PUBLIC-SENTINEL\n", encoding="utf-8")
            key.chmod(0o600)
            hosts.chmod(0o600)
            config = {
                "security_onion": {"ssh_key": str(key)},
                "alert_ingest": {
                    "enabled": True,
                    "mode": "ssh_batch",
                    "ssh_key": str(key),
                    "known_hosts": str(hosts),
                },
                "pcap_broker": {"enabled": False},
            }
            check = module.evaluate_ssh_health(config)
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        rendered = json.dumps(check)
        self.assertEqual(check["status"], "pass")
        self.assertNotIn("PRIVATE-SENTINEL", rendered)
        self.assertNotIn(str(key), rendered)

    def test_pcap_transfer_pin_metadata_is_required_when_enabled(self) -> None:
        module = self.require_module()
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            key = directory / "relay-key"
            hosts = directory / "known-hosts"
            key.write_text("PRIVATE-SENTINEL", encoding="utf-8")
            key.chmod(0o600)
            config = {
                "security_onion": {
                    "ssh_key": str(key),
                    "pcap_ssh_key": str(key),
                },
                "pcap_broker": {
                    "enabled": True,
                    "mac_transfer": {
                        "ssh_key": str(key),
                        "known_hosts": str(hosts),
                    },
                },
            }

            self.assertEqual(
                module.evaluate_ssh_health(config)["code"],
                "ssh_metadata_invalid",
            )
            hosts.write_text("host ssh-ed25519 PUBLIC-SENTINEL\n", encoding="utf-8")
            hosts.chmod(0o600)
            self.assertEqual(module.evaluate_ssh_health(config)["code"], "ssh_ready")

    def test_report_is_bounded_schema_only_and_never_contacts_remote_systems(self) -> None:
        module = self.require_module()
        storage = {
            "ok": True,
            "root_storage": {"used_percent": 10},
            "storage": {"used_percent": 20},
            "smart": {"passed": True},
            "failures": [],
        }
        checks = [
            {"id": identifier, "status": "pass", "code": "ready"}
            for identifier in module.CHECK_IDS
            if identifier != "storage"
        ]
        with (
            mock.patch.object(module, "load_config", return_value={}),
            mock.patch.object(module, "evaluate_storage", return_value=storage),
            mock.patch.object(module, "evaluate_nonstorage_checks", return_value=checks),
        ):
            report = module.build_report(Path("/not-read"))
        self.assertTrue(report["ok"])
        self.assertEqual(report["schema"], "onion-sentinel-relay-readiness-v1")
        self.assertEqual([item["id"] for item in report["checks"]], list(module.CHECK_IDS))
        self.assertLess(len(json.dumps(report)), module.MAX_REPORT_BYTES)

    def test_health_wrapper_sanitizer_allows_only_fixed_readiness_fields(self) -> None:
        module = self.require_module()
        sanitization = importlib.import_module("relay_health_sanitization")
        report = {
            "schema": "onion-sentinel-relay-readiness-v1",
            "ok": True,
            "checks": [
                {
                    "id": identifier,
                    "status": "pass",
                    "code": {
                        "power": "power_ready",
                        "thermal": "temperature_ready",
                        "filesystem": "filesystem_ready",
                        "storage": "storage_ready",
                        "services": "services_ready",
                        "routes": "routes_ready",
                        "ssh": "ssh_ready",
                        "brokers": "brokers_ready",
                    }[identifier],
                    "raw": "do-not-project",
                }
                for identifier in module.CHECK_IDS
            ],
            "host": "do-not-project",
        }
        sanitized = sanitization.sanitize_storage_summary(report)
        self.assertIsNotNone(sanitized)
        rendered = json.dumps(sanitized)
        self.assertNotIn("do-not-project", rendered)
        self.assertEqual(set(sanitized), {"schema", "ok", "checks"})
        report["checks"][0]["code"] = "attacker-controlled"
        self.assertIsNone(sanitization.sanitize_storage_summary(report))

    def test_invalid_route_and_credential_metadata_fail_without_remote_commands(self) -> None:
        module = self.require_module()
        commands = []

        def run(command):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")

        route = module.evaluate_route_health(
            {"security_onion": {"host": "not-an-ip"}},
            run,
        )
        self.assertEqual(route["code"], "route_config_invalid")
        self.assertEqual(commands, [])
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "key"
            key.write_text("PRIVATE-SENTINEL", encoding="utf-8")
            key.chmod(0o644)
            ssh = module.evaluate_ssh_health(
                {"security_onion": {"ssh_key": str(key)}}
            )
        self.assertEqual(ssh["code"], "ssh_metadata_invalid")

    def test_cli_failure_is_fixed_schema_and_does_not_echo_bad_config(self) -> None:
        sentinel = "do-not-echo-invalid-relay-config"
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "config.json"
            config.write_text(sentinel, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--config", str(config)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(sentinel, result.stdout + result.stderr)
        self.assertNotIn(str(config), result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["schema"], "onion-sentinel-relay-readiness-v1")
        self.assertFalse(report["ok"])

    def test_local_probe_commands_receive_no_relay_secret_environment(self) -> None:
        module = self.require_module()
        completed = subprocess.CompletedProcess(["/usr/bin/true"], 0, b"", b"")
        with mock.patch.object(
            module,
            "run_bounded_command",
            return_value=completed,
        ) as bounded:
            module._run_local(["/usr/bin/true"])
        child_environment = bounded.call_args.kwargs["env"]
        self.assertEqual(
            child_environment,
            {
                "HOME": "/opt/so-alert-relay",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            },
        )
        self.assertFalse(any("TOKEN" in name or "SECRET" in name for name in child_environment))

    def test_installer_wrapper_contract_and_runbooks_include_readiness_recovery(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        contract = HEALTH_CONTRACT.read_text(encoding="utf-8")
        relay_readme = RELAY_README.read_text(encoding="utf-8")
        reliability = RELIABILITY_RUNBOOK.read_text(encoding="utf-8")
        recovery = RECOVERY_RUNBOOK.read_text(encoding="utf-8")
        self.assertIn('relay/app/relay_readiness.py', installer)
        self.assertIn('/opt/so-alert-relay/app/relay_readiness.py', contract)
        self.assertIn("Read-only Relay readiness", relay_readme)
        self.assertIn("every five minutes", reliability)
        self.assertIn("Relay backup and restore", recovery)
        self.assertIn("Relay upgrade and rollback", recovery)

    def test_relay_upgrade_preserves_live_application_config(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("RELAY_APP_CONFIG=/opt/so-alert-relay/app/config.json", installer)
        self.assertIn('if [[ ! -f "$RELAY_APP_CONFIG" ]]; then', installer)
        self.assertIn("Upgrade and repair installs preserve live routing", installer)
        self.assertNotIn(
            'install -o soalert -g soalert -m 0644 "$REPO_DIR/relay/config/config.example.json" /opt/so-alert-relay/app/config.json',
            installer,
        )


if __name__ == "__main__":
    unittest.main()
