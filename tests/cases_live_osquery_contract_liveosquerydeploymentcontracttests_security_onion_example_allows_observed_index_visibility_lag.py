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

class LiveOsqueryDeploymentContractTestsSecurityOnionExampleAllowsObservedIndexVisibilityLagCases:
    def test_security_onion_example_allows_observed_index_visibility_lag(self):
        config = json.loads(SO_CONFIG_EXAMPLE.read_text(encoding="utf-8"))
        self.assertEqual(config["result_visibility_seconds"], 60)


    def test_mac_forced_key_runs_only_broker_as_service_account(self):
        authorized_key = RELAY_AUTHORIZED_KEY.read_text(encoding="utf-8")
        self.assertIn(
            'command="/usr/local/sbin/run-live-osquery-broker"',
            authorized_key,
        )
        self.assertNotIn("/opt/so-alert-relay/bin", authorized_key)
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


    def test_response_newline_is_inside_four_mib_ceiling(self):
        for module in (load_relay_broker(), load_security_onion_wrapper()):
            with self.subTest(module=module.__name__):
                sink = SimpleNamespace(buffer=io.BytesIO())
                encoded = b"x" * (module.MAX_RESPONSE_BYTES - 1)
                with (
                    mock.patch.object(module.sys, "stdout", sink),
                    mock.patch.object(
                        module,
                        "bounded_json_bytes",
                        return_value=encoded,
                    ) as serializer,
                ):
                    self.assertEqual(module._emit({"ok": True}), 0)
                serializer.assert_called_once_with(
                    {"ok": True},
                    maximum=module.MAX_RESPONSE_BYTES - 1,
                )
                self.assertEqual(
                    len(sink.buffer.getvalue()),
                    module.MAX_RESPONSE_BYTES,
                )
                self.assertTrue(sink.buffer.getvalue().endswith(b"\n"))


    def test_security_onion_forced_key_uses_pre_sudo_launcher(self):
        authorized_key = SO_AUTHORIZED_KEY.read_text(encoding="utf-8")
        self.assertIn(
            'command="/usr/local/sbin/run-live-osquery-forced"',
            authorized_key,
        )
        self.assertNotIn('command="sudo ', authorized_key)
        for restriction in (
            "no-agent-forwarding",
            "no-X11-forwarding",
            "no-port-forwarding",
            "no-pty",
            "no-user-rc",
        ):
            self.assertIn(restriction, authorized_key)

        completed = subprocess.run(
            [str(SO_LAUNCHER)],
            env={**os.environ, "SSH_ORIGINAL_COMMAND": "id"},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("commands are not accepted", completed.stderr)
        self.assertIn(
            "security-onion/bin/run-live-osquery-forced",
            SO_INSTALLER.read_text(encoding="utf-8"),
        )


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


    def test_relay_broker_main_preserves_success_and_failure_envelopes(self):
        broker = load_relay_broker()
        config = {
            "enabled": True,
            "allowed_target_aliases": ["endpoint-a"],
            "known_hosts": "/private/known-hosts",
            "ssh_key": "/private/key",
            "host": "relay.example",
        }
        request = {"case_id": "case-1", "requests": []}
        artifact = {"case_id": "case-1", "results": []}
        process = SimpleNamespace(
            returncode=0,
            stdout=json.dumps(artifact).encode("utf-8"),
            stderr=b"",
        )
        with (
            mock.patch.dict(broker.os.environ, {}, clear=True),
            mock.patch.object(broker, "_load_config", return_value=config),
            mock.patch.object(broker, "_read_request", return_value={"raw": True}),
            mock.patch.object(
                broker,
                "validate_transport_payload",
                return_value=request,
            ) as validate,
            mock.patch.object(
                broker,
                "run_bounded_command",
                return_value=process,
            ) as run,
            mock.patch.object(
                broker,
                "validate_result_artifact",
                return_value=artifact,
            ) as validate_artifact,
            mock.patch.object(broker, "_emit", return_value=17) as emit,
        ):
            self.assertEqual(broker.main(), 17)
        validate.assert_called_once_with(
            {"raw": True},
            allowed_aliases=["endpoint-a"],
        )
        self.assertEqual(run.call_args.args[0][0:5], [
            "/usr/bin/ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
        ])
        validate_artifact.assert_called_once_with(
            artifact,
            expected_requests=request["requests"],
        )
        emit.assert_called_once_with(artifact)

        with (
            mock.patch.dict(
                broker.os.environ,
                {"SSH_ORIGINAL_COMMAND": " id "},
                clear=True,
            ),
            mock.patch.object(broker, "_load_config") as load,
            mock.patch.object(broker, "_emit", return_value=23) as emit,
        ):
            self.assertEqual(broker.main(), 23)
        load.assert_not_called()
        emit.assert_called_once_with(
            {"error": "commands are not accepted by this forced endpoint"},
            2,
        )

        with (
            mock.patch.dict(broker.os.environ, {}, clear=True),
            mock.patch.object(
                broker,
                "_load_config",
                side_effect=broker.BrokerError("bounded failure"),
            ),
            mock.patch.object(broker, "_emit", return_value=29) as emit,
        ):
            self.assertEqual(broker.main(), 29)
        emit.assert_called_once_with({"error": "bounded failure"}, 3)


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
            "/usr/local/sbin/run-live-osquery-broker",
            installer,
        )
        self.assertIn(
            "install -o soalert -g soalert -m 0700 -d /opt/so-alert-relay",
            installer,
        )
