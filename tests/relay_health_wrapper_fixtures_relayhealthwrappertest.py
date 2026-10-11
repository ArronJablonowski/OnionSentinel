from __future__ import annotations

from relay_health_wrapper_fixtures import (
    Path,
    REPO_ROOT,
    WRAPPER_PATH,
    completed,
    contextlib,
    importlib,
    io,
    json,
    load_wrapper,
    mock,
    subprocess,
    sys,
    unittest,
)

class RelayHealthWrapperTestFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self.wrapper = load_wrapper()


    def run_component_with_state(
        self,
        component: str,
        state: dict,
        *,
        relay_result: subprocess.CompletedProcess | None = None,
        pcap_result: subprocess.CompletedProcess | None = None,
    ):
        stdout = io.StringIO()
        stderr = io.StringIO()
        persisted: list[dict] = []
        relay_result = relay_result or completed(
            0,
            stdout=(
                '{"alert_count":0,"dropped_alert_count":0,'
                '"new_alert_count":0,"posted_webhook_alerts":0}\n'
            ),
        )
        pcap_result = pcap_result or completed(
            0,
            stdout=(
                '{"ok":true,"enabled":true,"broker_contacted":true,'
                '"processed":0,"operational_failures":0}\n'
            ),
        )
        with (
            mock.patch.object(
                self.wrapper,
                "run_relay",
                return_value=relay_result,
            ),
            mock.patch.object(
                self.wrapper,
                "run_pcap_broker",
                return_value=pcap_result,
            ),
            mock.patch.object(
                self.wrapper,
                "validate_webhook_token_sources",
                return_value=None,
            ),
            mock.patch.object(
                self.wrapper,
                "load_state",
                return_value=state,
            ),
            mock.patch.object(
                self.wrapper,
                "persist_component_state",
                side_effect=lambda value, _component, _path: persisted.append(
                    dict(value)
                ),
            ),
            mock.patch.object(
                self.wrapper,
                "send_telegram",
                return_value={"ok": True, "status": 200},
            ) as send_telegram,
            mock.patch.object(
                self.wrapper,
                "send_relay_health_event",
                return_value={"ok": True, "status": 200},
            ),
            mock.patch.object(
                sys,
                "argv",
                ["relay_health_wrapper.py", "--component", component],
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            rc = self.wrapper.main()
        return rc, stdout.getvalue(), persisted, send_telegram


    def run_main_with(self, relay_result: subprocess.CompletedProcess, pcap_result: subprocess.CompletedProcess):
        stdout = io.StringIO()
        stderr = io.StringIO()
        saved_states: list[dict] = []
        with (
            mock.patch.object(self.wrapper, "run_relay", return_value=relay_result) as run_relay,
            mock.patch.object(self.wrapper, "run_pcap_broker", return_value=pcap_result) as run_pcap,
            mock.patch.object(self.wrapper, "validate_webhook_token_sources", return_value=None),
            mock.patch.object(self.wrapper, "load_state", return_value={"status": "unknown", "consecutive_failures": 0}),
            mock.patch.object(self.wrapper, "save_state", side_effect=lambda state: saved_states.append(dict(state))),
            mock.patch.object(self.wrapper, "send_telegram", return_value={"ok": True, "status": 200}),
            mock.patch.object(self.wrapper, "send_relay_health_event", return_value={"ok": True, "status": 200}),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            rc = self.wrapper.main()
        run_relay.assert_called_once()
        run_pcap.assert_called_once()
        return rc, stdout.getvalue(), stderr.getvalue(), saved_states


    def run_component_with_sinks(
        self,
        component: str,
        state: dict,
        *,
        relay_result: subprocess.CompletedProcess | None = None,
        pcap_result: subprocess.CompletedProcess | None = None,
        storage_result: subprocess.CompletedProcess | None = None,
        failure_threshold: int = 1,
    ) -> dict:
        stdout = io.StringIO()
        stderr = io.StringIO()
        persisted: list[dict] = []
        telegram_messages: list[str] = []
        webhook_events: list[dict] = []
        relay_result = relay_result or completed(
            0,
            stdout=(
                '{"alert_count":0,"dropped_alert_count":0,'
                '"new_alert_count":0,"posted_webhook_alerts":0}\n'
            ),
        )
        pcap_result = pcap_result or completed(
            0,
            stdout=(
                '{"ok":true,"enabled":true,"broker_contacted":true,'
                '"processed":0,"operational_failures":0}\n'
            ),
        )
        storage_result = storage_result or completed(
            0,
            stdout='{"ok":true,"failures":[]}\n',
        )

        def record_telegram(message: str) -> dict:
            telegram_messages.append(message)
            return {"ok": True, "status": 200}

        def record_event(event: dict) -> dict:
            webhook_events.append(event)
            return {"ok": True, "status": 200}

        with (
            mock.patch.object(
                self.wrapper,
                "run_relay",
                return_value=relay_result,
            ),
            mock.patch.object(
                self.wrapper,
                "run_pcap_broker",
                return_value=pcap_result,
            ),
            mock.patch.object(
                self.wrapper,
                "run_storage_health",
                return_value=storage_result,
            ),
            mock.patch.object(
                self.wrapper,
                "validate_webhook_token_sources",
                return_value=None,
            ),
            mock.patch.object(
                self.wrapper,
                "load_state",
                return_value=state,
            ),
            mock.patch.object(
                self.wrapper,
                "persist_component_state",
                side_effect=lambda value, _component, _path: persisted.append(
                    dict(value)
                ),
            ),
            mock.patch.object(
                self.wrapper,
                "send_telegram",
                side_effect=record_telegram,
            ),
            mock.patch.object(
                self.wrapper,
                "send_relay_health_event",
                side_effect=record_event,
            ),
            mock.patch.object(
                self.wrapper,
                "FAILURE_NOTIFY_THRESHOLD",
                failure_threshold,
            ),
            mock.patch.object(
                sys,
                "argv",
                ["relay_health_wrapper.py", "--component", component],
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            rc = self.wrapper.main()
        return {
            "returncode": rc,
            "stdout": stdout.getvalue(),
            "stderr": stderr.getvalue(),
            "persisted": persisted,
            "telegram_messages": telegram_messages,
            "webhook_events": webhook_events,
        }
