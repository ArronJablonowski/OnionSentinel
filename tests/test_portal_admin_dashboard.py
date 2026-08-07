"""Behavior contracts for the modular Administration dashboard."""
from __future__ import annotations

import datetime as dt
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_admin_dashboard import (  # noqa: E402
    AdminDashboardSources,
    compose_admin_dashboard,
    render_admin_dashboard,
)


def shell(title: str, kicker: str, body: str, extra: str) -> bytes:
    return f"TITLE:{title}\nKICKER:{kicker}\n{extra}\n{body}".encode()


class AdminDashboardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.tmp.name)
        older = self.state_dir / "older.log"
        newer = self.state_dir / "newer.json"
        older.write_text("older")
        newer.write_text("newer")
        older.touch()
        newer.touch()
        older_time = dt.datetime(2026, 8, 7, 10, tzinfo=dt.timezone.utc).timestamp()
        newer_time = dt.datetime(2026, 8, 7, 11, tzinfo=dt.timezone.utc).timestamp()
        import os

        os.utime(older, (older_time, older_time))
        os.utime(newer, (newer_time, newer_time))
        self.active_action = None
        self.latest_outcome = {
            "state": "ok",
            "label": "Update <finished>",
            "when": "now",
            "message": "Completed safely",
            "returncode": 0,
        }
        self.availability = {"update": (True, "Update ready"), "reboot": (True, "Ready")}
        self.statuses = {
            "update": {
                "state": "ok",
                "message": "Last <message>",
                "started_at": "2026-08-07T10:00:00Z",
                "pid": 42,
                "returncode": 0,
            },
            "reboot": {"state": "idle"},
        }
        self.actions = {
            "update": {
                "label": "Update <Onion>",
                "summary": "Apply trusted updates",
                "accent": "#23d3ee",
                "command": ["update", "--safe"],
            },
            "reboot": {
                "label": "Reboot",
                "summary": "Reboot the host",
                "accent": "#ff7a90",
                "command": ["shutdown", "-r", "now"],
            },
        }

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def sources(self) -> AdminDashboardSources:
        services = {
            "macs-fan-control": {
                "running": True,
                "label": "Fan Control",
                "value": "Running",
                "detail": "Healthy",
            },
            "codex": {
                "running": False,
                "label": "Codex <App>",
                "value": "Stopped",
                "detail": "Start when needed",
            },
            "codex-cli": {
                "running": True,
                "label": "Codex CLI",
                "value": "Ready",
                "detail": "Installed",
            },
            "docker": {
                "running": False,
                "startable": False,
                "level": "alert",
                "label": "Docker",
                "value": "Unavailable",
                "detail": "Not installed",
            },
            "n8n": {
                "running": True,
                "label": "n8n",
                "value": "Running",
                "detail": "Healthy",
            },
        }
        return AdminDashboardSources(
            ensure_token=lambda: 'token-"safe',
            running_action=lambda: self.active_action,
            latest_outcome=lambda: self.latest_outcome,
            service_statuses=lambda: services,
            actions=self.actions,
            read_action_status=lambda action_id: self.statuses[action_id],
            last_performed_label=lambda status: ("1 hour ago", "Exact timestamp"),
            check_action_available=lambda action_id, **kwargs: self.availability[action_id],
            action_version_info=lambda action_id: {
                "current": "1.0",
                "latest": "2.0",
                "detail": f"Version detail for {action_id}",
            },
            state_dir=self.state_dir,
            human_size=lambda size: f"{size} bytes",
            format_timestamp=lambda value: value.isoformat(),
            tail_file=lambda path: f"tail <for> {path.name}",
            admin_log_path=lambda action_id: self.state_dir / f"{action_id}.log",
            render_cron_failure=lambda: '<section id="cron-failure">trusted</section>',
            render_cron_menu=lambda: '<details id="cron-menu">trusted</details>',
        )

    def test_composition_collects_ordered_services_actions_and_state_files(self) -> None:
        view = compose_admin_dashboard(self.sources())

        self.assertEqual(
            [service.service_id for service in view.services],
            ["macs-fan-control", "codex", "codex-cli", "docker", "n8n"],
        )
        self.assertEqual([action.action_id for action in view.actions], ["update", "reboot"])
        self.assertEqual([item.name for item in view.state_files], ["newer.json", "older.log"])
        self.assertEqual(view.actions[0].display_state, "completed")
        self.assertEqual(view.actions[0].returncode, "0")
        self.assertEqual(view.actions[1].button_label, "Reboot system")
        self.assertIs(view.latest_outcome, self.latest_outcome)

    def test_render_escapes_collected_values_and_preserves_controls(self) -> None:
        rendered = render_admin_dashboard(
            compose_admin_dashboard(self.sources()),
            "Started <safely>",
            False,
            shell,
        ).decode()

        self.assertIn("TITLE:⚙️ Administration", rendered)
        self.assertIn("Codex &lt;App&gt;", rendered)
        self.assertIn("Update &lt;Onion&gt;", rendered)
        self.assertIn("Last &lt;message&gt;", rendered)
        self.assertIn("Started &lt;safely&gt;", rendered)
        self.assertNotIn("<safely>", rendered)
        self.assertIn('data-start-service="codex"', rendered)
        self.assertNotIn('data-start-service="docker"', rendered)
        self.assertIn("Approve update", rendered)
        self.assertIn('data-reboot-form="true"', rendered)
        self.assertIn('placeholder="REBOOT"', rendered)
        self.assertIn("Update &lt;finished&gt; completed successfully", rendered)
        self.assertIn("tail &lt;for&gt; update.log", rendered)
        self.assertIn('id="cron-menu"', rendered)
        self.assertIn('id="cron-failure"', rendered)
        self.assertIn('const adminServiceToken = "token-\\"safe";', rendered)
        self.assertIn("const adminActionRunning = false;", rendered)
        self.assertIn('action="/admin/logout"', rendered)

    def test_active_action_suppresses_latest_outcome_and_disables_all_actions(self) -> None:
        self.active_action = {"label": "Package update", "pid": 9001}

        view = compose_admin_dashboard(self.sources())
        rendered = render_admin_dashboard(view, "", False, shell).decode()

        self.assertIsNone(view.latest_outcome)
        self.assertTrue(all(action.disabled for action in view.actions))
        self.assertTrue(all(action.button_label == "Wait for running action" for action in view.actions))
        self.assertIn("Package update is currently running as PID 9001", rendered)
        self.assertNotIn("Update &lt;finished&gt; completed successfully", rendered)
        self.assertIn("const adminActionRunning = true;", rendered)

    def test_unavailable_update_is_disabled_but_reboot_remains_confirmable(self) -> None:
        self.availability["update"] = (False, "No update available")

        view = compose_admin_dashboard(self.sources())
        update, reboot = view.actions

        self.assertEqual(update.button_label, "No updates available")
        self.assertTrue(update.disabled)
        self.assertEqual(reboot.button_label, "Reboot system")
        self.assertFalse(reboot.disabled)

    def test_missing_state_directory_produces_stable_empty_inventory(self) -> None:
        sources = self.sources()
        sources = AdminDashboardSources(
            **{**sources.__dict__, "state_dir": self.state_dir / "missing"}
        )

        rendered = render_admin_dashboard(
            compose_admin_dashboard(sources), "Blocked <request>", True, shell
        ).decode()

        self.assertIn("No files found in the Administration action directory", rendered)
        self.assertIn("Action blocked", rendered)
        self.assertIn("Blocked &lt;request&gt;", rendered)


if __name__ == "__main__":
    unittest.main()
