import datetime as dt
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_portal_admin_session_store import load_portal


class PortalMetricDetailRendererContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.portal = load_portal()

    def test_shell_escapes_labels_and_preserves_owned_html_fragments(self):
        rendered = self.portal.metric_detail_shell(
            'Title <unsafe>', 'Kicker & detail',
            '<section id="owned">Body</section>',
            '<span id="hero-owned">Extra</span>',
        ).decode()
        self.assertIn("<title>Title &lt;unsafe&gt; · Mac Studio LAN Portal</title>", rendered)
        self.assertIn('<div class="kicker">Kicker &amp; detail</div>', rendered)
        self.assertIn('<section id="owned">Body</section>', rendered)
        self.assertIn('<span id="hero-owned">Extra</span>', rendered)

    def test_macos_update_detail_preserves_cache_metadata_and_escaping(self):
        with tempfile.TemporaryDirectory() as tmp:
            status_file = Path(tmp) / "updates.json"
            payload = {
                "status": "Available <now>",
                "count": 1,
                "checked_at": "2026-08-10T00:00:00-06:00",
                "ok": True,
                "updates": ["macOS <unsafe>"],
                "raw_tail": "raw <tail>",
                "command": "/usr/sbin/softwareupdate --list",
                "returncode": 0,
            }
            with (
                mock.patch.object(self.portal, "MACOS_UPDATE_STATUS_FILE", status_file),
                mock.patch.object(self.portal, "read_macos_update_status", return_value=payload),
            ):
                rendered = self.portal.render_macos_updates_detail().decode()
        self.assertIn("Available &lt;now&gt;", rendered)
        self.assertIn("macOS &lt;unsafe&gt;", rendered)
        self.assertIn("raw &lt;tail&gt;", rendered)
        self.assertIn(str(status_file), rendered)

    def test_system_uptime_detail_projects_warning_and_hostname(self):
        with (
            mock.patch.object(
                self.portal, "system_uptime_metric",
                return_value=("Fan check", "uptime detail <unsafe>", True),
            ),
            mock.patch.object(
                self.portal, "macs_fan_control_status",
                return_value=(False, "fan detail <unsafe>"),
            ),
            mock.patch.object(self.portal.socket, "gethostname", return_value="studio<host>"),
        ):
            rendered = self.portal.render_system_uptime_detail().decode()
        self.assertIn("Fan check", rendered)
        self.assertIn("Not running", rendered)
        self.assertIn("studio&lt;host&gt;", rendered)
        self.assertIn("uptime detail &lt;unsafe&gt;", rendered)
        self.assertIn("fan detail &lt;unsafe&gt;", rendered)

    def test_portal_update_detail_preserves_marker_age_and_report_count(self):
        marker = Path("/tmp/portal-marker")
        update = dt.datetime(2026, 8, 10, tzinfo=dt.timezone.utc)
        now = update + dt.timedelta(minutes=61)
        with (
            mock.patch.object(self.portal, "LAST_UPDATED_FILE", marker),
            mock.patch.object(self.portal, "portal_last_updated", return_value=update.timestamp()),
            mock.patch.object(self.portal.dt, "datetime", wraps=dt.datetime) as clock,
        ):
            clock.fromtimestamp.return_value = update
            clock.now.return_value = now
            rendered = self.portal.render_portal_update_detail([object(), object()]).decode()
        self.assertIn("61 minutes ago", rendered)
        self.assertIn("Reports indexed</span><strong>2</strong>", rendered)
        self.assertIn(str(marker), rendered)


if __name__ == "__main__":
    unittest.main()
