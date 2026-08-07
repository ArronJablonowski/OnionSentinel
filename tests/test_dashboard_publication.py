import json
import sys
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import dashboard_publication as publication  # noqa: E402


def report(digest: str = "a" * 12, alert_ts: float = 1.0) -> SimpleNamespace:
    return SimpleNamespace(
        digest=digest,
        rendered_html="<p>detail</p>",
        alert_ts=alert_ts,
        rule_id="rule-1",
        rule_name="Rule One",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        destination_port="443",
        criticality="High",
        ai_status_key="analyzed",
        ai_status_label="Analyzed",
        ai_status_detail="complete",
    )


class DashboardPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.paths = publication.DashboardPublicationPaths(
            out_dir=root / "web",
            detail_dir=root / "web" / "details",
            status_json=root / "web" / "status.json",
            beacon_json=root / "web" / "beacon.json",
            beacon_history_json=root / "web" / "history.json",
            source_beacon_json=root / "state" / "beacon.json",
            source_beacon_history_json=root / "state" / "history.json",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_status_and_seed_beacon_payloads_are_explicit_and_deterministic(self) -> None:
        item = report()
        status = publication.status_payload(
            [item], generated_at="now", ai_state={"label": "Codex"}
        )
        beacon = publication.seed_beacon_payload(
            [item], generated_at="fallback", report_time=lambda value: f"ts:{value}"
        )
        self.assertEqual(status["reports"][item.digest]["ai_status_key"], "analyzed")
        self.assertEqual(status["ai"], {"label": "Codex"})
        self.assertEqual(beacon["generated_at"], "ts:1.0")
        self.assertEqual(beacon["triage_level"], "high")

    def test_beacon_mirror_and_history_fallback_are_atomic(self) -> None:
        self.paths.source_beacon_json.parent.mkdir(parents=True)
        self.paths.source_beacon_json.write_text('{"ok": false}', encoding="utf-8")
        self.paths.source_beacon_history_json.write_text('{broken', encoding="utf-8")
        publication.publish_beacon_json(
            [], self.paths, generated_at="now", report_time=str
        )
        publication.publish_beacon_history_json(self.paths)
        self.assertEqual(json.loads(self.paths.beacon_json.read_text()), {"ok": False})
        self.assertEqual(json.loads(self.paths.beacon_history_json.read_text()), [])
        self.assertEqual(list(self.paths.out_dir.glob(".*.tmp")), [])

    def test_detail_publication_rejects_unsafe_names_and_removes_stale_files(self) -> None:
        self.paths.detail_dir.mkdir(parents=True)
        stale = self.paths.detail_dir / f"{'b' * 12}.html"
        stale.write_text("stale", encoding="utf-8")
        written = publication.publish_detail_fragments(
            [report(), report("../unsafe")], self.paths
        )
        self.assertEqual([path.name for path in written], [f"{'a' * 12}.html"])
        self.assertFalse(stale.exists())
        self.assertFalse((self.paths.out_dir / "unsafe.html").exists())

    def test_page_publication_includes_canonical_routes_and_aliases(self) -> None:
        written = publication.publish_static_pages(
            self.paths,
            [("alerts", "index.html", "Alerts", "Triage")],
            shell_html="shell",
            reports=[],
            render_page=lambda shell, key, reports: f"{shell}:{key}:{len(reports)}",
        )
        self.assertEqual(
            [path.name for path in written],
            ["index.html", "soc-alerts.html", "siem-tuning.html"],
        )
        self.assertEqual((self.paths.out_dir / "index.html").read_text(), "shell:alerts:0")
        self.assertEqual(
            (self.paths.out_dir / "siem-tuning.html").read_text(),
            "shell:siem_engineering:0",
        )


if __name__ == "__main__":
    unittest.main()
