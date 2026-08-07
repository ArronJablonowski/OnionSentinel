import sys
from dataclasses import replace
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

import portal_request_routes as routes  # noqa: E402
import portal_soc_write_dispatch as dispatch  # noqa: E402


class PortalSocWriteDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.calls = []

        def target(name):
            def callback(resource_id, payload):
                self.calls.append((name, resource_id, payload))
                return 202, {"operation": name}
            return callback

        def bulk(payload):
            self.calls.append(("incident_reanalyze_all", None, payload))
            return 202, {"operation": "incident_reanalyze_all"}

        self.callbacks = dispatch.SocWriteCallbacks(
            alert_ack=target("alert_ack"),
            alert_pcap=target("alert_pcap"),
            alert_analyze=target("alert_analyze"),
            alert_escalate=target("alert_escalate"),
            alert_adjudicate=target("alert_adjudicate"),
            incident_adjudicate=target("incident_adjudicate"),
            incident_status=target("incident_status"),
            incident_reanalyze=target("incident_reanalyze"),
            incident_reanalyze_all=bulk,
        )

    @staticmethod
    def classify(path):
        return routes.classify_post_route(
            path,
            cti_program_path="/api/cyber-threat-intel/program",
            prompt_paths=frozenset(),
        )

    def test_each_targeted_operation_calls_only_its_bounded_callback(self) -> None:
        cases = (
            ("/api/soc-alerts/a%20b/ack", "alert_ack", "a b"),
            ("/api/soc-alerts/a%20b/pcap", "alert_pcap", "a b"),
            ("/api/soc-alerts/a%20b/analyze", "alert_analyze", "a b"),
            ("/api/soc-alerts/a%20b/escalate", "alert_escalate", "a b"),
            ("/api/soc-alerts/a%20b/adjudicate", "alert_adjudicate", "a b"),
            ("/api/soc-incidents/a%20b/adjudicate", "incident_adjudicate", "a b"),
            ("/api/soc-incidents/a%20b/status", "incident_status", "a b"),
            ("/api/soc-incidents/a%20b/reanalyze", "incident_reanalyze", "a b"),
        )
        for path, name, resource_id in cases:
            with self.subTest(path=path):
                self.calls.clear()
                result = dispatch.dispatch_authorized_soc_write(
                    self.classify(path), {"reason": "test"}, self.callbacks
                )
                self.assertEqual(result, (202, {"operation": name}))
                self.assertEqual(
                    self.calls,
                    [(name, resource_id, {"reason": "test"})],
                )

    def test_bulk_reanalysis_uses_payload_only_callback(self) -> None:
        result = dispatch.dispatch_authorized_soc_write(
            self.classify("/api/soc-incidents/reanalyze-all"),
            {"mode": "queued"},
            self.callbacks,
        )
        self.assertEqual(result, (202, {"operation": "incident_reanalyze_all"}))
        self.assertEqual(
            self.calls,
            [("incident_reanalyze_all", None, {"mode": "queued"})],
        )

    def test_non_soc_route_is_rejected_before_any_callback(self) -> None:
        with self.assertRaisesRegex(ValueError, "not a SOC write operation"):
            dispatch.dispatch_authorized_soc_write(
                self.classify("/api/assets/update"), {}, self.callbacks
            )
        self.assertEqual(self.calls, [])

    def test_targeted_operation_without_resource_id_is_rejected(self) -> None:
        route = replace(
            self.classify("/api/soc-alerts/group/ack"),
            resource_id=None,
        )
        with self.assertRaisesRegex(ValueError, "has no resource target"):
            dispatch.dispatch_authorized_soc_write(route, {}, self.callbacks)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
