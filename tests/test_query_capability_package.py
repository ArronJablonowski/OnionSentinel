from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))

from onion_sentinel.analysis.query import capability  # noqa: E402


def package(*enabled: str) -> dict:
    return {
        "investigation_query_capability": {
            "enabled": True,
            "backends": {name: {"enabled": True} for name in enabled},
        },
    }


class QueryCapabilityPackageTests(unittest.TestCase):
    def test_security_onion_requires_enabled_advertisement_and_anchor(self) -> None:
        value = package("elastic", "oql")
        self.assertFalse(capability.available(
            value, "elastic", live_osquery_config=None,
        ))
        value["_local_investigation_query_context"] = {"anchor": {}}
        self.assertTrue(capability.available(
            value, "elastic", live_osquery_config=None,
        ))
        self.assertTrue(capability.available(
            value, "oql", live_osquery_config=None,
        ))

    def test_pcap_requires_nonempty_parsed_evidence(self) -> None:
        value = package("pcap_zeek")
        value["pcap_evidence"] = {"parsed_evidence": []}
        self.assertFalse(capability.available(
            value, "pcap_zeek", live_osquery_config=None,
        ))
        value["pcap_evidence"]["parsed_evidence"] = [{"kind": "zeek"}]
        self.assertTrue(capability.available(
            value, "pcap_zeek", live_osquery_config=None,
        ))

    def test_osquery_requires_live_runtime_enablement(self) -> None:
        value = package("osquery")
        self.assertFalse(capability.available(
            value, "osquery", live_osquery_config={"enabled": False},
        ))
        self.assertTrue(capability.available(
            value, "osquery", live_osquery_config={"enabled": True},
        ))

    def test_enrichment_requires_only_enabled_advertisement(self) -> None:
        self.assertTrue(capability.available(
            package("enrichment"), "enrichment", live_osquery_config=None,
        ))

    def test_disabled_or_unknown_backends_are_unavailable(self) -> None:
        self.assertFalse(capability.available(
            package(), "elastic", live_osquery_config=None,
        ))
        self.assertFalse(capability.available(
            package("invented"), "invented", live_osquery_config=None,
        ))
        value = package("elastic")
        value["investigation_query_capability"]["enabled"] = False
        self.assertFalse(capability.available(
            value, "elastic", live_osquery_config=None,
        ))


if __name__ == "__main__":
    unittest.main()
