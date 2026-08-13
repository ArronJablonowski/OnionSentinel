"""Characterization for the deterministic PCAP workflow proxy renderer."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n" / "bin" / "sync-pcap-broker-workflow.py"
WORKFLOW_PATH = (
    ROOT / "n8n" / "workflows" / "onion-sentinel-pcap-broker.workflow.json"
)


def load_module():
    spec = importlib.util.spec_from_file_location(
        "pcap_workflow_proxy_source_target",
        MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load PCAP workflow renderer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PcapWorkflowProxySourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def test_endpoint_sources_remain_byte_stable(self) -> None:
        expected = {
            ("GET", "/pcap/requests"): (
                2133,
                "4736441a1910de6f9e286661d3277cfae22bb90ab3dff13405885a624a32ce7f",
            ),
            ("POST", "/pcap/claim"): (
                2118,
                "d2044a70aa1b36f751daba410e5fb54de458554ccd21d389c5e57ed917a72c1a",
            ),
            ("POST", "/pcap/complete"): (
                2121,
                "49ffcad3a90e03d477df248ce32edccc4216ad23743849053ee318b2e2f6ca9f",
            ),
            ("POST", "/pcap/progress"): (
                2121,
                "d242aa4c4dcb2fc617387616d488a6114c766616011b4b7c3281ed396f739ea0",
            ),
            ("POST", "/pcap/retry"): (
                2118,
                "765a32d2bf1a43bbc21047611eef2880e7f1f26d8ea9b3e73ef5c9dc6818d006",
            ),
        }
        for endpoint in self.module.ENDPOINTS:
            identity = (endpoint["target_method"], endpoint["target_path"])
            with self.subTest(identity=identity):
                source = self.module.proxy_source(endpoint).encode("utf-8")
                self.assertEqual(
                    (len(source), hashlib.sha256(source).hexdigest()),
                    expected[identity],
                )

    def test_committed_workflow_contains_exact_renderer_output(self) -> None:
        workflow = json.loads(WORKFLOW_PATH.read_text(encoding="utf-8"))
        code_by_name = {
            node["name"]: node["parameters"]["jsCode"]
            for node in workflow["nodes"]
            if node["type"] == "n8n-nodes-base.code"
        }
        for endpoint in self.module.ENDPOINTS:
            self.assertEqual(
                code_by_name[endpoint["code_name"]],
                self.module.proxy_source(endpoint),
            )

    def test_renderer_preserves_string_coercion_and_projection_truthiness(self) -> None:
        cases = (
            (
                {"target_method": "PATCH", "target_path": "/synthetic/path"},
                2124,
                "f58a98a8fc58b9c23191eca00cd978ac38b29696de77980cca5d579c75192855",
            ),
            (
                {
                    "target_method": 7,
                    "target_path": 9,
                    "forward_body_as_query": "yes",
                },
                2116,
                "0d8967450193c654c49f881205d1580656062de67a62dd3e551a41095e61b077",
            ),
        )
        for source, length, digest in cases:
            original = dict(source)
            rendered = self.module.proxy_source(source).encode("utf-8")
            self.assertEqual(source, original)
            self.assertEqual(len(rendered), length)
            self.assertEqual(hashlib.sha256(rendered).hexdigest(), digest)

    def test_missing_required_fields_retain_key_errors(self) -> None:
        with self.assertRaisesRegex(KeyError, "target_method"):
            self.module.proxy_source({})
        with self.assertRaisesRegex(KeyError, "target_path"):
            self.module.proxy_source({"target_method": "GET"})

    def test_generated_source_keeps_metadata_only_security_boundary(self) -> None:
        source = self.module.proxy_source(self.module.ENDPOINTS[0])
        for required in (
            "$vars.PCAP_BROKER_TOKEN",
            "invalid or missing X-Relay-Token",
            "hostname: 'alert-store'",
            "port: 8787",
            "timeout: 20000",
            "proxy_status_code: response.statusCode",
            ".slice(0, 240)",
            "PCAP bytes never pass through n8n",
        ):
            self.assertIn(required, source)
        for forbidden in ("pcap-evidence", "artifact-chunk", "Buffer.from("):
            self.assertNotIn(forbidden, source)

    def test_check_mode_accepts_the_committed_workflow(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "")


if __name__ == "__main__":
    unittest.main()
