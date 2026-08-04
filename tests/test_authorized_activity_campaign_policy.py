#!/usr/bin/env python3
"""Exact-match and fail-closed tests for authorized activity campaigns."""
from pathlib import Path
import json
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "n8n/alert_store/lib/authorized_activity_policy.js"
POLICY = ROOT / "n8n/config/authorized_activity_campaigns.json"
ALERT_STORE = ROOT / "n8n/alert_store/alert_store.js"


class AuthorizedActivityCampaignPolicyTests(unittest.TestCase):
    def test_startup_backfill_is_bounded_and_keyset_paginated(self) -> None:
        code = ALERT_STORE.read_text()
        start = code.index("async function backfillAuthorizedActivityCampaigns()")
        end = code.index("\nasync function authorizedCampaignForAlertId", start)
        backfill = code[start:end]

        self.assertNotIn("SELECT * FROM alerts", backfill)
        self.assertIn("const pageSize = 128", backfill)
        self.assertIn("WHERE rowid > ?", backfill)
        self.assertIn("ORDER BY rowid ASC", backfill)
        self.assertIn("LIMIT ?", backfill)
        self.assertIn("NOT EXISTS", backfill)
        self.assertIn("earliestAuthorization", backfill)
        self.assertIn("latestAuthorization", backfill)

    def test_campaign_representative_is_recomputed_from_earliest_member(self) -> None:
        code = ALERT_STORE.read_text()
        self.assertIn(
            "SELECT alert_id FROM authorized_activity_campaign_members\n"
            "           WHERE campaign_id = ?\n"
            "           ORDER BY observed_at ASC, alert_id ASC LIMIT 1",
            code,
        )
        self.assertIn(
            "SELECT stable_group_id FROM authorized_activity_campaign_members\n"
            "           WHERE campaign_id = ?\n"
            "           ORDER BY observed_at ASC, alert_id ASC LIMIT 1",
            code,
        )

    def run_node(self, source: str) -> dict:
        result = subprocess.run(
            ["node", "-e", source],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout)

    def test_exact_authorized_scan_matches_deterministically(self) -> None:
        payload = self.run_node(f"""
const policy = require({json.dumps(str(MODULE))});
const registry = policy.loadAuthorizedActivityPolicy({json.dumps(str(POLICY))});
const alert = {{
  timestamp: '2026-07-31T23:10:00Z',
  rule_id: '2003068',
  source: {{ip: '10.77.7.222'}},
  destination: {{port: 22}},
  network: {{transport: 'tcp'}},
}};
const one = policy.matchAuthorizedActivity(registry, alert, {{}});
const two = policy.matchAuthorizedActivity(registry, alert, {{}});
console.log(JSON.stringify({{one, same: one.campaign_id === two.campaign_id}}));
""")
        self.assertTrue(payload["same"])
        self.assertEqual(payload["one"]["investigation_mode"], "incident_response_only")
        self.assertEqual(payload["one"]["pcap_sample_limit"], 3)

    def test_different_source_rule_port_protocol_or_time_fails_closed(self) -> None:
        payload = self.run_node(f"""
const policy = require({json.dumps(str(MODULE))});
const registry = policy.loadAuthorizedActivityPolicy({json.dumps(str(POLICY))});
const base = {{
  timestamp: '2026-07-31T23:10:00Z', rule_id: '2003068',
  source: {{ip: '10.77.7.222'}}, destination: {{port: 22}},
  network: {{transport: 'tcp'}},
}};
const variants = [
  {{...base, source: {{ip: '10.77.7.223'}}}},
  {{...base, rule_id: '2003069'}},
  {{...base, destination: {{port: 23}}}},
  {{...base, network: {{transport: 'udp'}}}},
  {{...base, timestamp: '2026-08-06T23:10:00Z'}},
];
console.log(JSON.stringify(variants.map((item) => policy.matchAuthorizedActivity(registry, item, {{}}))));
""")
        self.assertEqual(payload, [None, None, None, None, None])

    def test_exact_tls_response_tuple_matches_but_unrelated_inbound_fails(self) -> None:
        payload = self.run_node(f"""
const policy = require({json.dumps(str(MODULE))});
const registry = policy.loadAuthorizedActivityPolicy({json.dumps(str(POLICY))});
const base = {{
  timestamp: '2026-07-31T22:31:00Z', rule_id: '2029340',
  source: {{ip: '208.70.182.100', port: 443}},
  destination: {{ip: '10.77.7.222', port: 57730}},
  network: {{transport: 'tcp'}},
}};
const match = policy.matchAuthorizedActivity(registry, base, {{}});
const wrongEndpoint = policy.matchAuthorizedActivity(
  registry, {{...base, destination: {{ip: '10.77.7.223', port: 57730}}}}, {{}},
);
const wrongService = policy.matchAuthorizedActivity(
  registry, {{...base, source: {{ip: '208.70.182.100', port: 444}}}}, {{}},
);
console.log(JSON.stringify({{match, wrongEndpoint, wrongService}}));
""")
        self.assertEqual(
            payload["match"]["id"],
            "authorized-tls-scan-responses-10-77-7-222",
        )
        self.assertIsNone(payload["wrongEndpoint"])
        self.assertIsNone(payload["wrongService"])

    def test_relay_control_plane_match_disables_recursive_pcap(self) -> None:
        payload = self.run_node(f"""
const policy = require({json.dumps(str(MODULE))});
const registry = policy.loadAuthorizedActivityPolicy({json.dumps(str(POLICY))});
const base = {{
  timestamp: '2026-07-31T23:47:39Z', rule_id: '2003068',
  source: {{ip: '10.77.7.225'}},
  destination: {{ip: '10.88.8.8', port: 22}},
  network: {{transport: 'tcp'}},
}};
const match = policy.matchAuthorizedActivity(registry, base, {{}});
const wrongSource = policy.matchAuthorizedActivity(
  registry, {{...base, source: {{ip: '10.77.7.224'}}}}, {{}},
);
const wrongDestination = policy.matchAuthorizedActivity(
  registry, {{...base, destination: {{ip: '10.88.8.9', port: 22}}}}, {{}},
);
console.log(JSON.stringify({{match, wrongSource, wrongDestination}}));
""")
        self.assertEqual(
            payload["match"]["id"],
            "onion-sentinel-relay-ssh-control-plane",
        )
        self.assertEqual(payload["match"]["pcap_sample_limit"], 0)
        self.assertEqual(payload["match"]["enrichment_sample_limit"], 0)
        self.assertIsNone(payload["wrongSource"])
        self.assertIsNone(payload["wrongDestination"])

    def test_malformed_policy_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            path.write_text('{"version":1,"policies":[{"id":"bad"}]}')
            result = subprocess.run(
                [
                    "node",
                    "-e",
                    (
                        f"const p=require({json.dumps(str(MODULE))});"
                        f"try{{p.loadAuthorizedActivityPolicy({json.dumps(str(path))});process.exit(1)}}"
                        "catch(error){console.log(error.message)}"
                    ),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("authorization_start", result.stdout)


if __name__ == "__main__":
    unittest.main()
