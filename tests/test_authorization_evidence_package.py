"""Direct contracts for canonical operator authorization evidence."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.conclusions import authorization_evidence  # noqa: E402


def authorized_prompt() -> dict:
    alert = {
        "timestamp": "2026-07-24T18:30:00Z", "source_ip": "192.0.2.10",
        "source_port": 49152, "destination_ip": "198.51.100.20",
        "destination_port": 443, "rule_id": "2100001",
        "transport_protocol": "tcp",
    }
    coverage = {
        "source_ips": [alert["source_ip"]],
        "destination_ips": [alert["destination_ip"]],
        "rule_ids": [alert["rule_id"]], "source_ports": [alert["source_port"]],
        "destination_ports": [alert["destination_port"]],
        "destination_port_ranges": [],
        "transport_protocols": [alert["transport_protocol"]],
        "authorization_start": "2026-07-24T18:00:00Z",
        "authorization_end": "2026-07-24T19:00:00Z",
    }
    digest = hashlib.sha256(json.dumps(
        {"coverage": coverage}, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    return {
        "alert": alert,
        "authorization_evidence": {
            "status": "operator_authorized",
            "entries": [{
                "authorized": True, "source": "operator_assertion",
                "evidence_ref": f"authorized-activity:sha256:{digest}",
                "coverage": coverage,
            }],
        },
    }


class AuthorizationEvidencePackageTests(unittest.TestCase):
    def test_digest_bound_exact_event_tuple_is_accepted(self) -> None:
        self.assertTrue(
            authorization_evidence.has_structured_evidence(authorized_prompt())
        )

    def test_tampered_digest_fails_closed(self) -> None:
        prompt = authorized_prompt()
        prompt["authorization_evidence"]["entries"][0]["evidence_ref"] = (
            "authorized-activity:sha256:" + "f" * 64
        )
        self.assertFalse(authorization_evidence.has_structured_evidence(prompt))

    def test_event_outside_coverage_fails_closed(self) -> None:
        prompt = authorized_prompt()
        prompt["alert"]["destination_port"] = 444
        self.assertFalse(authorization_evidence.has_structured_evidence(prompt))

    def test_noncanonical_or_unbounded_entries_fail_closed(self) -> None:
        unsupported = authorized_prompt()
        unsupported["authorization_evidence"]["entries"][0]["source"] = "model_claim"
        overflow = authorized_prompt()
        overflow["authorization_evidence"]["entries"] *= 9
        extra = copy.deepcopy(authorized_prompt())
        extra["authorization_evidence"]["entries"][0]["coverage"]["free_form"] = True
        for prompt in (unsupported, overflow, extra):
            self.assertFalse(authorization_evidence.has_structured_evidence(prompt))


if __name__ == "__main__":
    unittest.main()
