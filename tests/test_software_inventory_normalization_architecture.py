from __future__ import annotations

import hashlib
import inspect
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

import software_inventory_normalization as normalization


class SoftwareInventoryNormalizationArchitectureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.window = {
            "start": "2026-08-11T12:00:00.000Z",
            "end": "2026-08-12T12:00:00.000Z",
        }

    @staticmethod
    def host_ref(hostname: str) -> str:
        normalized = hostname.strip().rstrip(".").lower()
        return hashlib.sha256(
            ("host\0" + normalized).encode("utf-8")
        ).hexdigest()[:24]

    def record(self, source: str = "zeek_software") -> dict:
        policy = normalization.SOURCE_POLICY[source]
        return {
            "evidence_id": "e" * 24,
            "source": source,
            "source_dataset": policy["dataset"],
            "tier": policy["tier"],
            "confidence": policy["confidence"],
            "asset_ref_type": policy["asset_ref_type"],
            "asset_ref": (
                self.host_ref("studio.example")
                if source == "osquery_apps"
                else "10.66.6.20"
            ),
            "platform": policy["platform"],
            "operating_system_type": "",
            "operating_system_version": "",
            "operating_system_source": "",
            "operating_system_confidence": "",
            "product": "Example",
            "version": "" if source == "http_user_agent" else "1",
            "category": "application",
            "first_seen": "2026-08-11T13:00:00.000Z",
            "last_seen": "2026-08-12T11:00:00.000Z",
            "observation_count": 2,
        }

    def normalized(self, value: object, source: str | None = None) -> dict:
        return normalization._normalize_record(
            value,
            expected_source=source,
            expected_window=self.window,
        )

    def test_owner_dependency_chain_is_inward_and_bounded(self) -> None:
        facade = (BIN / "software_inventory_normalization.py").read_text()
        record_owner = (
            BIN / "software_inventory_record_normalization.py"
        ).read_text()
        state_owner = (
            BIN / "software_inventory_state_validation.py"
        ).read_text()
        self.assertLessEqual(len(facade.splitlines()), 250)
        self.assertLessEqual(len(record_owner.splitlines()), 600)
        self.assertLessEqual(len(state_owner.splitlines()), 600)
        self.assertNotIn("software_inventory_normalization", record_owner)
        self.assertNotIn("software_inventory_normalization", state_owner)
        self.assertIn(
            "from software_inventory_record_normalization import normalize_record",
            state_owner,
        )
        self.assertIn(
            "normalize_record as _normalize_record",
            facade,
        )
        self.assertIn(
            "from software_inventory_state_validation import",
            facade,
        )

    def test_public_signatures_and_record_projection_are_exact(self) -> None:
        self.assertEqual(
            str(inspect.signature(normalization._normalize_record)),
            "(value: 'object', *, expected_source: 'Optional[str]' = None, expected_window: 'Optional[Dict[str, str]]' = None) -> 'Dict[str, Any]'",
        )
        self.assertEqual(
            str(inspect.signature(normalization.validate_state)),
            "(value: 'object') -> 'Dict[str, Any]'",
        )
        record = self.record("osquery_apps")
        record.update(
            {
                "operating_system_type": "macOS",
                "operating_system_version": "macOS 26.0",
                "operating_system_source": "osquery_manager.result:host.os",
                "operating_system_confidence": "HIGH",
            }
        )
        expected = dict(record)
        expected["operating_system_confidence"] = "high"
        self.assertEqual(self.normalized(record, "osquery_apps"), expected)

    def test_record_rejection_precedence_and_messages_are_exact(self) -> None:
        base = self.record()
        cases = []
        cases.append((None, "invalid shape"))
        cases.append(({**base, "extra": True}, "invalid shape"))
        cases.append(({**base, "source": "unknown"}, "source is invalid"))
        cases.append(({**base, "source_dataset": "wrong"}, "dataset is invalid"))
        cases.append(({**base, "tier": "installed"}, "evidence semantics are invalid"))
        cases.append(({**base, "evidence_id": "bad"}, "evidence identifier is invalid"))
        cases.append(({**base, "asset_ref_type": "host"}, "asset reference type is invalid"))
        cases.append(({**base, "asset_ref": "203.0.113.10"}, "not a LAN address"))
        cases.append(({**base, "platform": "wrong"}, "platform conflicts"))
        cases.append((
            {**self.record("http_user_agent"), "version": "invented"},
            "must not invent a version",
        ))
        endpoint = self.record("osquery_apps")
        endpoint.update({
            "operating_system_type": "macOS",
            "operating_system_source": "untrusted",
            "operating_system_confidence": "high",
        })
        cases.append((endpoint, "invalid provenance"))
        passive = {**base, "operating_system_type": "Linux"}
        cases.append((passive, "passive software evidence"))
        cases.append((
            {**base, "first_seen": base["last_seen"], "last_seen": base["first_seen"]},
            "timestamps are reversed",
        ))
        cases.append((
            {**base, "last_seen": self.window["end"]},
            "falls outside the query window",
        ))
        cases.append(({**base, "observation_count": 0}, "must be from 1"))
        for value, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    self.normalized(value)

    def success_state(self) -> dict:
        statuses = {
            source: {
                "status": "ok",
                "complete": True,
                "pages": 1,
                "returned": 1 if source == "zeek_software" else 0,
                "freshness": "fresh" if source == "zeek_software" else "empty",
                "latest_observation_at": (
                    "2026-08-12T11:00:00.000Z"
                    if source == "zeek_software"
                    else ""
                ),
            }
            for source in normalization.SOURCES
        }
        return {
            "schema": normalization.STATE_SCHEMA,
            "version": 1,
            "updated_at": "2026-08-12T12:00:00.000Z",
            "collection": {
                "status": "ok",
                "last_attempt_at": "2026-08-12T12:00:00.000Z",
                "last_success_at": "2026-08-12T12:00:00.000Z",
                "last_error": "",
                "window": dict(self.window),
                "source_statuses": statuses,
                "complete": True,
                "osquery_ready": 3,
            },
            "records": [self.record()],
        }

    def test_state_projection_empty_success_and_optional_field_are_exact(self) -> None:
        empty = normalization.empty_state()
        self.assertEqual(normalization.validate_state(empty), empty)
        state = self.success_state()
        self.assertEqual(normalization.validate_state(state), state)

    def test_state_rejection_precedence_and_messages_are_exact(self) -> None:
        state = self.success_state()
        cases = (
            (None, "state has an invalid shape"),
            ({**state, "extra": True}, "state has an invalid shape"),
            ({**state, "version": 2}, "state schema is unsupported"),
            ({**state, "collection": None}, "collection metadata is invalid"),
            ({**state, "collection": {**state["collection"], "status": "bad"}}, "collection status is unsupported"),
            ({**state, "collection": {**state["collection"], "complete": "yes"}}, "collection completeness is invalid"),
            ({**state, "collection": {**state["collection"], "source_statuses": {}}}, "source status roster is invalid"),
            ({**state, "collection": {**state["collection"], "complete": False}}, "successful software inventory state is incomplete"),
            ({**state, "records": "bad"}, "state record list is invalid"),
        )
        for value, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    normalization.validate_state(value)

        duplicate = json.loads(json.dumps(state))
        duplicate["records"].append(json.loads(json.dumps(state["records"][0])))
        with self.assertRaisesRegex(ValueError, "duplicate evidence"):
            normalization.validate_state(duplicate)

        bad_ready = json.loads(json.dumps(state))
        bad_ready["collection"]["osquery_ready"] = True
        with self.assertRaisesRegex(ValueError, "must be an integer"):
            normalization.validate_state(bad_ready)


if __name__ == "__main__":
    unittest.main()
