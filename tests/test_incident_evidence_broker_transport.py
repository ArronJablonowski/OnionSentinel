from __future__ import annotations

import copy
import importlib.machinery
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
RELAY_APP = ROOT / "relay" / "app"
BROKER = RELAY_APP / "incident_evidence_broker.py"
if str(RELAY_APP) not in sys.path:
    sys.path.insert(0, str(RELAY_APP))


def load_broker():
    loader = importlib.machinery.SourceFileLoader(
        "incident_evidence_broker_transport_test",
        str(BROKER),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class IncidentEvidenceBrokerTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.broker = load_broker()

    def audited_envelope(self, payload: dict | None = None) -> dict:
        value = payload if payload is not None else {"operation": "incident_evidence"}
        return {
            "transport_contract": self.broker.TRANSPORT_AUDIT_CONTRACT,
            "correlation_id": "c" * 32,
            "request_digest": self.broker._canonical_digest(value),
            "payload": value,
        }

    def response(self, *, complete: object = True) -> tuple[dict, dict]:
        audit = {
            "transport_contract": self.broker.TRANSPORT_AUDIT_CONTRACT,
            "correlation_id": "c" * 32,
            "request_digest": "d" * 64,
        }
        response = {"ok": True, "complete": complete, "results": []}
        response["audit_receipt"] = {
            "receipt_contract": self.broker.TRANSPORT_RECEIPT_CONTRACT,
            "correlation_id": audit["correlation_id"],
            "request_digest": audit["request_digest"],
            "response_payload_digest": self.broker._canonical_digest(response),
            "elastic_search_count": 0,
            "osquery_query_count": 0,
            "helper_invocation_count": 0,
            "read_only": True,
            "terminal_status": "complete" if complete is True else "partial",
        }
        return response, audit

    def test_audited_and_legacy_transport_projection_is_exact(self) -> None:
        envelope = self.audited_envelope()
        payload, transported = self.broker._transport_envelope(envelope)
        self.assertIs(payload, envelope["payload"])
        self.assertEqual(transported, envelope)

        generated = mock.Mock(hex="a" * 32)
        legacy = {"operation": "incident_evidence", "hours": 1}
        with mock.patch.object(self.broker.uuid, "uuid4", return_value=generated):
            payload, transported = self.broker._transport_envelope(legacy)
        self.assertIs(payload, legacy)
        self.assertEqual(
            transported,
            {
                "transport_contract": self.broker.TRANSPORT_AUDIT_CONTRACT,
                "correlation_id": "a" * 32,
                "request_digest": self.broker._canonical_digest(legacy),
                "payload": legacy,
            },
        )

    def test_transport_rejection_precedence_and_messages_are_exact(self) -> None:
        invalid_cases = (
            (None, "request root must be an object"),
            (
                {**self.audited_envelope(), "extra": True},
                "transport envelope fields are invalid",
            ),
            (
                {**self.audited_envelope(), "correlation_id": "invalid"},
                "transport envelope failed validation",
            ),
            (
                {**self.audited_envelope(), "request_digest": "0" * 64},
                "transport envelope failed validation",
            ),
        )
        for value, message in invalid_cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    self.broker._transport_envelope(value)

        oversized = {"value": "x" * self.broker.MAX_REQUEST_BYTES}
        with self.assertRaisesRegex(
            ValueError,
            "request payload exceeds the broker byte limit",
        ):
            self.broker._transport_envelope(oversized)

    def test_receipt_identity_accepts_exact_binding(self) -> None:
        response, audit = self.response()
        receipt = response["audit_receipt"]
        self.assertIs(self.broker._receipt_identity(response, audit), receipt)

        response, audit = self.response(complete="truthy")
        self.assertEqual(
            self.broker._receipt_identity(response, audit)["terminal_status"],
            "partial",
        )

    def test_receipt_rejection_precedence_and_messages_are_exact(self) -> None:
        response, audit = self.response()
        missing = copy.deepcopy(response)
        missing.pop("audit_receipt")
        with self.assertRaisesRegex(
            ValueError,
            "Security Onion response omitted its audit receipt",
        ):
            self.broker._receipt_identity(missing, audit)

        malformed = copy.deepcopy(response)
        malformed["audit_receipt"]["extra"] = True
        with self.assertRaisesRegex(
            ValueError,
            "Security Onion response omitted its audit receipt",
        ):
            self.broker._receipt_identity(malformed, audit)

        mutators = (
            lambda receipt: receipt.update(correlation_id="e" * 32),
            lambda receipt: receipt.update(request_digest="e" * 64),
            lambda receipt: receipt.update(response_payload_digest="e" * 64),
            lambda receipt: receipt.update(read_only=1),
            lambda receipt: receipt.update(terminal_status="partial"),
            lambda receipt: receipt.update(elastic_search_count=True),
            lambda receipt: receipt.update(osquery_query_count=-1),
        )
        for mutate in mutators:
            invalid = copy.deepcopy(response)
            mutate(invalid["audit_receipt"])
            with self.subTest(receipt=json.dumps(invalid["audit_receipt"], sort_keys=True)):
                with self.assertRaisesRegex(
                    ValueError,
                    "Security Onion audit receipt failed validation",
                ):
                    self.broker._receipt_identity(invalid, audit)


if __name__ == "__main__":
    unittest.main()
