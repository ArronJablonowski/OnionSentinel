"""Characterize exact alert-tuple normalization for authorization evidence."""
from __future__ import annotations

import copy
import datetime as dt
import unittest
from unittest.mock import patch

from n8n.onion_sentinel.analysis.conclusions import authorization_evidence


class TrackingDict(dict):
    def __init__(self, *args: object, trace: list[object], label: str, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.trace = trace
        self.label = label

    def get(self, key: object, default: object = None) -> object:
        self.trace.append(("get", self.label, key, default))
        return super().get(key, default)


class AuthorizationPromptEventTests(unittest.TestCase):
    def test_non_mapping_alert_fails_before_normalization(self) -> None:
        for alert in (None, [], "alert", 7):
            with self.subTest(alert=alert):
                with patch.object(
                    authorization_evidence, "_alert_timestamp"
                ) as timestamp:
                    self.assertIsNone(
                        authorization_evidence.prompt_event({"alert": alert})
                    )
                    timestamp.assert_not_called()

    def test_normalizer_and_mapping_access_order_return_shape_are_exact(self) -> None:
        trace: list[object] = []
        timestamp = dt.datetime(2026, 7, 24, 18, 30, tzinfo=dt.timezone.utc)
        alert = TrackingDict(
            {
                "rule_id": " Rule-1 ",
                "transport_protocol": " TCP ",
                "network_protocol": "udp",
            },
            trace=trace,
            label="alert",
        )
        prompt = TrackingDict({"alert": alert}, trace=trace, label="prompt")

        def alert_timestamp(actual):
            trace.append(("timestamp", actual))
            return timestamp

        def address(actual, key):
            trace.append(("address", actual, key))
            return "192.0.2.1" if key == "source_ip" else "198.51.100.2"

        def port(actual, key):
            trace.append(("port", actual, key))
            return 49152 if key == "source_port" else 443

        with (
            patch.object(authorization_evidence, "_alert_timestamp", alert_timestamp),
            patch.object(authorization_evidence, "_address", address),
            patch.object(authorization_evidence, "_port", port),
        ):
            event = authorization_evidence.prompt_event(prompt)

        self.assertEqual(event, {
            "timestamp": timestamp,
            "source_ip": "192.0.2.1",
            "destination_ip": "198.51.100.2",
            "source_port": 49152,
            "destination_port": 443,
            "rule_id": "rule-1",
            "transport": "tcp",
        })
        self.assertIs(event["timestamp"], timestamp)
        self.assertEqual(trace, [
            ("get", "prompt", "alert", None),
            ("timestamp", alert),
            ("address", alert, "source_ip"),
            ("address", alert, "destination_ip"),
            ("port", alert, "source_port"),
            ("port", alert, "destination_port"),
            ("get", "alert", "rule_id", None),
            ("get", "alert", "transport_protocol", None),
        ])

    def test_transport_truthiness_fallback_and_input_non_mutation_are_exact(self) -> None:
        base = {
            "timestamp": "2026-07-24T18:30:00Z",
            "source_ip": "192.0.2.1",
            "destination_ip": "198.51.100.2",
            "source_port": "",
            "destination_port": 443,
            "rule_id": "rule-1",
            "transport_protocol": "",
            "network_protocol": " UDP ",
        }
        prompt = {"alert": copy.deepcopy(base)}
        snapshot = copy.deepcopy(prompt)

        event = authorization_evidence.prompt_event(prompt)

        self.assertEqual(event["transport"], "udp")
        self.assertIsNone(event["source_port"])
        self.assertEqual(prompt, snapshot)

    def test_validation_short_circuit_and_helper_exceptions_are_exact(self) -> None:
        alert = {
            "rule_id": "rule-1",
            "transport_protocol": "tcp",
        }
        with (
            patch.object(authorization_evidence, "_alert_timestamp", return_value=None),
            patch.object(authorization_evidence, "_address", return_value="192.0.2.1"),
            patch.object(authorization_evidence, "_port", return_value=443),
            patch.object(authorization_evidence.re, "fullmatch") as fullmatch,
        ):
            self.assertIsNone(authorization_evidence.prompt_event({"alert": alert}))
            fullmatch.assert_not_called()

        with patch.object(
            authorization_evidence,
            "_alert_timestamp",
            side_effect=RuntimeError("timestamp normalization failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "timestamp normalization failed"):
                authorization_evidence.prompt_event({"alert": alert})

        class ExplodingPrompt(dict):
            def get(self, key: object, default: object = None) -> object:
                raise LookupError("prompt alert access failed")

        with self.assertRaisesRegex(LookupError, "prompt alert access failed"):
            authorization_evidence.prompt_event(ExplodingPrompt())


if __name__ == "__main__":
    unittest.main()
