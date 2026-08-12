from __future__ import annotations

import base64
import copy
import importlib
import inspect
import json
import sys
import unittest
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
BASELINE = ROOT / "operations/quality/module-quality-baseline.json"


def load_transport_module():
    if str(DASHBOARD) not in sys.path:
        sys.path.insert(0, str(DASHBOARD))
    return importlib.import_module("ac_hunter_transport")


def jwt(expiry: object) -> str:
    def encoded(value: Mapping[str, object]) -> str:
        raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return "e30.%s.synthetic-signature" % encoded({"exp": expiry})


class TraceLock:
    def __init__(self, events: List[object]) -> None:
        self.events = events

    def __enter__(self):
        self.events.append("lock.enter")
        return self

    def __exit__(self, exc_type, _exc, _traceback) -> bool:
        self.events.append(
            ["lock.exit", None if exc_type is None else exc_type.__name__]
        )
        return False


class SequenceTransport:
    def __init__(
        self,
        events: List[object],
        responses: Mapping[str, object],
    ) -> None:
        self.events = events
        self.responses = dict(responses)
        self.calls: List[Tuple[str, Dict[str, object]]] = []
        self.client = None

    def call(self, operation: str, **kwargs: object) -> Dict[str, object]:
        assert self.client is not None
        copied = copy.deepcopy(kwargs)
        self.calls.append((operation, copied))
        self.events.append(
            [
                "transport",
                operation,
                {
                    "jwt": self.client._jwt,
                    "expiry": self.client._jwt_expiry,
                    "cookies": dict(self.client._cookies),
                },
            ]
        )
        response = self.responses[operation]
        if isinstance(response, list):
            response = response.pop(0)
        if isinstance(response, BaseException):
            raise response
        return copy.deepcopy(response)


class AcHunterAuthenticationArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.transport_module = load_transport_module()

    def client(
        self,
        responses: Mapping[str, object],
        *,
        now: float = 1_800_000_000.0,
        clock_values: Optional[List[float]] = None,
    ):
        events: List[object] = []
        transport = SequenceTransport(events, responses)
        credentials_calls: List[object] = []

        def credentials() -> Tuple[str, str]:
            credentials_calls.append("credentials")
            events.append("credentials")
            return "service@example.invalid", "synthetic-secret"

        values = list(clock_values or [now, now, now, now])

        def clock() -> float:
            events.append("clock")
            return values.pop(0)

        client = self.transport_module.AcHunterApiClient(
            transport,
            credentials,
            clock=clock,
        )
        client._auth_lock = TraceLock(events)
        transport.client = client
        return client, transport, events, credentials_calls

    @staticmethod
    def responses(
        expiry: object,
        *,
        form_ok: bool = True,
        login_ok: bool = True,
        jwt_ok: bool = True,
        token: Optional[object] = None,
    ) -> Dict[str, Dict[str, object]]:
        return {
            "login_form": {
                "ok": form_ok,
                "status": 200 if form_ok else 503,
                "headers": {
                    "set_cookie": ["session=preauth; Secure; HttpOnly; Path=/"]
                },
                "body": (
                    '<form><input value="csrf-value" name="csrf_token"></form>'
                ),
            },
            "login": {
                "ok": login_ok,
                "status": 303 if login_ok else 401,
                "headers": {
                    "set_cookie": [
                        "session=authenticated; Secure; HttpOnly; Path=/",
                        "secondary=bounded; Secure; Path=/",
                    ]
                },
                "body": None,
            },
            "jwt": {
                "ok": jwt_ok,
                "status": 200 if jwt_ok else 403,
                "headers": {"set_cookie": ["secondary=final; Secure; Path=/"]},
                "body": {"token": jwt(expiry) if token is None else token},
            },
        }

    def test_signature_current_quality_debt_and_fresh_token_short_circuit(self) -> None:
        signature = inspect.signature(
            self.transport_module.AcHunterApiClient._authenticate
        )
        self.assertEqual(list(signature.parameters), ["self"])
        self.assertEqual(str(signature.return_annotation), "None")
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        self.assertNotIn(
            "onion-sentinel-dashboard/ac_hunter_transport.py::"
            "AcHunterApiClient._authenticate",
            baseline["functions"],
        )

        client, transport, events, credentials = self.client({})
        client._jwt = jwt(1_800_000_300.0)
        client._jwt_expiry = 1_800_000_300.0
        client._cookies = {"session": "authenticated"}
        before = (client._jwt, client._jwt_expiry, dict(client._cookies))
        client._authenticate()
        self.assertEqual(
            (client._jwt, client._jwt_expiry, client._cookies), before
        )
        self.assertEqual(events, ["lock.enter", "clock", ["lock.exit", None]])
        self.assertEqual(transport.calls, [])
        self.assertEqual(credentials, [])

    def test_successful_flow_preserves_exact_state_call_order_and_payloads(self) -> None:
        now = 1_800_000_000.0
        client, transport, events, credentials = self.client(
            self.responses(now + 300), now=now
        )
        client._jwt = "expired-token"
        client._jwt_expiry = now - 1
        client._cookies = {"z-old": "must-clear"}

        client._authenticate()

        self.assertEqual(credentials, ["credentials"])
        self.assertEqual(
            [event[0] if isinstance(event, list) else event for event in events],
            [
                "lock.enter",
                "clock",
                "transport",
                "credentials",
                "transport",
                "transport",
                "clock",
                "lock.exit",
            ],
        )
        self.assertEqual([name for name, _kwargs in transport.calls], [
            "login_form", "login", "jwt"
        ])
        self.assertEqual(transport.calls[0][1], {})
        self.assertEqual(
            transport.calls[1][1],
            {
                "headers": {"cookie": "session=preauth"},
                "body": {
                    "email": "service@example.invalid",
                    "password": "synthetic-secret",
                    "csrf_token": "csrf-value",
                    "next": "/jwt/json",
                    "remember": False,
                },
            },
        )
        self.assertEqual(
            transport.calls[2][1],
            {"headers": {"cookie": "secondary=bounded; session=authenticated"}},
        )
        first_snapshot = events[2][2]
        self.assertEqual(
            first_snapshot,
            {"jwt": "", "expiry": 0.0, "cookies": {}},
        )
        self.assertEqual(client._cookies, {
            "secondary": "final", "session": "authenticated"
        })
        self.assertEqual(client._jwt, jwt(now + 300))
        self.assertEqual(client._jwt_expiry, now + 300)
        self.assertFalse(
            hasattr(client, "password") or hasattr(client, "credentials")
        )

    def test_failure_boundaries_preserve_short_circuiting_and_partial_state(self) -> None:
        now = 1_800_000_000.0
        cases = [
            (
                "form",
                self.responses(now + 300, form_ok=False),
                "AC Hunter login form was unavailable",
                ["login_form"],
                0,
                {"session": "preauth"},
            ),
            (
                "login",
                self.responses(now + 300, login_ok=False),
                "AC Hunter service-account login failed",
                ["login_form", "login"],
                1,
                {"secondary": "bounded", "session": "authenticated"},
            ),
            (
                "jwt",
                self.responses(now + 300, jwt_ok=False),
                "AC Hunter JWT issuance failed",
                ["login_form", "login", "jwt"],
                1,
                {"secondary": "final", "session": "authenticated"},
            ),
            (
                "token-type",
                self.responses(now + 300, token=123),
                "AC Hunter JWT issuance returned an invalid token",
                ["login_form", "login", "jwt"],
                1,
                {"secondary": "final", "session": "authenticated"},
            ),
            (
                "token-expiry",
                self.responses(now + 5),
                "AC Hunter JWT expiry is outside the expected window",
                ["login_form", "login", "jwt"],
                1,
                {"secondary": "final", "session": "authenticated"},
            ),
        ]
        for (
            label,
            responses,
            message,
            operations,
            credential_count,
            cookies,
        ) in cases:
            with self.subTest(label=label):
                client, transport, events, credentials = self.client(
                    responses, now=now
                )
                client._jwt = "stale"
                client._jwt_expiry = now - 1
                client._cookies = {"old": "cleared"}
                with self.assertRaisesRegex(
                    self.transport_module.AcHunterAuthenticationError,
                    message,
                ) as raised:
                    client._authenticate()
                self.assertIsNone(raised.exception.__cause__)
                self.assertEqual(
                    [name for name, _kwargs in transport.calls], operations
                )
                self.assertEqual(len(credentials), credential_count)
                self.assertEqual(client._jwt, "")
                self.assertEqual(client._jwt_expiry, 0.0)
                self.assertEqual(client._cookies, cookies)
                self.assertEqual(events[0], "lock.enter")
                self.assertEqual(
                    events[-1], ["lock.exit", "AcHunterAuthenticationError"]
                )

    def test_token_payload_errors_retain_cause_and_clock_is_not_called(self) -> None:
        invalid_payload = "e30.bm90LWpzb24.synthetic-signature"
        client, transport, events, credentials = self.client(
            self.responses(1_800_000_300.0, token=invalid_payload)
        )
        with self.assertRaisesRegex(
            self.transport_module.AcHunterAuthenticationError,
            "AC Hunter returned an invalid JWT",
        ) as raised:
            client._authenticate()
        self.assertIsInstance(raised.exception.__cause__, json.JSONDecodeError)
        self.assertEqual(credentials, ["credentials"])
        self.assertEqual(
            [name for name, _kwargs in transport.calls],
            ["login_form", "login", "jwt"],
        )
        self.assertNotIn("clock", events)
        self.assertEqual(client._jwt, "")
        self.assertEqual(client._jwt_expiry, 0.0)

    def test_empty_csrf_cookie_headers_and_upper_expiry_bound_are_exact(self) -> None:
        now = 1_800_000_000.0
        responses = self.responses(now + 15 * 60)
        responses["login_form"]["headers"] = {"set_cookie": []}
        responses["login_form"]["body"] = object()
        responses["login"]["headers"] = {"set_cookie": []}
        responses["jwt"]["headers"] = {"set_cookie": []}
        client, transport, _events, _credentials = self.client(
            responses, now=now
        )
        client._authenticate()
        self.assertEqual(
            transport.calls[1][1]["headers"], {}
        )
        self.assertEqual(
            transport.calls[1][1]["body"]["csrf_token"], ""
        )
        self.assertEqual(transport.calls[2][1]["headers"], {})
        self.assertEqual(client._jwt_expiry, now + 15 * 60)
        self.assertEqual(client._cookies, {})


if __name__ == "__main__":
    unittest.main()
