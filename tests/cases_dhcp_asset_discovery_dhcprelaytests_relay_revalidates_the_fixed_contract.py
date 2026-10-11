from __future__ import annotations

from dhcp_asset_discovery_fixtures import (
    BROKER,
    BUILDER,
    COLLECTOR,
    INSTALLER,
    PORTAL,
    PROMOTER,
    Path,
    QUERY_CLIENT,
    ROOT,
    SimpleNamespace,
    WRAPPER,
    contextlib,
    dt,
    hashlib,
    importlib,
    inspect,
    io,
    json,
    load_module,
    mock,
    shutil,
    stat,
    subprocess,
    sys,
    tempfile,
    unittest,
)

class DhcpRelayTestsRelayRevalidatesTheFixedContractCases:
    def test_relay_revalidates_the_fixed_contract(self) -> None:
        request = {
            "contract": self.broker.DHCP_DISCOVERY_CONTRACT,
            "operation": "dhcp_observations",
            "window": {
                "start": "2026-07-29T17:00:00Z",
                "end": "2026-07-29T17:15:00Z",
            },
            "size": 500,
        }
        self.broker.validate_dhcp_request(request)
        with self.assertRaises(ValueError):
            self.broker.validate_dhcp_request({**request, "index": "*"})


    def test_relay_rejection_precedence_and_messages_are_exact(self) -> None:
        request = {
            "contract": self.broker.DHCP_DISCOVERY_CONTRACT,
            "operation": self.broker.DHCP_DISCOVERY_OPERATION,
            "window": {
                "start": "2026-07-29T17:00:00Z",
                "end": "2026-07-29T17:15:00Z",
            },
            "size": 500,
        }
        cases = (
            (None, "request fields do not match the DHCP discovery contract"),
            (
                {**request, "extra": True},
                "request fields do not match the DHCP discovery contract",
            ),
            (
                {**request, "contract": "unsupported", "window": None},
                "unsupported DHCP discovery operation",
            ),
            (
                {**request, "window": []},
                "invalid DHCP discovery window",
            ),
            (
                {**request, "window": {**request["window"], "extra": True}},
                "invalid DHCP discovery window",
            ),
            (
                {
                    **request,
                    "window": {
                        "start": "2026-07-29T17:00:00",
                        "end": "2026-07-29T17:15:00Z",
                    },
                },
                "timestamp lacks offset",
            ),
            (
                {
                    **request,
                    "window": {
                        "start": "2026-07-29T17:15:00Z",
                        "end": "2026-07-29T17:15:00Z",
                    },
                },
                "DHCP discovery window must be positive and no longer than 24 hours",
            ),
            (
                {
                    **request,
                    "window": {
                        "start": "2026-07-28T17:14:59Z",
                        "end": "2026-07-29T17:15:00Z",
                    },
                },
                "DHCP discovery window must be positive and no longer than 24 hours",
            ),
            (
                {**request, "size": True},
                "DHCP discovery size must be from 1 through 1000",
            ),
            (
                {**request, "size": 1001},
                "DHCP discovery size must be from 1 through 1000",
            ),
        )
        for value, message in cases:
            with self.subTest(message=message, value=value):
                with self.assertRaisesRegex(ValueError, message):
                    self.broker.validate_dhcp_request(value)
