"""Behavior contracts for the report-portal HTTP compatibility adapter."""
from __future__ import annotations

import importlib
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

adapter = importlib.import_module("portal_http_handler")


class _Headers:
    def __init__(self, values: dict[str, object], trace: list[tuple[str, str]]) -> None:
        self.values = values
        self.trace = trace

    def get(self, name: str) -> object:
        self.trace.append(("header", name))
        return self.values.get(name)


class PortalHttpHandlerTests(unittest.TestCase):
    def test_soc_review_write_authorization_matrix_and_trace_are_exact(self) -> None:
        cases = (
            ({}, False, ("Content-Type",), ()),
            ({"Content-Type": "text/plain"}, False, ("Content-Type",), ()),
            (
                {"Content-Type": " application/json", "X-Onion-Sentinel-Request": "dashboard"},
                False,
                ("Content-Type",),
                (),
            ),
            (
                {"Content-Type": "application/json", "X-Onion-Sentinel-Request": "Dashboard"},
                False,
                ("Content-Type", "X-Onion-Sentinel-Request"),
                (),
            ),
            (
                {
                    "Content-Type": "application/json",
                    "X-Onion-Sentinel-Request": "dashboard",
                    "Sec-Fetch-Site": "cross-site",
                },
                False,
                ("Content-Type", "X-Onion-Sentinel-Request", "Sec-Fetch-Site"),
                (),
            ),
            (
                {
                    "Content-Type": "Application/JSON; Charset=UTF-8",
                    "X-Onion-Sentinel-Request": "dashboard",
                    "Sec-Fetch-Site": " SAME-ORIGIN ",
                },
                True,
                ("Content-Type", "X-Onion-Sentinel-Request", "Sec-Fetch-Site", "Origin"),
                (),
            ),
            (
                {
                    "Content-Type": "application/json",
                    "X-Onion-Sentinel-Request": "dashboard",
                    "Origin": "   ",
                },
                True,
                ("Content-Type", "X-Onion-Sentinel-Request", "Sec-Fetch-Site", "Origin"),
                (),
            ),
            (
                {
                    "Content-Type": "application/json-patch+json",
                    "X-Onion-Sentinel-Request": "dashboard",
                    "Origin": "HTTPS://Portal.Example:8766",
                    "Host": " PORTAL.EXAMPLE:8766 ",
                },
                True,
                (
                    "Content-Type", "X-Onion-Sentinel-Request", "Sec-Fetch-Site",
                    "Origin", "Host",
                ),
                ("HTTPS://Portal.Example:8766",),
            ),
            (
                {
                    "Content-Type": "application/json",
                    "X-Onion-Sentinel-Request": "dashboard",
                    "Origin": "ftp://portal.example",
                    "Host": "portal.example",
                },
                False,
                (
                    "Content-Type", "X-Onion-Sentinel-Request", "Sec-Fetch-Site",
                    "Origin", "Host",
                ),
                ("ftp://portal.example",),
            ),
            (
                {
                    "Content-Type": "application/json",
                    "X-Onion-Sentinel-Request": "dashboard",
                    "Origin": "/relative",
                    "Host": "portal.example",
                },
                False,
                (
                    "Content-Type", "X-Onion-Sentinel-Request", "Sec-Fetch-Site",
                    "Origin", "Host",
                ),
                ("/relative",),
            ),
            (
                {
                    "Content-Type": "application/json",
                    "X-Onion-Sentinel-Request": "dashboard",
                    "Origin": "https://portal.example",
                    "Host": "other.example",
                },
                False,
                (
                    "Content-Type", "X-Onion-Sentinel-Request", "Sec-Fetch-Site",
                    "Origin", "Host",
                ),
                ("https://portal.example",),
            ),
        )
        for values, expected, expected_headers, expected_origins in cases:
            with self.subTest(values=values):
                trace: list[tuple[str, str]] = []

                def parse_origin(value: str):
                    trace.append(("urlparse", value))
                    return urlparse(value)

                handler = SimpleNamespace(headers=_Headers(values, trace))
                runtime = SimpleNamespace(urlparse=parse_origin)

                result = adapter._soc_review_write_authorized(handler, runtime)

                self.assertIs(result, expected)
                self.assertEqual(
                    tuple(value for kind, value in trace if kind == "header"),
                    expected_headers,
                )
                self.assertEqual(
                    tuple(value for kind, value in trace if kind == "urlparse"),
                    expected_origins,
                )


if __name__ == "__main__":
    unittest.main()
