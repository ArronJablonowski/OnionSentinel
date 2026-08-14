#!/usr/bin/env python3
"""Contracts for late-bound portal settings runtime helpers."""
from __future__ import annotations

from pathlib import Path
import sys
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_settings_runtime import maxmind_geoip_database_status  # noqa: E402


class TrackingSettings(dict):
    def __init__(self, events, *args, **kwargs):
        self.events = events
        super().__init__(*args, **kwargs)

    def get(self, key, default=None):
        self.events.append(("settings.get", key, default))
        return super().get(key, default)


class IsoString(str):
    def __new__(cls, value, events):
        instance = super().__new__(cls, value)
        instance.events = events
        return instance

    def replace(self, old, new, count=-1):
        self.events.append(("timestamp.replace", old, new, count))
        return super().replace(old, new, count)


class DateValue:
    def __init__(self, events):
        self.events = events

    def astimezone(self):
        self.events.append(("timestamp.astimezone",))
        return self

    def isoformat(self):
        self.events.append(("timestamp.isoformat",))
        return IsoString("2026-08-13T20:00:00-06:00", self.events)


class PathValue:
    def __init__(self, configured, events, *, stat_result=None, stat_error=None,
                 is_file=True):
        self.configured = configured
        self.events = events
        self.stat_result = stat_result or SimpleNamespace(st_size=321, st_mtime=456.0)
        self.stat_error = stat_error
        self.is_file_value = is_file

    def expanduser(self):
        self.events.append(("path.expanduser", self.configured))
        return self

    @property
    def name(self):
        self.events.append(("path.name",))
        return "GeoLite.mmdb"

    def stat(self):
        self.events.append(("path.stat",))
        if self.stat_error is not None:
            raise self.stat_error
        return self.stat_result

    def is_file(self):
        self.events.append(("path.is_file",))
        return self.is_file_value


class MaxMindStatusTests(unittest.TestCase):
    def runtime(
        self,
        events,
        *,
        stat_error=None,
        is_file=True,
        readable=True,
    ):
        path_holder = {}

        def path(configured):
            events.append(("Path", configured))
            value = PathValue(
                configured,
                events,
                stat_error=stat_error,
                is_file=is_file,
            )
            path_holder["value"] = value
            return value

        def access(value, mode):
            events.append(("os.access", value is path_holder["value"], mode))
            return readable

        def fromtimestamp(value):
            events.append(("datetime.fromtimestamp", value))
            return DateValue(events)

        return SimpleNamespace(
            MAXMIND_GEOIP_DATABASE_SETTINGS={
                "asn": ("maxmind_geoip_asn_db_path", "/default/asn.mmdb"),
                "city": ("maxmind_geoip_city_db_path", "/default/city.mmdb"),
                "country": (
                    "maxmind_geoip_country_db_path",
                    "/default/country.mmdb",
                ),
            },
            Path=path,
            os=SimpleNamespace(R_OK=4, access=access),
            dt=SimpleNamespace(
                datetime=SimpleNamespace(fromtimestamp=fromtimestamp),
            ),
        )

    def test_unsupported_type_fails_before_settings_or_path_access(self) -> None:
        events = []
        settings = TrackingSettings(events)
        with self.assertRaisesRegex(
            ValueError,
            "Unsupported MaxMind database type: continent",
        ):
            maxmind_geoip_database_status(
                self.runtime(events), settings, "continent"
            )
        self.assertEqual(events, [])

    def test_configured_path_precedence_and_city_legacy_fallback(self) -> None:
        cases = (
            (
                "asn",
                {"maxmind_geoip_asn_db_path": "  ~/asn.mmdb  "},
                "~/asn.mmdb",
                ["maxmind_geoip_asn_db_path"],
            ),
            (
                "city",
                {
                    "maxmind_geoip_city_db_path": " ",
                    "maxmind_geoip_db_path": "  ~/legacy.mmdb ",
                },
                "~/legacy.mmdb",
                ["maxmind_geoip_city_db_path", "maxmind_geoip_db_path"],
            ),
            (
                "city",
                {
                    "maxmind_geoip_city_db_path": " /specific.mmdb ",
                    "maxmind_geoip_db_path": "/legacy.mmdb",
                },
                "/specific.mmdb",
                ["maxmind_geoip_city_db_path"],
            ),
            (
                "country",
                {"maxmind_geoip_country_db_path": ""},
                "/default/country.mmdb",
                ["maxmind_geoip_country_db_path"],
            ),
        )
        for database_type, values, expected, keys in cases:
            with self.subTest(database_type=database_type, expected=expected):
                events = []
                result = maxmind_geoip_database_status(
                    self.runtime(events, stat_error=FileNotFoundError()),
                    TrackingSettings(events, values),
                    database_type,
                )
                self.assertEqual(result["configured_path"], expected)
                self.assertEqual(
                    [event[1] for event in events if event[0] == "settings.get"],
                    keys,
                )
                self.assertIn(("Path", expected), events)

    def test_missing_and_unreadable_states_preserve_short_circuit_order(self) -> None:
        cases = (
            (
                FileNotFoundError("missing"),
                True,
                True,
                "missing",
                ["settings.get", "Path", "path.expanduser", "path.name", "path.stat"],
            ),
            (
                PermissionError("denied"),
                True,
                True,
                "unreadable",
                ["settings.get", "Path", "path.expanduser", "path.name", "path.stat"],
            ),
            (
                None,
                False,
                True,
                "unreadable",
                [
                    "settings.get", "Path", "path.expanduser", "path.name",
                    "path.stat", "path.is_file",
                ],
            ),
            (
                None,
                True,
                False,
                "unreadable",
                [
                    "settings.get", "Path", "path.expanduser", "path.name",
                    "path.stat", "path.is_file", "os.access",
                ],
            ),
        )
        for error, is_file, readable, state, names in cases:
            with self.subTest(state=state, error=error, is_file=is_file):
                events = []
                result = maxmind_geoip_database_status(
                    self.runtime(
                        events,
                        stat_error=error,
                        is_file=is_file,
                        readable=readable,
                    ),
                    TrackingSettings(events, {}),
                    "asn",
                )
                self.assertEqual(result["state"], state)
                self.assertEqual([event[0] for event in events], names)
                self.assertEqual(
                    list(result),
                    [
                        "database_type", "setting_key", "state",
                        "configured_path", "filename",
                    ],
                )

    def test_ready_status_preserves_timestamp_chain_and_key_order(self) -> None:
        events = []
        result = maxmind_geoip_database_status(
            self.runtime(events),
            TrackingSettings(events, {"maxmind_geoip_asn_db_path": "/db.mmdb"}),
            "asn",
        )

        self.assertEqual(
            result,
            {
                "database_type": "asn",
                "setting_key": "maxmind_geoip_asn_db_path",
                "state": "ready",
                "configured_path": "/db.mmdb",
                "filename": "GeoLite.mmdb",
                "size_bytes": 321,
                "modified_at": "2026-08-13  20:00:00-06:00",
            },
        )
        self.assertEqual(
            [event[0] for event in events],
            [
                "settings.get", "Path", "path.expanduser", "path.name",
                "path.stat", "path.is_file", "os.access",
                "datetime.fromtimestamp", "timestamp.astimezone",
                "timestamp.isoformat", "timestamp.replace",
            ],
        )
        self.assertIn(("os.access", True, 4), events)


if __name__ == "__main__":
    unittest.main()
