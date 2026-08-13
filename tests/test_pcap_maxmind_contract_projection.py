"""Characterize PCAP MaxMind configuration and compact projection."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n/bin/pcap_processor_contract.py"


def load_contract(name: str):
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("PCAP processor contract cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PcapMaxmindContractProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.contract = load_contract(f"pcap_maxmind_projection_{id(self)}")
        self.defaults = {
            "asn": self.root / "defaults/asn.mmdb",
            "city": self.root / "defaults/city.mmdb",
            "country": self.root / "defaults/country.mmdb",
        }
        self.contract.DEFAULT_MAXMIND_DBS = self.defaults

    def tearDown(self):
        self.temp.cleanup()

    def _settings(self, payload) -> Path:
        path = self.root / "settings.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_missing_invalid_and_non_object_settings_preserve_defaults(self):
        cases = (
            self.root / "missing.json",
            self.root / "invalid.json",
            self._settings(["not", "an", "object"]),
        )
        (self.root / "invalid.json").write_text("{", encoding="utf-8")
        with mock.patch.dict(os.environ, {}, clear=True):
            for path in cases:
                with self.subTest(path=path.name):
                    result = self.contract.configured_maxmind_db_paths(path)
                    self.assertEqual(result, self.defaults)
                    self.assertEqual(list(result), ["asn", "city", "country"])
                    self.assertTrue(all(isinstance(value, Path) for value in result.values()))

    def test_typed_environment_settings_and_defaults_keep_exact_precedence(self):
        settings = self._settings(
            {
                "maxmind_geoip_db_path": " /settings/legacy-city.mmdb ",
                "maxmind_geoip_asn_db_path": " ~/settings-asn.mmdb ",
                "maxmind_geoip_city_db_path": " /settings/city.mmdb ",
                "maxmind_geoip_country_db_path": " /settings/country.mmdb ",
            }
        )
        environment = {
            "MAXMIND_GEOIP_DB_PATH": " /environment/legacy-city.mmdb ",
            "MAXMIND_GEOIP_ASN_DB_PATH": " /environment/asn.mmdb ",
            "MAXMIND_GEOIP_COUNTRY_DB_PATH": " /environment/country.mmdb ",
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            result = self.contract.configured_maxmind_db_paths(settings)
        self.assertEqual(
            result,
            {
                "asn": Path("/environment/asn.mmdb"),
                "city": Path("/settings/city.mmdb"),
                "country": Path("/environment/country.mmdb"),
            },
        )
        environment["MAXMIND_GEOIP_CITY_DB_PATH"] = "  "
        with mock.patch.dict(os.environ, environment, clear=True):
            whitespace_environment = self.contract.configured_maxmind_db_paths(
                settings
            )
        self.assertEqual(
            whitespace_environment["city"],
            Path("/environment/legacy-city.mmdb"),
        )

    def test_city_legacy_migration_and_single_path_facade_are_exact(self):
        settings = self._settings(
            {"maxmind_geoip_db_path": " ~/legacy-city.mmdb "}
        )
        with mock.patch.dict(os.environ, {}, clear=True):
            result = self.contract.configured_maxmind_db_paths(settings)
        self.assertEqual(result["asn"], self.defaults["asn"])
        self.assertEqual(result["city"], Path.home() / "legacy-city.mmdb")
        self.assertEqual(result["country"], self.defaults["country"])

        with mock.patch.object(
            self.contract,
            "configured_maxmind_db_paths",
            return_value={"city": Path("/synthetic/city.mmdb")},
        ) as configured:
            self.assertEqual(
                self.contract.configured_maxmind_db_path(settings),
                Path("/synthetic/city.mmdb"),
            )
        configured.assert_called_once_with(settings)

    def test_compact_record_preserves_allowlist_order_values_and_input(self):
        record = {
            "continent": {"names": {"en": "North America"}},
            "country": {"iso_code": "US", "names": {"en": "United States"}},
            "registered_country": {"iso_code": "CA"},
            "subdivisions": [{"names": {"en": "Colorado"}}],
            "city": {"names": {"en": "Denver"}},
            "location": {
                "time_zone": "America/Denver",
                "accuracy_radius": 0,
                "latitude": 0.0,
                "longitude": -104.9903,
            },
            "autonomous_system_number": 0,
            "autonomous_system_organization": "Example Network",
            "raw_secret_field": "must-not-project",
        }
        before = copy.deepcopy(record)
        result = self.contract.compact_maxmind_record(
            "203.0.113.7", record, ["source", "destination", "source"], 9
        )
        self.assertEqual(record, before)
        self.assertEqual(
            list(result),
            [
                "ip",
                "roles",
                "packet_observations",
                "continent",
                "country_iso_code",
                "country",
                "registered_country_iso_code",
                "subdivision",
                "city",
                "time_zone",
                "accuracy_radius_km",
                "latitude",
                "longitude",
                "autonomous_system_number",
                "autonomous_system_organization",
            ],
        )
        self.assertEqual(result["roles"], ["destination", "source"])
        self.assertEqual(result["packet_observations"], 9)
        self.assertEqual(result["accuracy_radius_km"], 0)
        self.assertEqual(result["latitude"], 0.0)
        self.assertEqual(result["autonomous_system_number"], 0)
        self.assertNotIn("raw_secret_field", result)
        self.assertNotIn("must-not-project", json.dumps(result))

    def test_compact_record_freezes_sanitizer_order_bounds_and_nested_admission(self):
        sanitize = mock.Mock(side_effect=lambda value, limit: f"<{value}:{limit}>")
        record = {
            "continent": {"names": {"en": "continent"}},
            "country": {"iso_code": "US", "names": {"en": "country"}},
            "registered_country": {"iso_code": "CA"},
            "subdivisions": [{"names": {"en": "subdivision"}}],
            "city": {"names": {"en": "city"}},
            "location": {"time_zone": "zone"},
            "autonomous_system_organization": "organization",
        }
        with mock.patch.object(
            self.contract, "sanitize_evidence_text", sanitize
        ):
            result = self.contract.compact_maxmind_record(
                "198.51.100.9", record, [], 1
            )
        self.assertEqual(
            sanitize.mock_calls,
            [
                mock.call("continent", 160),
                mock.call("US", 8),
                mock.call("country", 160),
                mock.call("CA", 8),
                mock.call("subdivision", 160),
                mock.call("city", 160),
                mock.call("zone", 80),
                mock.call("organization", 200),
            ],
        )
        self.assertEqual(result["continent"], "<continent:160>")
        self.assertEqual(result["autonomous_system_organization"], "<organization:200>")

        malformed = {
            "continent": [],
            "country": "not-an-object",
            "registered_country": None,
            "subdivisions": ["invalid-first", {"names": {"en": "ignored"}}],
            "city": 7,
            "location": "not-an-object",
            "unknown": "not-projected",
        }
        self.assertEqual(
            self.contract.compact_maxmind_record("192.0.2.8", malformed, [], 0),
            {"ip": "192.0.2.8", "packet_observations": 0},
        )


if __name__ == "__main__":
    unittest.main()
