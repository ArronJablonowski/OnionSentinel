from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

from portal_ai_settings_store import (  # noqa: E402
    AiSettingsStoreSources,
    read_soc_ai_settings,
    save_soc_agent_model,
    save_soc_ai_settings,
)


class AiSettingsStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "settings.json"
        self.routes = {"ollama:primary", "ollama:reviewer", "ollama:judge"}

        def defaults():
            return {
                "enabled": sorted(self.routes),
                "agent_models": {"soc-analyst": "ollama:primary"},
                "agent_second_opinion_models": {"soc-analyst": ""},
                "agent_adjudicator_models": {"soc-analyst": ""},
            }

        def normalize(value):
            if not isinstance(value, dict) or value.get("invalid"):
                return False, {"ok": False, "error": "invalid settings"}
            current = defaults()
            current.update(value)
            return True, current

        self.sources = AiSettingsStoreSources(
            path=self.path,
            lock=threading.RLock(),
            normalize=normalize,
            readiness=lambda settings: (True, ""),
            enabled_routes=lambda settings: settings["enabled"],
            route_identity=lambda route, settings: route.split(":")[-1],
            geoip_databases=lambda settings: {"city": {"state": "ready"}},
            geoip_city=lambda settings: {"state": "ready"},
            roles={"soc-analyst"},
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_missing_file_reads_normalized_defaults(self) -> None:
        response = read_soc_ai_settings(self.sources)
        self.assertTrue(response["ok"])
        self.assertEqual(response["settings"]["agent_models"]["soc-analyst"], "ollama:primary")

    def test_full_save_is_atomic_owner_only_and_projects_geoip(self) -> None:
        saved, response = save_soc_ai_settings(self.sources, {
            "agent_models": {"soc-analyst": "ollama:primary"}
        })
        self.assertTrue(saved)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(response["geoip_database"]["state"], "ready")
        self.assertEqual(json.loads(self.path.read_text())["agent_models"]["soc-analyst"], "ollama:primary")

    def test_read_and_readiness_errors_are_returned_without_overwrite(self) -> None:
        self.path.write_text("not-json", encoding="utf-8")
        response = read_soc_ai_settings(self.sources)
        self.assertFalse(response["ok"])
        self.assertIn("Could not read", response["error"])
        before = self.path.read_text()
        blocked = AiSettingsStoreSources(
            **{**self.sources.__dict__, "readiness": lambda settings: (False, "not ready")}
        )
        saved, response = save_soc_ai_settings(blocked, {})
        self.assertFalse(saved)
        self.assertEqual(response["error"], "not ready")
        self.assertEqual(self.path.read_text(), before)

    def test_failed_atomic_replace_preserves_original_and_cleans_staged_document(self) -> None:
        original = '{"original": true}\n'
        self.path.write_text(original, encoding="utf-8")

        with mock.patch(
            "portal_ai_settings_store.Path.replace",
            side_effect=OSError("synthetic replace failure"),
        ):
            saved, response = save_soc_ai_settings(self.sources, {})

        self.assertFalse(saved)
        self.assertIn("Could not save", response["error"])
        self.assertEqual(self.path.read_text(encoding="utf-8"), original)
        self.assertEqual(
            sorted(path.name for path in self.path.parent.iterdir()),
            [self.path.name],
        )

    def test_agent_save_updates_only_requested_role_and_all_three_routes(self) -> None:
        save_soc_ai_settings(self.sources, {})
        saved, response = save_soc_agent_model(self.sources, {
            "role": "soc-analyst",
            "model": "ollama:primary",
            "second_opinion_model": "ollama:reviewer",
            "adjudicator_model": "ollama:judge",
        })
        self.assertTrue(saved)
        self.assertEqual(response["second_opinion_model_route"], "ollama:reviewer")
        persisted = json.loads(self.path.read_text())
        self.assertEqual(persisted["agent_adjudicator_models"]["soc-analyst"], "ollama:judge")

    def test_global_save_preserves_a_newer_agent_assignment_transaction(self) -> None:
        save_soc_ai_settings(self.sources, {})
        saved, _response = save_soc_agent_model(self.sources, {
            "role": "soc-analyst",
            "model": "ollama:reviewer",
            "second_opinion_model": "ollama:primary",
            "adjudicator_model": "ollama:judge",
        })
        self.assertTrue(saved)

        saved, response = save_soc_ai_settings(self.sources, {
            "policy_marker": "updated",
            "agent_models": {"soc-analyst": "ollama:primary"},
            "agent_second_opinion_models": {"soc-analyst": ""},
            "agent_adjudicator_models": {"soc-analyst": ""},
        })

        self.assertTrue(saved)
        self.assertEqual(response["settings"]["policy_marker"], "updated")
        self.assertEqual(
            response["settings"]["agent_models"]["soc-analyst"],
            "ollama:reviewer",
        )
        self.assertEqual(
            response["settings"]["agent_second_opinion_models"]["soc-analyst"],
            "ollama:primary",
        )
        self.assertEqual(
            response["settings"]["agent_adjudicator_models"]["soc-analyst"],
            "ollama:judge",
        )

    def test_agent_save_rejects_invalid_role_disabled_route_and_collisions(self) -> None:
        save_soc_ai_settings(self.sources, {})
        cases = (
            ({"role": "unknown", "model": "ollama:primary"}, "role is invalid"),
            ({"role": "soc-analyst", "model": "ollama:disabled"}, "not enabled"),
            ({
                "role": "soc-analyst", "model": "ollama:primary",
                "second_opinion_model": "provider:primary",
            }, "provider/model identity"),
            ({
                "role": "soc-analyst", "model": "ollama:primary",
                "second_opinion_model": "ollama:reviewer",
                "adjudicator_model": "provider:reviewer",
            }, "adjudicator must differ"),
        )
        expanded = AiSettingsStoreSources(
            **{
                **self.sources.__dict__,
                "enabled_routes": lambda settings: {
                    *settings["enabled"], "provider:primary", "provider:reviewer"
                },
            }
        )
        for payload, expected in cases:
            with self.subTest(payload=payload):
                saved, response = save_soc_agent_model(expanded, payload)
                self.assertFalse(saved)
                self.assertIn(expected, response["error"])

    def test_routes_are_bounded_before_assignment(self) -> None:
        save_soc_ai_settings(self.sources, {})
        long_route = "x" * 400
        bounded = "x" * 260
        custom = AiSettingsStoreSources(
            **{
                **self.sources.__dict__,
                "enabled_routes": lambda settings: {bounded},
                "route_identity": lambda route, settings: route,
            }
        )
        saved, response = save_soc_agent_model(custom, {
            "role": "soc-analyst", "model": long_route
        })
        self.assertTrue(saved)
        self.assertEqual(response["model_route"], bounded)

    def test_invalid_role_short_circuits_before_lock_read_and_normalization(self) -> None:
        class ExplodingLock:
            def __enter__(self):
                raise AssertionError("invalid role acquired settings lock")

            def __exit__(self, *_args):
                return False

        sources = AiSettingsStoreSources(
            **{
                **self.sources.__dict__,
                "lock": ExplodingLock(),
                "normalize": lambda _value: (_ for _ in ()).throw(
                    AssertionError("invalid role normalized settings")
                ),
            }
        )
        self.assertEqual(
            save_soc_agent_model(
                sources, {"role": "unknown", "model": "ollama:primary"}
            ),
            (
                False,
                {
                    "ok": False,
                    "error": "Cyber Security Agent role is invalid.",
                },
            ),
        )

    def test_failed_agent_write_does_not_add_success_projection(self) -> None:
        directory_path = Path(self.temp.name) / "settings-directory"
        directory_path.mkdir()
        sources = AiSettingsStoreSources(
            **{**self.sources.__dict__, "path": directory_path}
        )

        saved, response = save_soc_agent_model(
            sources,
            {"role": "soc-analyst", "model": "ollama:primary"},
        )

        self.assertFalse(saved)
        self.assertIn("Could not read SOC AI settings", response["error"])
        self.assertNotIn("message", response)
        self.assertNotIn("role", response)
        self.assertNotIn("model_route", response)


if __name__ == "__main__":
    unittest.main()
