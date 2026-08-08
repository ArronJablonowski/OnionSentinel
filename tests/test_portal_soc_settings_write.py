#!/usr/bin/env python3
"""Direct contracts for SOC Settings request orchestration."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_request_routes import classify_post_route  # noqa: E402
from portal_soc_settings_write import (  # noqa: E402
    SocSettingsWriteCallbacks,
    is_soc_settings_write,
    prepare_soc_settings_write,
)


PROMPTS = frozenset({"/api/soc-settings/analyst-prompt"})


def route(path: str):
    return classify_post_route(
        path,
        cti_program_path="/api/cyber-threat-intel/program",
        prompt_paths=PROMPTS,
    )


def callbacks(**overrides) -> SocSettingsWriteCallbacks:
    values = {
        "save_prompt": lambda _path, _prompt: (True, {"ok": True}),
        "save_ai_settings": lambda _payload: (True, {"ok": True}),
        "save_agent_model": lambda _payload: (True, {"ok": True}),
    }
    values.update(overrides)
    return SocSettingsWriteCallbacks(**values)


class SocSettingsWriteTests(unittest.TestCase):
    def test_only_allowlisted_settings_routes_are_owned(self) -> None:
        self.assertTrue(is_soc_settings_write(route(next(iter(PROMPTS)))))
        self.assertTrue(is_soc_settings_write(route("/api/soc-settings/ai-model")))
        self.assertTrue(is_soc_settings_write(route("/api/soc-settings/agent-model")))
        self.assertFalse(is_soc_settings_write(route("/api/soc-alerts/status")))

    def test_non_settings_route_is_declined_without_auth_or_save(self) -> None:
        auth_calls: list[bool] = []
        result = prepare_soc_settings_write(
            route("/api/soc-alerts/status"),
            "{}",
            admin_authenticated=lambda: auth_calls.append(True) or True,
            callbacks=callbacks(
                save_ai_settings=lambda _payload: self.fail("must not save"),
            ),
        )
        self.assertIsNone(result)
        self.assertEqual(auth_calls, [])

    def test_authentication_failure_is_explicit_and_does_not_save(self) -> None:
        result = prepare_soc_settings_write(
            route("/api/soc-settings/ai-model"),
            '{"mode":"ollama"}',
            admin_authenticated=lambda: False,
            callbacks=callbacks(
                save_ai_settings=lambda _payload: self.fail("must not save"),
            ),
        )
        self.assertEqual(result.status, 403)
        self.assertIn("Sign in to Administration", result.payload["error"])

    def test_each_settings_family_dispatches_its_existing_payload(self) -> None:
        calls: list[tuple[str, object]] = []
        cases = (
            (
                "/api/soc-settings/analyst-prompt",
                '{"prompt":"Investigate carefully"}',
                ("prompt", "Investigate carefully"),
            ),
            (
                "/api/soc-settings/ai-model",
                '{"mode":"ollama"}',
                ("ai", {"mode": "ollama"}),
            ),
            (
                "/api/soc-settings/agent-model",
                '{"role":"soc-analyst"}',
                ("agent", {"role": "soc-analyst"}),
            ),
        )
        bound = callbacks(
            save_prompt=lambda _path, payload: (
                calls.append(("prompt", payload)) or True, {"ok": True}
            ),
            save_ai_settings=lambda payload: (
                calls.append(("ai", payload)) or True, {"ok": True}
            ),
            save_agent_model=lambda payload: (
                calls.append(("agent", payload)) or True, {"ok": True}
            ),
        )
        for path, raw, expected in cases:
            result = prepare_soc_settings_write(
                route(path), raw,
                admin_authenticated=lambda: True,
                callbacks=bound,
            )
            self.assertEqual(result.status, 200)
            self.assertEqual(calls.pop(), expected)

    def test_malformed_json_preserves_empty_object_fallback(self) -> None:
        received: list[object] = []
        result = prepare_soc_settings_write(
            route("/api/soc-settings/ai-model"),
            "{not-json",
            admin_authenticated=lambda: True,
            callbacks=callbacks(
                save_ai_settings=lambda payload: (
                    received.append(payload) or False,
                    {"ok": False, "error": "invalid"},
                ),
            ),
        )
        self.assertEqual(result.status, 400)
        self.assertEqual(received, [{}])

    def test_saver_failure_maps_to_bad_request(self) -> None:
        result = prepare_soc_settings_write(
            route("/api/soc-settings/agent-model"),
            "{}",
            admin_authenticated=lambda: True,
            callbacks=callbacks(
                save_agent_model=lambda _payload: (
                    False, {"ok": False, "error": "rejected"},
                ),
            ),
        )
        self.assertEqual(result.status, 400)
        self.assertEqual(result.payload["error"], "rejected")


if __name__ == "__main__":
    unittest.main()
