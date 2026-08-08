from __future__ import annotations

import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

from portal_ollama_catalog import (  # noqa: E402
    OllamaCatalogSources,
    OllamaMetadataSources,
    classify_ollama_model_compatibility,
    compose_ollama_models_response,
    list_ollama_models,
    load_ollama_model_compatibility,
    ollama_context_length,
)


class OllamaCatalogTest(unittest.TestCase):
    def test_list_models_uses_first_working_command_and_deduplicates(self) -> None:
        calls = []

        def run(command, **kwargs):
            calls.append((command, kwargs))
            if len(calls) == 1:
                raise OSError("missing")
            return SimpleNamespace(
                returncode=0,
                stdout="NAME ID SIZE\nalpha:latest 1 2\nalpha:latest 1 2\nbeta:7b 2 3\n",
            )

        models = list_ollama_models(
            run=run,
            env={"PATH": "/safe"},
            commands=(("first", "ls"), ("second", "ls"), ("third", "ls")),
        )
        self.assertEqual(models, ["alpha:latest", "beta:7b"])
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][1]["timeout"], 10)

    def test_context_length_uses_largest_valid_value(self) -> None:
        self.assertEqual(ollama_context_length({
            "a.context_length": "8192",
            "b.context_length": 32768,
            "ignored": 999999,
            "bad.context_length": "x",
        }), 32768)

    def test_compatibility_covers_unverified_capability_template_and_context(self) -> None:
        unverified = classify_ollama_model_compatibility(
            "missing", None, min_context_tokens=32768
        )
        incompatible = classify_ollama_model_compatibility(
            "image",
            {
                "capabilities": ["IMAGE", "image"],
                "template": "",
                "model_info": {"x.context_length": 8192},
            },
            min_context_tokens=32768,
        )
        self.assertEqual(unverified["status"], "unverified")
        self.assertEqual(incompatible["capabilities"], ["image"])
        self.assertEqual(len(incompatible["reasons"]), 3)

    def test_metadata_lookup_is_bounded_cached_and_url_normalized(self) -> None:
        seen = {}

        @contextmanager
        def open_url(request, timeout):
            seen["url"] = request.full_url
            seen["timeout"] = timeout
            yield object()

        def cache(key, compute):
            seen["key"] = key
            return compute()

        def read_json(response, max_bytes):
            seen["max_bytes"] = max_bytes
            return {
                "capabilities": ["completion"],
                "template": "{{ .Messages }}",
                "model_info": {"x.context_length": 32768},
            }

        result = load_ollama_model_compatibility(
            OllamaMetadataSources(
                cache_get_or_compute=cache,
                open_url=open_url,
                read_json=read_json,
                max_bytes=1234,
                min_context_tokens=32768,
            ),
            "soc:latest",
            "http://127.0.0.1:11434/",
        )
        self.assertTrue(result["compatible"])
        self.assertEqual(seen["key"], ("http://127.0.0.1:11434", "soc:latest"))
        self.assertEqual(seen["url"], "http://127.0.0.1:11434/api/show")
        self.assertEqual(seen["max_bytes"], 1234)

    def test_response_retains_uninstalled_enabled_models_and_refreshes_cache(self) -> None:
        cleared = []
        calls = []
        sources = OllamaCatalogSources(
            read_settings=lambda: {"settings": {
                "enabled_ollama_models": ["installed", "offline"],
                "ollama_url": "http://127.0.0.1:11434/",
            }},
            default_settings=lambda: {},
            list_models=lambda: ["installed", "extra"],
            normalize_models=lambda value: list(value),
            compatibility=lambda model, url: calls.append((model, url)) or {
                "compatible": True,
                "status": "compatible",
                "reasons": [],
                "capabilities": ["completion"],
                "context_length": 32768,
            },
            clear_cache=lambda: cleared.append(True),
        )
        result = compose_ollama_models_response(sources, force_refresh=True)
        self.assertEqual(result["models"], ["installed", "extra", "offline"])
        self.assertEqual(result["compatibility"]["offline"]["status"], "unavailable")
        self.assertEqual(result["selected"], "installed")
        self.assertEqual(cleared, [True])
        self.assertEqual({model for model, _ in calls}, {"installed", "extra"})

    def test_empty_catalog_uses_legacy_selection_without_workers(self) -> None:
        result = compose_ollama_models_response(OllamaCatalogSources(
            read_settings=lambda: {"settings": {"ollama_model": "legacy"}},
            default_settings=lambda: {},
            list_models=lambda: [],
            normalize_models=lambda value: [],
            compatibility=lambda model, url: {},
            clear_cache=lambda: None,
        ))
        self.assertEqual(result["selected"], "legacy")
        self.assertEqual(result["compatibility"], {})


if __name__ == "__main__":
    unittest.main()
