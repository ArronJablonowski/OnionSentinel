#!/usr/bin/env python3
"""Focused contracts for the extracted bounded Ollama adapter."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
if str(N8N_ROOT) not in sys.path:
    sys.path.insert(0, str(N8N_ROOT))

from onion_sentinel.analysis.providers import ollama


class Response:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _maximum=-1):
        return b"{}"


class OllamaProviderAdapterTests(unittest.TestCase):
    def args(self):
        return SimpleNamespace(
            system_prompt_file=Path("synthetic-system.md"),
            temperature=0.0,
            max_predict_tokens=512,
            timeout=7.0,
            max_response_bytes=4096,
        )

    def test_request_is_bounded_json_only_and_attests_exact_model(self) -> None:
        captured = {}

        def request_factory(url, **kwargs):
            captured.update({"url": url, **kwargs})
            return object()

        result = ollama.request(
            {"alert": {"id": "synthetic"}},
            self.args(),
            {"ollama_model": "model:exact", "ollama_url": "http://localhost:11434/"},
            "Analyze synthetic evidence.",
            system_prompt_file=None,
            load_system_prompt=lambda _path: "Bounded system prompt.",
            read_bounded_json=lambda _response, max_bytes: {
                "message": {"content": json.dumps({"summary": "bounded"})}
            },
            extract_json_object=json.loads,
            urlopen=lambda _request, timeout: Response(),
            request_factory=request_factory,
            transport_errors=(TimeoutError,),
        )

        body = json.loads(captured["data"])
        self.assertEqual(captured["url"], "http://localhost:11434/api/chat")
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(body["model"], "model:exact")
        self.assertEqual(body["format"], "json")
        self.assertIs(body["stream"], False)
        self.assertEqual(result["_analysis_model"], "model:exact")
        self.assertEqual(result["_analysis_provider"], "ollama")

    def test_transport_timeout_is_classified_without_fallback(self) -> None:
        def timeout(_request, timeout):
            raise TimeoutError(f"deadline {timeout}")

        with self.assertRaisesRegex(
            SystemExit,
            r"Ollama request failed at http://127\.0\.0\.1:11434/api/chat",
        ):
            ollama.request(
                {},
                self.args(),
                {},
                "task",
                system_prompt_file=Path("system.md"),
                load_system_prompt=lambda _path: "system",
                read_bounded_json=lambda *_args, **_kwargs: {},
                extract_json_object=json.loads,
                urlopen=timeout,
                request_factory=lambda *_args, **_kwargs: object(),
                transport_errors=(TimeoutError,),
            )

    def test_missing_or_malformed_content_fails_closed(self) -> None:
        for payload in ({}, {"message": {}}, {"message": {"content": ""}}):
            with (
                self.subTest(payload=payload),
                self.assertRaisesRegex(SystemExit, "no message content"),
            ):
                ollama.request(
                    {},
                    self.args(),
                    {},
                    "task",
                    system_prompt_file=Path("system.md"),
                    load_system_prompt=lambda _path: "system",
                    read_bounded_json=lambda *_args, value=payload, **_kwargs: value,
                    extract_json_object=json.loads,
                    urlopen=lambda *_args, **_kwargs: Response(),
                    request_factory=lambda *_args, **_kwargs: object(),
                    transport_errors=(TimeoutError,),
                )

    def test_observed_model_mismatch_fails_closed(self) -> None:
        with self.assertRaisesRegex(SystemExit, "different model"):
            ollama.request(
                {},
                self.args(),
                {"ollama_model": "assigned:model"},
                "task",
                system_prompt_file=Path("system.md"),
                load_system_prompt=lambda _path: "system",
                read_bounded_json=lambda *_args, **_kwargs: {
                    "model": "different:model",
                    "message": {"content": "{}"},
                },
                extract_json_object=json.loads,
                urlopen=lambda *_args, **_kwargs: Response(),
                request_factory=lambda *_args, **_kwargs: object(),
                transport_errors=(TimeoutError,),
            )

    def test_locked_failure_still_unloads_and_releases_lock(self) -> None:
        events = []
        with tempfile.TemporaryDirectory() as temp_name:
            with self.assertRaisesRegex(SystemExit, "inference failed"):
                ollama.locked_chat(
                    {},
                    self.args(),
                    {},
                    "model:exact",
                    system_prompt_file=None,
                    independent_review=False,
                    lock_path=Path(temp_name) / "ollama.lock",
                    flock=lambda _handle, operation: events.append(("flock", operation)),
                    lock_exclusive=2,
                    lock_unlock=8,
                    unlocked_call=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                        SystemExit("inference failed")
                    ),
                    unload_call=lambda *_args, **_kwargs: events.append(("unload", None)),
                )
        self.assertEqual(events, [("flock", 2), ("unload", None), ("flock", 8)])

    def test_failover_uses_only_enabled_models_in_order(self) -> None:
        calls = []

        def invoke(_prompt, _args, _settings, model):
            calls.append(model)
            if model == "first":
                raise SystemExit("unavailable")
            return {"_analysis_model": model}

        result = ollama.chat_with_failover(
            {},
            self.args(),
            {"enabled_ollama_models": ["first", "second"]},
            normalize_roster=lambda value: list(value),
            chat_for_model=invoke,
        )
        self.assertEqual(calls, ["first", "second"])
        self.assertEqual(result["_analysis_model"], "second")


if __name__ == "__main__":
    unittest.main()
