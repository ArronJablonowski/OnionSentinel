#!/usr/bin/env python3
"""Focused contracts for the extracted bounded Ollama adapter."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock


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
    def test_request_preserves_prompt_precedence_and_transport_read_order(self) -> None:
        trace: list[object] = []
        explicit = Path("explicit-system.md")
        response = Response()

        class TracedResponse(Response):
            def __enter__(self):
                trace.append("enter")
                return self

            def __exit__(self, exc_type, _exc, _tb):
                trace.append(("exit", exc_type))
                return False

        def factory(url, **kwargs):
            trace.append(("factory", url, kwargs["method"]))
            return "request"

        def open_request(value, timeout):
            trace.append(("open", value, timeout))
            return response

        response = TracedResponse()
        result = ollama.request(
            {"alert": {"id": "synthetic"}}, self.args(), {}, "task",
            system_prompt_file=explicit,
            load_system_prompt=lambda path: trace.append(("system", path)) or "prompt",
            read_bounded_json=lambda observed, max_bytes: trace.append(
                ("read", observed is response, max_bytes)
            ) or {"message": {"content": '{"summary":"ok"}'}},
            extract_json_object=lambda content: trace.append(
                ("extract", content)
            ) or json.loads(content),
            urlopen=open_request, request_factory=factory,
            transport_errors=(TimeoutError,),
        )
        self.assertEqual(trace, [
            ("system", explicit),
            ("factory", "http://127.0.0.1:11434/api/chat", "POST"),
            ("open", "request", 7.0), "enter", ("read", True, 4096),
            ("exit", None), ("extract", '{"summary":"ok"}'),
        ])
        self.assertEqual(result["summary"], "ok")

    def test_transport_failure_preserves_exception_cause_and_skips_extraction(self) -> None:
        failure = TimeoutError("synthetic timeout")
        extracted = mock.Mock()
        with self.assertRaisesRegex(SystemExit, "Ollama request failed") as raised:
            ollama.request(
                {}, self.args(), {}, "task",
                system_prompt_file=None,
                load_system_prompt=lambda _path: "system",
                read_bounded_json=lambda *_args, **_kwargs: {},
                extract_json_object=extracted,
                urlopen=lambda *_args, **_kwargs: (_ for _ in ()).throw(failure),
                request_factory=lambda *_args, **_kwargs: object(),
                transport_errors=(TimeoutError,),
            )
        self.assertIs(raised.exception.__cause__, failure)
        extracted.assert_not_called()

    def test_attestation_reuses_extracted_object_and_model_access_precedes_extract(self) -> None:
        trace: list[object] = []
        result_object: dict[str, object] = {"summary": "bounded"}

        class Payload(dict):
            def get(self, key, default=None):
                trace.append(("get", key))
                return super().get(key, default)

        payload = Payload({
            "model": " observed:model ",
            "message": Payload({"content": "{}"}),
        })
        result = ollama.request(
            {}, self.args(), {"ollama_model": "observed:model"}, "task",
            system_prompt_file=None,
            load_system_prompt=lambda _path: "system",
            read_bounded_json=lambda *_args, **_kwargs: payload,
            extract_json_object=lambda content: trace.append(
                ("extract", content)
            ) or result_object,
            urlopen=lambda *_args, **_kwargs: Response(),
            request_factory=lambda *_args, **_kwargs: object(),
            transport_errors=(TimeoutError,),
        )
        self.assertIs(result, result_object)
        self.assertEqual(trace, [
            ("get", "message"), ("get", "content"),
            ("get", "model"), ("extract", "{}"),
        ])
        self.assertEqual(result["_analysis_model"], "observed:model")

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
