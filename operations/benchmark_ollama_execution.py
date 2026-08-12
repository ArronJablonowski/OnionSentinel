"""Deterministic prompt construction and bounded Ollama benchmark execution."""
from __future__ import annotations

import json
import socket
import time
import urllib.error
from collections.abc import Callable, Sequence
from typing import Any


JsonRequest = Callable[[str, dict[str, Any], int], dict[str, Any]]


def extract_json(text: str) -> tuple[dict[str, Any], str]:
    stripped = text.strip()
    candidates: list[tuple[str, str]] = [(stripped, "exact")]
    if stripped.startswith("```") and stripped.endswith("```"):
        inner = stripped.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        candidates.append((inner, "fenced"))
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start >= 0 and end > start:
        candidates.append((stripped[start : end + 1], "extracted"))
    last_error: Exception | None = None
    for candidate, mode in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed, mode
        except (json.JSONDecodeError, TypeError) as exc:
            last_error = exc
    raise ValueError(f"model response was not valid JSON: {last_error}")


def batch_prompt(cases: Sequence[Any], repetition: int) -> str:
    payload = {
        "benchmark_version": 1,
        "repetition": repetition,
        "cases": [case.prompt_payload() for case in cases],
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def query_batch_prompt(cases: Sequence[Any], repetition: int) -> str:
    payload = {
        "benchmark_version": 2,
        "repetition": repetition,
        "query_tasks": [case.prompt_payload() for case in cases],
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def _chat_payload(
    model: str,
    prompt: str,
    system_prompt: str,
    temperature: float,
    num_predict: int,
) -> dict[str, Any]:
    return {
        "model": model,
        "stream": False,
        "think": False,
        "format": "json",
        "keep_alive": "10m",
        "options": {"temperature": temperature, "num_predict": num_predict},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
    }


def _successful_chat_result(
    response: dict[str, Any],
    attempt: int,
    wall_seconds: float,
) -> dict[str, Any]:
    content = str(((response.get("message") or {}).get("content")) or "")
    parsed, parse_mode = extract_json(content)
    return {
        "ok": True,
        "attempt": attempt + 1,
        "wall_seconds": wall_seconds,
        "parse_mode": parse_mode,
        "response": parsed,
        "ollama_metrics": {
            key: response.get(key)
            for key in (
                "total_duration", "load_duration", "prompt_eval_count",
                "prompt_eval_duration", "eval_count", "eval_duration",
            )
        },
    }


def _run_chat(
    *,
    ollama_url: str,
    model: str,
    prompt: str,
    system_prompt: str,
    num_predict: int,
    timeout: int,
    retries: int,
    temperature: float,
    request_json: JsonRequest,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    request_payload = _chat_payload(
        model,
        prompt,
        system_prompt,
        temperature,
        num_predict,
    )
    error: Exception | None = None
    for attempt in range(retries + 1):
        started = monotonic()
        try:
            response = request_json(
                ollama_url.rstrip("/") + "/api/chat",
                request_payload,
                timeout,
            )
            wall_seconds = monotonic() - started
            return _successful_chat_result(response, attempt, wall_seconds)
        except (
            OSError,
            TimeoutError,
            socket.timeout,
            urllib.error.URLError,
            ValueError,
            RuntimeError,
            json.JSONDecodeError,
        ) as exc:
            error = exc
            if attempt < retries:
                sleep(min(5.0, 1.0 + attempt * 2.0))
    return {
        "ok": False,
        "attempt": retries + 1,
        "error": f"{type(error).__name__}: {error}",
    }


def run_decision_batch(
    ollama_url: str,
    model: str,
    cases: Sequence[Any],
    repetition: int,
    timeout: int,
    retries: int,
    temperature: float,
    *,
    system_prompt: str,
    request_json: JsonRequest,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    return _run_chat(
        ollama_url=ollama_url,
        model=model,
        prompt=batch_prompt(cases, repetition),
        system_prompt=system_prompt,
        num_predict=3072,
        timeout=timeout,
        retries=retries,
        temperature=temperature,
        request_json=request_json,
        monotonic=monotonic,
        sleep=sleep,
    )


def run_query_batch(
    ollama_url: str,
    model: str,
    cases: Sequence[Any],
    repetition: int,
    timeout: int,
    retries: int,
    temperature: float,
    *,
    system_prompt: str,
    request_json: JsonRequest,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    return _run_chat(
        ollama_url=ollama_url,
        model=model,
        prompt=query_batch_prompt(cases, repetition),
        system_prompt=system_prompt,
        num_predict=4096,
        timeout=timeout,
        retries=retries,
        temperature=temperature,
        request_json=request_json,
        monotonic=monotonic,
        sleep=sleep,
    )
