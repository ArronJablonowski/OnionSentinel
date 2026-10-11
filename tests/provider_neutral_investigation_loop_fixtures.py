"""Focused contracts for the provider-neutral investigation pivot loop."""


from __future__ import annotations


import ast


import argparse


import copy


import hashlib


import importlib.util


import json


import sys


import tempfile


import unittest


from pathlib import Path


from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]


BIN_DIR = REPO_ROOT / "n8n" / "bin"


def load_module(name: str, path: Path):
    if str(BIN_DIR) not in sys.path:
        sys.path.insert(0, str(BIN_DIR))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class RecordingHarness:
    """Minimal harness double that makes call ordering observable."""

    class _Policy:
        def __init__(self, mode: str) -> None:
            self.mode = mode

    class _Decision:
        def __init__(
            self,
            allowed: bool,
            backend: str,
            *,
            requires_approval: bool,
        ) -> None:
            self.allowed = allowed
            self.capability = f"query.{backend}"
            self.reason = "test policy decision"
            self.requires_approval = requires_approval

    def __init__(
        self,
        events: list[tuple],
        *,
        mode: str = "enforce",
        tool_allowed: bool = True,
        tool_requires_approval: bool = False,
        fail_authorization: bool = False,
        remaining_model_calls: int = 6,
        query_rounds_used: int = 0,
        remaining_query_rounds: int = 3,
        remaining_queries: int = 12,
    ) -> None:
        self.events = events
        self.policy = self._Policy(mode)
        self.tool_allowed = tool_allowed
        self.tool_requires_approval = tool_requires_approval
        self.fail_authorization = fail_authorization
        self._remaining_model_calls = remaining_model_calls
        self._query_rounds_used = query_rounds_used
        self._remaining_query_rounds = remaining_query_rounds
        self._remaining_queries = remaining_queries

    def remaining_model_calls(self) -> int:
        return self._remaining_model_calls

    def query_rounds_used(self) -> int:
        return self._query_rounds_used

    def remaining_query_rounds(self) -> int:
        return self._remaining_query_rounds

    def remaining_queries(self) -> int:
        return self._remaining_queries

    def phase(self, phase: str, route: str = "", reason: str = "") -> None:
        self.events.append(("phase", phase, route, reason))

    def authorize_tool(
        self,
        *,
        round_number: int,
        query_id: str,
        backend: str,
        approved: bool = False,
    ) -> _Decision:
        self.events.append(
            ("authorize_tool", round_number, query_id, backend, approved)
        )
        if self.fail_authorization:
            raise RuntimeError("synthetic shadow observation failure")
        return self._Decision(
            self.tool_allowed and (
                not self.tool_requires_approval or approved
            ),
            backend,
            requires_approval=self.tool_requires_approval,
        )

    def preflight_query_batch(
        self,
        *,
        round_number: int,
        request_count: int,
    ) -> None:
        self.events.append(
            ("preflight_query_batch", round_number, request_count)
        )

    def query_round(self, round_result: dict) -> None:
        self.events.append(("query_round", round_result.get("round")))

    def catalogue_prompt_evidence(self, _prompt_package: dict) -> None:
        self.events.append(("catalogue_prompt_evidence",))

    def preflight_model_call(
        self,
        *,
        call_id: str,
        input_value: object,
        requested_route: str,
        purpose: str,
        independent_review: bool = False,
    ) -> None:
        self.events.append(
            (
                "preflight_model_call",
                call_id,
                independent_review,
                bool(input_value),
                requested_route,
                purpose,
            )
        )

    def model_call(
        self,
        *,
        call_id: str,
        independent_review: bool = False,
        **_kwargs,
    ) -> None:
        self.events.append(
            ("model_call", call_id, independent_review)
        )


