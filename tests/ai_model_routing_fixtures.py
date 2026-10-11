"""Contract tests for provider rosters and exact per-agent model routing."""


from __future__ import annotations


import copy


from contextlib import ExitStack


import hashlib


import importlib.util


import io


import json


import sys


import tempfile


import unittest


from concurrent.futures import ThreadPoolExecutor


from pathlib import Path


from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]


BIN_DIR = REPO_ROOT / "n8n" / "bin"


RUNNER_PATH = BIN_DIR / "run-local-ai-analysis.py"


if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))


import local_ai_pipeline_adapters as PIPELINE_ADAPTERS


from agent_memory_context_contract import build_agent_memory_context_contract


def load_runner():
    if str(BIN_DIR) not in sys.path:
        sys.path.insert(0, str(BIN_DIR))
    spec = importlib.util.spec_from_file_location("run_local_ai_analysis_model_routing", RUNNER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module
