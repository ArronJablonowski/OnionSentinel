"""Regression checks for relay wrapper isolation between alert and PCAP paths."""


from __future__ import annotations


import contextlib


import importlib.util


import io


import json


import subprocess


import sys


import unittest


from pathlib import Path


from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]


WRAPPER_PATH = REPO_ROOT / "relay" / "app" / "relay_health_wrapper.py"


def load_wrapper():
    spec = importlib.util.spec_from_file_location("relay_health_wrapper", WRAPPER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def completed(returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess("unit-test", returncode, stdout, stderr)
