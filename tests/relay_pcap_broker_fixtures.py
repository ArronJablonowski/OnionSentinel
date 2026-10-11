"""Regression checks for relay-side PCAP broker fulfillment."""


from __future__ import annotations


import importlib.util


import contextlib


import fcntl


import hashlib


import io


import json


import os


import subprocess


import sys


import tarfile


import tempfile


import time


import unittest


from pathlib import Path


from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]


RELAY_PATH = REPO_ROOT / "relay" / "app" / "relay.py"


def load_relay():
    spec = importlib.util.spec_from_file_location("relay", RELAY_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module
