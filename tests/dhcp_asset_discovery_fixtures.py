"""Contracts for bounded, read-only DHCP asset discovery."""


from __future__ import annotations


import datetime as dt


import contextlib


import hashlib


import importlib.machinery


import importlib.util


import inspect


import io


import json


import shutil


import stat


import subprocess


import sys


import tempfile


import unittest


from pathlib import Path


from types import SimpleNamespace


from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


COLLECTOR = ROOT / "n8n" / "bin" / "collect-dhcp-asset-discovery.py"


QUERY_CLIENT = ROOT / "n8n" / "bin" / "query-security-onion.py"


PROMOTER = ROOT / "n8n" / "bin" / "promote-dhcp-asset.py"


WRAPPER = ROOT / "security-onion" / "bin" / "export-dhcp-observations"


BROKER = ROOT / "relay" / "app" / "incident_evidence_broker.py"


PORTAL = ROOT / "onion-sentinel-dashboard" / "report_portal.py"


BUILDER = ROOT / "onion-sentinel-dashboard" / "scripts" / "build_soc_alerts_dashboard.py"


INSTALLER = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load_module(name: str, path: Path):
    for dependency in (ROOT / "n8n" / "bin", ROOT / "relay" / "app"):
        if str(dependency) not in sys.path:
            sys.path.insert(0, str(dependency))
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module
