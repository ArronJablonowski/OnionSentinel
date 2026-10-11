"""Regression checks for editable SOC settings prompt helpers."""


from __future__ import annotations


import io


import importlib.util


import json


import sys


import tempfile


import unittest


from pathlib import Path


from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]


PORTAL_PATH = REPO_ROOT / "onion-sentinel-dashboard" / "report_portal.py"


def load_portal():
    spec = importlib.util.spec_from_file_location("report_portal_settings", PORTAL_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SettingsPostRequest:
    """Minimal request stub for exercising the Settings POST route policy."""

    def __init__(self, path: str, payload: dict, *, settings_authorized: bool = True):
        body = json.dumps(payload).encode("utf-8")
        self.path = path
        self.headers = {"Content-Length": str(len(body))}
        self.rfile = io.BytesIO(body)
        self.settings_authorized = settings_authorized
        self.response: tuple[int, dict] | None = None

    def _soc_settings_write_authorized(self) -> bool:
        return self.settings_authorized

    def _send(self, status: int, body: bytes, _content_type: str = "") -> None:
        self.response = (int(status), json.loads(body.decode("utf-8")))


