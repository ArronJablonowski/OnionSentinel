"""Regression checks for the SOC Alerts grouped-summary API path."""


from __future__ import annotations


import importlib.util


import json


import sqlite3


import sys


import tempfile


import time


import unittest


import datetime as dt


from concurrent.futures import ThreadPoolExecutor


from pathlib import Path


from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]


PORTAL_PATH = REPO_ROOT / "onion-sentinel-dashboard" / "report_portal.py"


def load_portal():
    spec = importlib.util.spec_from_file_location("report_portal", PORTAL_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


