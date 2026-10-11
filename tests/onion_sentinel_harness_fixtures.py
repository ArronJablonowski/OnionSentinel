from __future__ import annotations


import dataclasses


import contextlib


import gc


import importlib.util


import inspect


import json


import os


import sqlite3


import stat


import subprocess


import sys


import tempfile


import threading


import unittest


import warnings


from pathlib import Path


from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


MODULE_PATH = ROOT / "n8n" / "bin" / "onion_sentinel_harness.py"


SPEC = importlib.util.spec_from_file_location(
    "onion_sentinel_harness_test_module",
    MODULE_PATH,
)


HARNESS = importlib.util.module_from_spec(SPEC)


assert SPEC and SPEC.loader


sys.modules[SPEC.name] = HARNESS


SPEC.loader.exec_module(HARNESS)
