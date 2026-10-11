import datetime as dt


from contextlib import closing


import importlib.util


import io


import json


from pathlib import Path


import shutil


import sqlite3


import subprocess


import sys


import tempfile


import unittest


from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
