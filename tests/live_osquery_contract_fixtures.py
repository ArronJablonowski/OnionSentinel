import importlib.machinery


import importlib.util


import datetime as dt


import io


import json


import os


import stat


import subprocess


import sys


import tempfile


import time


import unittest


import urllib.error


import urllib.request


from concurrent.futures import ThreadPoolExecutor


from pathlib import Path


from types import SimpleNamespace


from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


BIN = ROOT / "n8n" / "bin"


SO_WRAPPER = ROOT / "security-onion" / "bin" / "run-live-osquery"


SO_CONFIG_EXAMPLE = (
    ROOT / "security-onion" / "config" / "live-osquery.example.json"
)


SO_LAUNCHER = ROOT / "security-onion" / "bin" / "run-live-osquery-forced"


SO_AUTHORIZED_KEY = (
    ROOT / "security-onion" / "ssh" / "authorized_keys.live-osquery.example"
)


SO_INSTALLER = ROOT / "security-onion" / "bin" / "install-security-onion-wrapper.sh"


RELAY_AUTHORIZED_KEY = (
    ROOT / "relay" / "config" / "authorized_keys.live-osquery.example"
)


RELAY_INSTALLER = ROOT / "relay" / "bin" / "install-pi-relay.sh"


RELAY_SUDOERS = ROOT / "relay" / "sudoers" / "so-live-osquery"


RELAY_LAUNCHER = ROOT / "relay" / "bin" / "run-live-osquery-broker"


RELAY_BROKER = ROOT / "relay" / "app" / "live_osquery_broker.py"


sys.path.insert(0, str(BIN))


sys.path.insert(0, str(ROOT / "relay" / "app"))


from live_osquery_contract import (  # noqa: E402
    LiveOsqueryContractError,
    normalize_query,
    normalize_requests,
    validate_result_artifact,
)


from live_osquery_client import (  # noqa: E402
    LiveOsqueryClientError,
    _persist_live_osquery_artifact,
    capability_descriptor,
    collect_live_osquery,
    harness_operator_approved,
    load_live_osquery_config,
    scheduled_inventory_approved,
)


from bounded_process import BoundedProcessError  # noqa: E402


def load_security_onion_wrapper():
    loader = importlib.machinery.SourceFileLoader("run_live_osquery", str(SO_WRAPPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def load_relay_broker():
    loader = importlib.machinery.SourceFileLoader(
        "live_osquery_broker_test",
        str(RELAY_BROKER),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


