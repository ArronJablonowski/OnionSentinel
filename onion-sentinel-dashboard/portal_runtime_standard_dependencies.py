"""Standard-library and foundational imports for the report-portal facade."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import secrets
import shlex
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from http import HTTPStatus
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import parse_qs, unquote, urlencode, urlparse

PORTAL_SOURCE_DIR = Path(__file__).resolve().parent
if str(PORTAL_SOURCE_DIR) not in sys.path:
    sys.path.insert(0, str(PORTAL_SOURCE_DIR))

import soc_alert_api
import software_inventory
import cti_program
import portal_asset_runtime
import portal_admin_runtime
import portal_operational_runtime
import portal_settings_runtime
import portal_soc_status_runtime
import portal_soc_pcap_runtime
import portal_llm_runtime
import portal_soc_query_runtime
import portal_incident_action_runtime
import portal_incident_read_runtime
import portal_soc_record_runtime
import portal_write_runtime
import portal_soc_core_runtime
import portal_soc_detail_runtime
import portal_delivery_runtime
import portal_dashboard_runtime
import portal_foundation_runtime
import portal_access_runtime
import portal_catalog_runtime
from artifact_cache import ArtifactCache
from http_runtime import BoundedResponseError, read_bounded_json
from jsonl_log import JsonlLogIndex
from portal_catalog_routes import classify_catalog_route

__all__ = tuple(
    name for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
)
