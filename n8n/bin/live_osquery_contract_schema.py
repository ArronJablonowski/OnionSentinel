#!/usr/bin/env python3
"""Immutable limits, schema, and lexical policy for live-host OSQuery."""

from __future__ import annotations

import re
from typing import Any


SCHEMA = "onion-sentinel-live-osquery-v1"
MAX_REQUESTS = 8
MAX_QUERY_CHARS = 4096
MAX_PURPOSE_CHARS = 500
MAX_ROWS = 200
DEFAULT_ROWS = 100
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_TARGET_ALIASES = 64
MAX_RESULT_DURATION_MS = 10 * 60 * 1000
MAX_REPORTED_ROWS = 1_000_000

TARGET_PLATFORM = "darwin"
TARGET_OSQUERY_VERSION = "5.15.0"
ALLOWED_TABLE_COLUMNS = {
    "apps": frozenset(
        {
            "name",
            "path",
            "bundle_executable",
            "bundle_identifier",
            "bundle_name",
            "bundle_short_version",
            "bundle_version",
            "bundle_package_type",
        }
    ),
    "arp_cache": frozenset({"address", "mac", "interface", "permanent"}),
    "crontab": frozenset(
        {
            "event",
            "minute",
            "hour",
            "day_of_month",
            "month",
            "day_of_week",
            "command",
            "path",
        }
    ),
    "groups": frozenset({"gid", "gid_signed", "groupname", "is_hidden"}),
    "homebrew_packages": frozenset(
        {"name", "path", "version", "type", "prefix"}
    ),
    "interface_addresses": frozenset(
        {"interface", "address", "mask", "broadcast", "point_to_point", "type"}
    ),
    "kernel_info": frozenset({"version", "arguments", "path", "device"}),
    "listening_ports": frozenset(
        {"pid", "port", "protocol", "family", "address", "fd", "socket", "path"}
    ),
    "logged_in_users": frozenset({"type", "user", "tty", "host", "time", "pid"}),
    "os_version": frozenset(
        {
            "name",
            "version",
            "major",
            "minor",
            "patch",
            "build",
            "platform",
            "platform_like",
            "codename",
            "arch",
            "extra",
        }
    ),
    "osquery_info": frozenset(
        {
            "pid",
            "uuid",
            "instance_id",
            "version",
            "config_hash",
            "config_valid",
            "extensions",
            "build_platform",
            "build_distro",
            "start_time",
            "watcher",
            "platform_mask",
        }
    ),
    "process_open_sockets": frozenset(
        {
            "pid",
            "fd",
            "socket",
            "family",
            "protocol",
            "local_address",
            "remote_address",
            "local_port",
            "remote_port",
            "path",
            "state",
        }
    ),
    "processes": frozenset(
        {
            "pid",
            "name",
            "path",
            "cmdline",
            "state",
            "cwd",
            "root",
            "uid",
            "gid",
            "euid",
            "egid",
            "suid",
            "sgid",
            "on_disk",
            "wired_size",
            "resident_size",
            "total_size",
            "user_time",
            "system_time",
            "disk_bytes_read",
            "disk_bytes_written",
            "start_time",
            "parent",
            "pgroup",
            "threads",
            "nice",
            "upid",
            "uppid",
            "cpu_type",
            "cpu_subtype",
            "translated",
        }
    ),
    "routes": frozenset(
        {
            "destination",
            "netmask",
            "gateway",
            "source",
            "flags",
            "interface",
            "mtu",
            "metric",
            "type",
            "hopcount",
        }
    ),
    "startup_items": frozenset(
        {"name", "path", "args", "type", "source", "status", "username"}
    ),
    "system_info": frozenset(
        {
            "hostname",
            "uuid",
            "cpu_type",
            "cpu_subtype",
            "cpu_brand",
            "cpu_physical_cores",
            "cpu_logical_cores",
            "cpu_sockets",
            "cpu_microcode",
            "physical_memory",
            "hardware_vendor",
            "hardware_model",
            "hardware_version",
            "hardware_serial",
            "board_vendor",
            "board_model",
            "board_version",
            "board_serial",
            "computer_name",
            "local_hostname",
        }
    ),
    "users": frozenset(
        {
            "uid",
            "gid",
            "uid_signed",
            "gid_signed",
            "username",
            "description",
            "directory",
            "shell",
            "uuid",
            "is_hidden",
        }
    ),
}
ALLOWED_TABLES = frozenset(ALLOWED_TABLE_COLUMNS)

_FORBIDDEN_TARGETS = frozenset({"*", "all", "agent_all", "all_agents", "_all"})
_FORBIDDEN_SQL = re.compile(
    r"\b("
    r"alter|attach|create|delete|detach|drop|insert|into|load_extension|"
    r"pragma|reindex|replace|update|vacuum"
    r")\b",
    re.IGNORECASE,
)
_FORBIDDEN_QUERY_SHAPES = re.compile(
    r"\b(?:except|intersect|union|with)\b|\(\s*select\b|\b(?:from|join)\s*\(",
    re.IGNORECASE,
)
_SQL_STRING_LITERAL = re.compile(r"'(?:''|[^'])*'")
_FUNCTION_CALL = re.compile(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_SQL_IDENTIFIER = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_SQL_KEYWORDS = frozenset(
    {
        "and",
        "asc",
        "between",
        "by",
        "desc",
        "escape",
        "false",
        "from",
        "glob",
        "in",
        "is",
        "like",
        "limit",
        "match",
        "not",
        "null",
        "or",
        "order",
        "regexp",
        "select",
        "true",
        "where",
    }
)
_SELECT_PROJECTION = re.compile(
    r"^\s*select\s+(?P<body>.*?)\s+from\b", re.IGNORECASE | re.DOTALL
)
_SAFE_PROJECTION_ITEM = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9_]*\.)?(?:\*|[A-Za-z_][A-Za-z0-9_]*)$"
)
_TABLE_REFERENCE = re.compile(
    r"\b(?:from|join)\s+([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE
)
_FROM_CLAUSE = re.compile(
    r"\bfrom\b(?P<body>.*?)(?=\bwhere\b|\bgroup\s+by\b|\border\s+by\b|\blimit\b|$)",
    re.IGNORECASE | re.DOTALL,
)
_TERMINAL_LIMIT = re.compile(r"\s+limit\s+([0-9]+)\s*$", re.IGNORECASE)
_ALIAS = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_RESULT_STATUSES = frozenset(
    {"ok", "timeout", "error", "invalid_response", "cancelled"}
)


class LiveOsqueryContractError(ValueError):
    """A request or response crossed the bounded live-query contract."""


def _bounded_text(value: Any, *, label: str, maximum: int, required: bool = True) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise LiveOsqueryContractError(f"{label} is required")
    if len(text) > maximum:
        raise LiveOsqueryContractError(f"{label} exceeds {maximum} characters")
    if any(ord(char) < 32 and char not in "\t\r\n" for char in text):
        raise LiveOsqueryContractError(f"{label} contains control characters")
    return text
