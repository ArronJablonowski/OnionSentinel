"""Shared constants, errors, canonical hashing, and clock for cohort tooling."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import re
from typing import Any


SCHEMA = "onion-sentinel-incident-harness-cohort-v4"
EXPORT_SCHEMA = "onion-sentinel-incident-harness-cohort-export-v4"
MAX_COHORT_SIZE = 100
MAX_HTTP_BODY_BYTES = 1_000_000
MAX_SOURCE_ROWS_BYTES = 2_000_000
MAX_MANIFEST_BYTES = 10_000_000
MAX_STORED_RESPONSE_BYTES = 8_000_000
MAX_STABLE_GROUP_KEY_BYTES = 2048
MAX_EVALUATION_TOKEN_BYTES = 64
TERMINAL_MONITOR_STATES = {"completed", "failed", "skipped"}
ACTIVE_JOB_STATES = {"pending", "processing"}
ACTIVE_AGENT_STATES = {"queued", "analyzing"}
ACTIVE_REANALYSIS_STATES = {"queued", "running"}
AGENT_ROLES = {"incident-responder", "soc-analyst"}
COHORT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}")
DASHBOARD_GROUP_ID_RE = re.compile(r"[a-f0-9]{12}")
STABLE_GROUP_ID_RE = re.compile(r"[a-f0-9]{20}")
REPRESENTATIVE_ALERT_ID_RE = re.compile(r"[A-Za-z0-9._:@=-]{1,256}")
CASE_ID_RE = re.compile(r"ir-[a-z0-9_-]{1,64}")
RUN_ID_RE = re.compile(r"irr-[a-z0-9-]{1,64}")
SHA256_RE = re.compile(r"[a-f0-9]{64}")
SKILL_ID_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._:@+=/-]{0,255}")
MAX_ATTESTED_INVESTIGATION_SKILLS = 4
RELEASE_ID_RE = re.compile(r"[a-f0-9]{40}")
SAFE_ROUTE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{2,255}")
CONTROLLED_ROUTE_RE = re.compile(
    r"codex-cli:(?:gpt-5\.5|gpt-5\.6-(?:sol|terra|luna)):"
    r"(?:low|medium|high|xhigh)"
)
CONTROLLED_EVALUATION_PROFILE = (
    "onion-sentinel-gpt55-high-gpt56-sol-xhigh-v1"
)
PROFILE_ASSIGNED_ROUTE = "codex-cli:gpt-5.5:high"
PROFILE_REVIEWER_ROUTE = "codex-cli:gpt-5.6-sol:xhigh"
MODEL_CALL_CONTRACT_SCHEMA = "onion-sentinel-model-call-contract-v1"
MAX_RUNTIME_MODEL_CALLS = 6
DISPATCH_ID_SCHEMA = "onion-sentinel-cohort-member-dispatch-v1"
REPRESENTATIVE_BINDING_SCHEMA = (
    "onion-sentinel-frozen-representative-binding-v1"
)
FROZEN_REPRESENTATIVE_IMMUTABLE_FIELDS = (
    "stable_group_key",
    "timestamp",
    "rule_name",
    "event_dataset",
    "severity",
    "severity_label",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "network_protocol",
    "transport_protocol",
    "traffic_direction",
)
ALERT_STORE_CANONICAL_SHA256_JS = r"""
const crypto = require("node:crypto");
const fs = require("node:fs");
const canonicalize = (item) => {
  if (Array.isArray(item)) return item.map((entry) => canonicalize(entry));
  if (item && typeof item === "object") {
    return Object.fromEntries(
      Object.keys(item).sort().map((key) => [key, canonicalize(item[key])]),
    );
  }
  return item;
};
const value = JSON.parse(fs.readFileSync(0, "utf8"));
process.stdout.write(
  crypto.createHash("sha256")
    .update(JSON.stringify(canonicalize(value)))
    .digest("hex"),
);
"""


class CohortError(RuntimeError):
    """A fail-closed cohort validation or orchestration error."""


class AmbiguousDispatchError(CohortError):
    """The caller cannot prove whether the dashboard accepted a request."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_value(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)
