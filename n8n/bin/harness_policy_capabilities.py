"""Harness activation, capability catalogs, and authorization decisions."""
from __future__ import annotations

import dataclasses
from typing import Any

from harness_policy_primitives import AgentRole


EXTERNAL_AGENT_HARNESS_PROVIDERS = frozenset({"hermes-agent", "openclaw"})


def external_agent_harness_provider(route: Any) -> str:
    """Return the third-party agent harness selected by an exact route."""
    normalized = str(route or "").strip().lower()
    return next(
        (
            provider
            for provider in EXTERNAL_AGENT_HARNESS_PROVIDERS
            if normalized == provider or normalized.startswith(f"{provider}:")
        ),
        "",
    )


def should_start_onion_sentinel_harness(
    *,
    policy_enabled: bool,
    assigned_route: Any,
    reviewer_route: Any,
) -> tuple[bool, str]:
    """Keep the custom harness mutually exclusive with external harnesses."""
    if not policy_enabled:
        return False, "investigation harness policy is disabled"
    for route_kind, route in (
        ("assigned", assigned_route),
        ("second-opinion", reviewer_route),
    ):
        provider = external_agent_harness_provider(route)
        if provider:
            return False, f"{route_kind} route uses the external {provider} harness"
    return True, "policy enabled and selected routes are eligible"


READ_ONLY_CAPABILITIES = frozenset(
    {
        "alerts.read", "cases.read", "reports.read",
        "security-onion.events.query", "security-onion.oql.query",
        "endpoint.osquery.query", "pcap.derived.query", "zeek.derived.query",
        "suricata.events.read", "threat-intel.lookup", "detections.read",
        "memory.read",
    }
)
MUTATING_CAPABILITIES = frozenset(
    {
        "alerts.acknowledge", "alerts.suppress", "cases.write",
        "detections.write", "notifications.send", "response.contain",
        "memory.promote",
    }
)
SENSITIVE_ACTIVE_CAPABILITIES = frozenset({"endpoint.osquery.query"})
APPROVAL_GATED_CAPABILITIES = MUTATING_CAPABILITIES | SENSITIVE_ACTIVE_CAPABILITIES
ALL_CAPABILITIES = READ_ONLY_CAPABILITIES | MUTATING_CAPABILITIES
QUERY_BACKEND_CAPABILITIES = {
    "elastic": "security-onion.events.query",
    "oql": "security-onion.oql.query",
    "osquery": "endpoint.osquery.query",
    "pcap_zeek": "pcap.derived.query",
}


def query_backend_capability(backend: object) -> str:
    return QUERY_BACKEND_CAPABILITIES.get(str(backend), "unknown")


def query_backend_is_approval_gated(backend: object) -> bool:
    return query_backend_capability(backend) in APPROVAL_GATED_CAPABILITIES


DEFAULT_ROLE_CAPABILITIES: dict[str, frozenset[str]] = {
    AgentRole.SOC_ANALYST.value: frozenset(
        {
            "alerts.read", "reports.read", "security-onion.events.query",
            "security-onion.oql.query", "endpoint.osquery.query",
            "pcap.derived.query", "zeek.derived.query", "suricata.events.read",
            "threat-intel.lookup", "detections.read", "memory.read",
            "alerts.acknowledge", "alerts.suppress", "cases.write",
            "notifications.send", "memory.promote",
        }
    ),
    AgentRole.INCIDENT_RESPONDER.value: frozenset(
        {
            "alerts.read", "cases.read", "reports.read",
            "security-onion.events.query", "security-onion.oql.query",
            "endpoint.osquery.query", "pcap.derived.query", "zeek.derived.query",
            "suricata.events.read", "threat-intel.lookup", "detections.read",
            "memory.read", "cases.write", "notifications.send",
            "response.contain", "memory.promote",
        }
    ),
    AgentRole.SIEM_ENGINEER.value: frozenset(
        {
            "alerts.read", "cases.read", "reports.read",
            "security-onion.events.query", "security-onion.oql.query",
            "pcap.derived.query", "zeek.derived.query", "suricata.events.read",
            "detections.read", "memory.read", "detections.write",
            "memory.promote",
        }
    ),
    AgentRole.CYBER_THREAT_INTEL.value: frozenset(
        {
            "alerts.read", "cases.read", "reports.read",
            "security-onion.events.query", "security-onion.oql.query",
            "pcap.derived.query", "zeek.derived.query", "suricata.events.read",
            "threat-intel.lookup", "detections.read", "memory.read",
            "memory.promote",
        }
    ),
    AgentRole.THREAT_HUNTER.value: frozenset(
        {
            "alerts.read", "cases.read", "reports.read",
            "security-onion.events.query", "security-onion.oql.query",
            "endpoint.osquery.query", "pcap.derived.query", "zeek.derived.query",
            "suricata.events.read", "threat-intel.lookup", "detections.read",
            "memory.read", "cases.write", "detections.write", "memory.promote",
        }
    ),
}


@dataclasses.dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    capability: str
    reason: str
    requires_approval: bool = False


def policy_decision_is_effective(mode: str, decision: PolicyDecision) -> bool:
    """Allow shadow observation, but never manufacture required approval."""
    return bool(
        decision.allowed
        or (
            str(mode).strip().lower() == "shadow"
            and not decision.requires_approval
        )
    )
