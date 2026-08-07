"""Authorized SOC and incident-response write dispatch for the report portal.

The HTTP handler must complete authentication, same-origin checks, and JSON
validation before calling this module.  Dispatch is deliberately limited to
the operations emitted by :mod:`portal_request_routes` and receives explicit
callbacks so it owns no database, cache, or process state.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from portal_request_routes import PostRoute, SOC_WRITE_OPERATIONS


WriteResponse = tuple[int, dict]
TargetWrite = Callable[[str, dict], WriteResponse]
BulkWrite = Callable[[dict], WriteResponse]


@dataclass(frozen=True)
class SocWriteCallbacks:
    alert_ack: TargetWrite
    alert_pcap: TargetWrite
    alert_analyze: TargetWrite
    alert_escalate: TargetWrite
    alert_adjudicate: TargetWrite
    incident_adjudicate: TargetWrite
    incident_status: TargetWrite
    incident_reanalyze: TargetWrite
    incident_reanalyze_all: BulkWrite


def dispatch_authorized_soc_write(
    route: PostRoute,
    payload: dict,
    callbacks: SocWriteCallbacks,
) -> WriteResponse:
    """Call the single bounded callback selected by an authorized POST route."""
    operation = route.operation
    if operation not in SOC_WRITE_OPERATIONS:
        raise ValueError(f"POST route is not a SOC write operation: {route.path}")
    if operation == 'soc_incident_reanalyze_all':
        return callbacks.incident_reanalyze_all(payload)

    resource_id = route.resource_id
    if resource_id is None:
        raise ValueError(f"SOC write route has no resource target: {route.path}")
    handlers: dict[str, TargetWrite] = {
        'soc_alert_ack': callbacks.alert_ack,
        'soc_alert_pcap': callbacks.alert_pcap,
        'soc_alert_analyze': callbacks.alert_analyze,
        'soc_alert_escalate': callbacks.alert_escalate,
        'soc_alert_adjudicate': callbacks.alert_adjudicate,
        'soc_incident_adjudicate': callbacks.incident_adjudicate,
        'soc_incident_status': callbacks.incident_status,
        'soc_incident_reanalyze': callbacks.incident_reanalyze,
    }
    return handlers[operation](resource_id, payload)
