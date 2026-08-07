"""Pure request-route classification for the legacy report portal handler.

The HTTP handler remains responsible for authentication, body parsing, and
responses.  This module centralizes only method/path policy so GET/HEAD/POST
contracts can be tested without constructing a socket-backed handler.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import AbstractSet
from urllib.parse import unquote


HEAD_EXACT_PATHS = frozenset({
    '/', '/index.html', '/healthz', '/api/reports',
    '/api/admin/session-status', '/api/asset-inventory',
    '/api/dhcp-asset-discovery', '/api/software-inventory',
    '/api/llm-analysis/current', '/api/llm-analysis/logs',
    '/api/system-health/beacons', '/api/soc-alerts',
    '/api/soc-alerts/events', '/api/soc-alerts/metrics',
    '/api/soc-alerts/suppressions', '/api/soc-alerts/status',
    '/api/soc-incidents', '/api/soc-incidents/reanalysis-runs',
    '/api/soc-settings/agent-memory', '/api/soc-settings/ai-model',
    '/api/soc-settings/ollama-models', '/api/resource-library/favorites',
    '/admin', '/admin/login',
})
GET_EXACT_OPERATIONS = {
    '/': 'home',
    '/index.html': 'home',
    '/admin/login': 'admin_login',
    '/admin': 'admin',
    '/healthz': 'health',
    '/api/admin/session-status': 'admin_session_status',
    '/api/admin/service-status': 'admin_service_status',
    '/api/resource-library/favorites': 'resource_favorites',
    '/api/system-health/beacons': 'system_health_beacons',
    '/api/asset-inventory': 'asset_inventory',
    '/api/dhcp-asset-discovery': 'dhcp_asset_discovery',
    '/api/software-inventory': 'software_inventory',
    '/api/llm-analysis/current': 'llm_analysis_current',
    '/api/llm-analysis/logs': 'llm_analysis_logs',
    '/api/soc-alerts/events': 'soc_alert_events',
    '/api/soc-alerts/status': 'soc_alert_status',
    '/api/soc-settings/agent-memory': 'soc_agent_memory',
    '/api/soc-settings/ai-model': 'soc_ai_model',
    '/api/soc-settings/ollama-models': 'soc_ollama_models',
    '/api/soc-alerts': 'soc_alerts',
    '/api/soc-alerts/metrics': 'soc_alert_metrics',
    '/api/soc-alerts/suppressions': 'soc_alert_suppressions',
    '/api/soc-incidents': 'soc_incidents',
    '/api/soc-incidents/reanalysis-runs': 'soc_reanalysis_runs',
    '/api/resource-library/action-status': 'resource_action_status',
}
POST_FORM_PATHS = frozenset({
    '/admin/login', '/admin/logout', '/admin/action',
})
POST_JSON_EXACT_PATHS = frozenset({
    '/api/admin/start-service', '/api/soc-alerts/status',
    '/api/soc-settings/ai-model', '/api/soc-settings/agent-model',
})
RESOURCE_WRITE_PATHS = frozenset({
    '/api/resource-library/remove', '/api/resource-library/tags',
    '/api/resource-library/rename', '/api/resource-library/favorite',
})
ASSET_WRITE_PATHS = frozenset({
    '/api/assets/promote-dhcp', '/api/assets/approve-dhcp-ip-change',
    '/api/assets/update', '/api/assets/demote',
})
SOC_ALERT_PREFIX = '/api/soc-alerts/'
SOC_INCIDENT_PREFIX = '/api/soc-incidents/'
SOC_WRITE_OPERATIONS = frozenset({
    'soc_alert_ack',
    'soc_alert_pcap',
    'soc_alert_analyze',
    'soc_alert_escalate',
    'soc_alert_adjudicate',
    'soc_incident_adjudicate',
    'soc_incident_status',
    'soc_incident_reanalyze',
    'soc_incident_reanalyze_all',
})


@dataclass(frozen=True)
class PostRoute:
    path: str
    accepted: bool
    operation: str | None
    resource_id: str | None
    cti_program_write: bool
    asset_write: bool
    incident_reanalysis: bool
    review_write: bool
    alert_action: bool
    prompt_write: bool
    resource_write: bool
    json_request: bool

    def request_limit(self, cti_file_bytes: int) -> int:
        return cti_file_bytes if self.cti_program_write else 50_000


@dataclass(frozen=True)
class GetRoute:
    path: str
    operation: str | None
    resource_id: str | None = None


def _dynamic_target(
    path: str,
    prefix: str,
    suffix: str,
) -> str | None:
    if not path.startswith(prefix) or not path.endswith(suffix):
        return None
    encoded_id = path[len(prefix):-len(suffix)].strip('/')
    return unquote(encoded_id)


def _soc_write_target(path: str) -> tuple[str | None, str | None]:
    if path == '/api/soc-incidents/reanalyze-all':
        return 'soc_incident_reanalyze_all', None
    candidates = (
        (SOC_ALERT_PREFIX, '/ack', 'soc_alert_ack'),
        (SOC_ALERT_PREFIX, '/pcap', 'soc_alert_pcap'),
        (SOC_ALERT_PREFIX, '/analyze', 'soc_alert_analyze'),
        (SOC_ALERT_PREFIX, '/escalate', 'soc_alert_escalate'),
        (SOC_ALERT_PREFIX, '/adjudicate', 'soc_alert_adjudicate'),
        (SOC_INCIDENT_PREFIX, '/adjudicate', 'soc_incident_adjudicate'),
        (SOC_INCIDENT_PREFIX, '/status', 'soc_incident_status'),
        (SOC_INCIDENT_PREFIX, '/reanalyze', 'soc_incident_reanalyze'),
    )
    for prefix, suffix, operation in candidates:
        resource_id = _dynamic_target(path, prefix, suffix)
        if resource_id is not None:
            return operation, resource_id
    return None, None


def classify_post_route(
    path: str,
    *,
    cti_program_path: str,
    prompt_paths: AbstractSet[str],
) -> PostRoute:
    """Classify a POST path without reading headers, bodies, or runtime state."""
    operation, resource_id = _soc_write_target(path)
    cti_write = path == cti_program_path
    asset_write = path in ASSET_WRITE_PATHS
    incident_reanalysis = operation in {
        'soc_incident_reanalyze', 'soc_incident_reanalyze_all',
    }
    review_write = operation in {
        'soc_alert_adjudicate', 'soc_incident_adjudicate',
        'soc_incident_status',
    }
    alert_action = operation in {
        'soc_alert_ack', 'soc_alert_pcap', 'soc_alert_analyze',
        'soc_alert_escalate',
    }
    prompt_write = path in prompt_paths
    resource_write = path in RESOURCE_WRITE_PATHS
    json_request = bool(
        path in POST_JSON_EXACT_PATHS
        or prompt_write
        or alert_action
        or review_write
        or incident_reanalysis
        or asset_write
        or cti_write
        or resource_write
    )
    accepted = bool(path in POST_FORM_PATHS or json_request)
    return PostRoute(
        path=path,
        accepted=accepted,
        operation=operation,
        resource_id=resource_id,
        cti_program_write=cti_write,
        asset_write=asset_write,
        incident_reanalysis=incident_reanalysis,
        review_write=review_write,
        alert_action=alert_action,
        prompt_write=prompt_write,
        resource_write=resource_write,
        json_request=json_request,
    )


def classify_get_route(
    path: str,
    *,
    cti_program_path: str,
    prompt_paths: AbstractSet[str],
) -> GetRoute:
    """Classify portal pages and API reads before report-catalog routing."""
    operation = GET_EXACT_OPERATIONS.get(path)
    if operation is not None:
        return GetRoute(path=path, operation=operation)
    if path == cti_program_path:
        return GetRoute(path=path, operation='cti_program')
    if path in prompt_paths:
        return GetRoute(path=path, operation='soc_settings_prompt')

    candidates = (
        (SOC_INCIDENT_PREFIX, '/adjudications', 'incident_adjudications'),
        (SOC_INCIDENT_PREFIX, '/detail', 'incident_detail'),
        (SOC_ALERT_PREFIX, '/adjudications', 'alert_adjudications'),
        (SOC_ALERT_PREFIX, '/detail', 'alert_detail_fragment'),
    )
    for prefix, suffix, dynamic_operation in candidates:
        resource_id = _dynamic_target(path, prefix, suffix)
        if resource_id is not None:
            return GetRoute(
                path=path,
                operation=dynamic_operation,
                resource_id=resource_id,
            )
    if path.startswith(SOC_ALERT_PREFIX):
        resource_id = unquote(path[len(SOC_ALERT_PREFIX):].strip('/'))
        return GetRoute(
            path=path,
            operation='alert_detail',
            resource_id=resource_id,
        )
    return GetRoute(path=path, operation=None)


def is_head_route(
    path: str,
    *,
    cti_program_path: str,
    prompt_paths: AbstractSet[str],
) -> bool:
    """Return whether the legacy portal advertises this path to HEAD clients."""
    return bool(
        path in HEAD_EXACT_PATHS
        or path == cti_program_path
        or path in prompt_paths
        or (path.startswith('/api/soc-incidents/') and path.endswith('/detail'))
        or (
            path.startswith('/api/soc-alerts/')
            and not path.endswith(('/ack', '/escalate'))
        )
    )


def head_content_type(path: str) -> str:
    if path in {'/', '/index.html', '/admin', '/admin/login'}:
        return 'text/html; charset=utf-8'
    if path == '/api/soc-alerts/events':
        return 'text/event-stream; charset=utf-8'
    return 'application/json; charset=utf-8'
