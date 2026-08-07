"""Pure request-route classification for the legacy report portal handler.

The HTTP handler remains responsible for authentication, body parsing, and
responses.  This module centralizes only method/path policy so GET/HEAD/POST
contracts can be tested without constructing a socket-backed handler.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import AbstractSet


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
ALERT_ACTION_SUFFIXES = ('/ack', '/pcap', '/analyze', '/escalate')


@dataclass(frozen=True)
class PostRoute:
    path: str
    accepted: bool
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


def _dynamic_suffix(path: str, prefix: str, suffixes: tuple[str, ...]) -> bool:
    return path.startswith(prefix) and path.endswith(suffixes)


def classify_post_route(
    path: str,
    *,
    cti_program_path: str,
    prompt_paths: AbstractSet[str],
) -> PostRoute:
    """Classify a POST path without reading headers, bodies, or runtime state."""
    cti_write = path == cti_program_path
    asset_write = path in ASSET_WRITE_PATHS
    incident_reanalysis = path == '/api/soc-incidents/reanalyze-all' or (
        path.startswith('/api/soc-incidents/') and path.endswith('/reanalyze')
    )
    review_write = (
        path.startswith('/api/soc-alerts/') and path.endswith('/adjudicate')
    ) or (
        path.startswith('/api/soc-incidents/')
        and path.endswith(('/adjudicate', '/status'))
    )
    alert_action = _dynamic_suffix(
        path, '/api/soc-alerts/', ALERT_ACTION_SUFFIXES
    )
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
        cti_program_write=cti_write,
        asset_write=asset_write,
        incident_reanalysis=incident_reanalysis,
        review_write=review_write,
        alert_action=alert_action,
        prompt_write=prompt_write,
        resource_write=resource_write,
        json_request=json_request,
    )


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
