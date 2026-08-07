"""Pure query policy for the Incident Response list read model."""
from __future__ import annotations

from dataclasses import dataclass


ALLOWED_STATUSES = frozenset({'all', 'open', 'in_progress', 'resolved'})
ALLOWED_SORT_KEYS = frozenset({
    'status', 'severity', 'escalated', 'alert', 'source', 'destination',
    'destination_port', 'count', 'agent', 'updated', 'priority',
})
COMMON_SORT_SQL = {
    'status': 'c.status',
    'escalated': 'c.escalated_at',
    'agent': 'c.agent_status',
    'updated': 'c.updated_at',
}
SUMMARY_SORT_SQL = {
    **COMMON_SORT_SQL,
    'severity': 'COALESCE(g.severity, a.severity, 0)',
    'alert': "COALESCE(g.rule_name, a.rule_name, '') COLLATE NOCASE",
    'source': "COALESCE(g.source_ip, a.source_ip, '') COLLATE NOCASE",
    'destination': (
        "COALESCE(g.destination_ip, a.destination_ip, '') COLLATE NOCASE"
    ),
    'destination_port': (
        'COALESCE(g.destination_port, a.destination_port, -1)'
    ),
    'count': 'COALESCE(g.total_seen_count, a.seen_count, 0)',
}
PRIORITY_ORDER_SQL = (
    "CASE c.status WHEN 'open' THEN 0 "
    "WHEN 'in_progress' THEN 1 ELSE 2 END, "
    "CASE c.agent_status WHEN 'analyzing' THEN 0 "
    "WHEN 'queued' THEN 1 WHEN 'failed' THEN 2 ELSE 3 END, "
    'c.updated_at DESC, c.case_id DESC'
)


class IncidentQueryError(ValueError):
    """Raised when a caller requests an unsupported incident-list policy."""


@dataclass(frozen=True)
class IncidentListRequest:
    page: int
    per_page: int
    status: str
    sort: str
    direction: str

    @property
    def where_sql(self) -> str:
        return '' if self.status == 'all' else 'WHERE c.status = ?'

    @property
    def where_arguments(self) -> list[object]:
        return [] if self.status == 'all' else [self.status]

    def pagination(self, total: int) -> tuple[int, int, int]:
        pages = max(1, (max(0, total) + self.per_page - 1) // self.per_page)
        page = min(self.page, pages)
        return page, pages, (page - 1) * self.per_page


def _positive_int(raw: object, default: int, maximum: int | None = None) -> int:
    try:
        value = int(str(raw or default))
    except ValueError:
        value = default
    value = max(1, value)
    return min(maximum, value) if maximum is not None else value


def _query_value(
    query: dict[str, list[str]],
    key: str,
    default: str,
) -> str:
    values = query.get(key)
    if not values or not values[0]:
        return default
    return values[0]


def parse_incident_list_request(
    query: dict[str, list[str]],
    *,
    max_per_page: int,
) -> IncidentListRequest:
    page = _positive_int(_query_value(query, 'page', '1'), 1)
    per_page = _positive_int(
        _query_value(query, 'per_page', '25'), 25, max_per_page
    )
    status = _query_value(query, 'status', 'all').strip().lower()
    sort = _query_value(query, 'sort', 'priority').strip().lower()
    direction = _query_value(query, 'direction', 'desc').strip().lower()
    if status not in ALLOWED_STATUSES:
        raise IncidentQueryError('Invalid incident status filter')
    if sort not in ALLOWED_SORT_KEYS:
        raise IncidentQueryError('Invalid incident sort field')
    if direction not in {'asc', 'desc'}:
        raise IncidentQueryError('Invalid incident sort direction')
    return IncidentListRequest(page, per_page, status, sort, direction)


def incident_order_sql(request: IncidentListRequest, summary_ready: bool) -> str:
    if request.sort == 'priority':
        return PRIORITY_ORDER_SQL
    expressions = SUMMARY_SORT_SQL if summary_ready else COMMON_SORT_SQL
    expression = expressions.get(request.sort, 'c.updated_at')
    direction = 'ASC' if request.direction == 'asc' else 'DESC'
    return f'{expression} {direction}, c.updated_at DESC, c.case_id DESC'


def optional_case_selects(columns: set[str]) -> tuple[str, str, str]:
    return (
        'c.resolution_reason'
        if 'resolution_reason' in columns
        else 'NULL AS resolution_reason',
        'c.resolved_at' if 'resolved_at' in columns else 'NULL AS resolved_at',
        'c.resolved_by' if 'resolved_by' in columns else 'NULL AS resolved_by',
    )


def empty_incident_page(request: IncidentListRequest) -> dict:
    return {
        'ok': True,
        'incidents': [],
        'page': 1,
        'per_page': request.per_page,
        'total': 0,
        'pages': 1,
        'status_counts': {},
        'agent_status_counts': {},
        'schema_ready': False,
    }
