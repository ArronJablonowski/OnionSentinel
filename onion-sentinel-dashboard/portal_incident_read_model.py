"""Pure query policy for the Incident Response list read model."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json


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


@dataclass(frozen=True)
class IncidentRowCallbacks:
    epoch: Callable[[object], float]
    embedded_reviewer: Callable[[dict, dict], dict]
    final_review_status: Callable[[dict, bool, dict | None], str]
    outcome_label: Callable[[object], str]
    agent_display_state: Callable[[object, object, object], tuple[str, str]]
    reviewer_authorization: Callable[[dict], dict]
    resolve_asset_ip: Callable[[object, object, dict], dict]


@dataclass(frozen=True)
class IncidentAnalysisPresentation:
    response: dict
    evidence_gap_count: int
    coverage_status: str
    freshness_status: str


@dataclass(frozen=True)
class IncidentReviewPresentation:
    adjudication: dict | None
    final_status: str
    primary_outcome: str
    primary_confidence: str
    effective_outcome: str
    effective_confidence: str
    material_disagreement: bool
    reviewer_status: object
    reviewer_error: object
    reviewer_outcome: object
    reviewer_confidence: object
    reviewer_agreement: object
    automation_authorization: object


@dataclass(frozen=True)
class IncidentAssetPresentation:
    observed_at: object
    source: dict
    destination: dict


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


def select_incident_analysis(
    item: dict,
    analyses: dict[str, dict],
    run_columns: set[str],
) -> dict:
    """Return only the latest analysis bound to this case and agent role."""
    analysis_id = str(item.get('latest_analysis_id') or '')
    analysis = dict(analyses.get(analysis_id) or {})
    return analysis if _analysis_matches_case(item, analysis, run_columns) else {}


def _analysis_matches_case(
    item: dict,
    analysis: dict,
    run_columns: set[str],
) -> bool:
    if not analysis:
        return True
    if 'group_id' in run_columns:
        if str(analysis.get('group_id') or '') != str(item.get('group_id') or ''):
            return False
    if 'agent_role' in run_columns:
        if str(analysis.get('agent_role') or '') != 'incident-responder':
            return False
    return True


def _json_object(value: object) -> dict:
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(str(value or '{}'))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _nonempty_count(value: object) -> int:
    if isinstance(value, list):
        return len([item for item in value if str(item or '').strip()])
    return 1 if str(value or '').strip() else 0


def _value_or(value: object, fallback: object) -> object:
    return value if value else fallback


def _first_text(*values: object) -> str:
    for value in values:
        if value:
            return str(value)
    return ''


def _analysis_presentation(
    item: dict,
    analysis: dict,
    callbacks: IncidentRowCallbacks,
) -> IncidentAnalysisPresentation:
    response = _json_object(analysis.get('response_json'))
    report = response.get('incident_response_report')
    report = report if isinstance(report, dict) else {}
    gap_count = _nonempty_count(report.get('evidence_gaps'))
    query_audit = response.get('_incident_query_audit')
    query_audit = query_audit if isinstance(query_audit, dict) else {}
    coverage = (
        'gaps'
        if gap_count or query_audit.get('partial')
        else 'complete'
        if query_audit.get('complete')
        else 'unknown'
    )
    generated_at = str(analysis.get('generated_at') or '')
    freshness = (
        'stale'
        if generated_at
        and callbacks.epoch(item.get('last_seen')) > callbacks.epoch(generated_at)
        else 'current'
        if generated_at
        else 'not_analyzed'
    )
    return IncidentAnalysisPresentation(response, gap_count, coverage, freshness)


def _merge_reviewer(
    response: dict,
    analysis: dict,
    reviewer: dict | None,
    callbacks: IncidentRowCallbacks,
) -> dict:
    reviewer_state = dict(reviewer or {})
    embedded = callbacks.embedded_reviewer(response, analysis)
    if not reviewer_state:
        return embedded
    if not reviewer_state.get('reviewer_error'):
        reviewer_state['reviewer_error'] = embedded.get('reviewer_error') or ''
    reviewer_state['automation_authorization'] = (
        embedded.get('automation_authorization') or {}
    )
    return reviewer_state


def _base_review_presentation(
    analysis: dict,
    reviewer: dict,
    adjudication: dict | None,
    callbacks: IncidentRowCallbacks,
) -> IncidentReviewPresentation:
    material = str(
        reviewer.get('material_disagreement') or ''
    ).strip().lower() in {'1', 'true', 'yes'}
    adjudication = dict(adjudication) if adjudication else None
    primary_outcome = _first_text(
        reviewer.get('primary_outcome'), analysis.get('detection_outcome')
    )
    primary_confidence = _first_text(
        reviewer.get('primary_confidence'), analysis.get('confidence')
    )
    effective_outcome = str(
        adjudication.get('outcome_override') if adjudication else primary_outcome
    )
    effective_confidence = str(
        adjudication.get('confidence') if adjudication else primary_confidence
    )
    return IncidentReviewPresentation(
        adjudication=adjudication,
        final_status=callbacks.final_review_status(
            reviewer, material, adjudication
        ),
        primary_outcome=primary_outcome,
        primary_confidence=primary_confidence,
        effective_outcome=effective_outcome,
        effective_confidence=effective_confidence,
        material_disagreement=material,
        reviewer_status=_value_or(reviewer.get('status'), 'not_requested'),
        reviewer_error=_value_or(reviewer.get('reviewer_error'), ''),
        reviewer_outcome=_value_or(reviewer.get('reviewer_outcome'), ''),
        reviewer_confidence=_value_or(reviewer.get('reviewer_confidence'), ''),
        reviewer_agreement=_value_or(reviewer.get('agreement'), ''),
        automation_authorization=_value_or(
            callbacks.reviewer_authorization(reviewer), {}
        ),
    )


def _fallback_review_presentation(
    fallback: dict,
) -> IncidentReviewPresentation:
    primary_outcome = _first_text(fallback.get('primary_outcome'))
    primary_confidence = _first_text(fallback.get('primary_confidence'))
    raw_adjudication = fallback.get('adjudication')
    adjudication = (
        dict(raw_adjudication) if isinstance(raw_adjudication, dict) else None
    )
    return IncidentReviewPresentation(
        adjudication=adjudication,
        final_status=_first_text(
            fallback.get('final_review_status'), 'unreviewed'
        ),
        primary_outcome=primary_outcome,
        primary_confidence=primary_confidence,
        effective_outcome=_first_text(
            fallback.get('effective_outcome'), primary_outcome
        ),
        effective_confidence=_first_text(
            fallback.get('effective_confidence'), primary_confidence
        ),
        material_disagreement=bool(fallback.get('material_disagreement')),
        reviewer_status=_value_or(
            fallback.get('reviewer_status'), 'not_requested'
        ),
        reviewer_error=_value_or(fallback.get('reviewer_error'), ''),
        reviewer_outcome=_value_or(fallback.get('reviewer_outcome'), ''),
        reviewer_confidence=_value_or(
            fallback.get('reviewer_confidence'), ''
        ),
        reviewer_agreement=_value_or(fallback.get('reviewer_agreement'), ''),
        automation_authorization=_value_or(
            fallback.get('automation_authorization'), {}
        ),
    )


def _review_presentation(
    analysis: dict,
    response: dict,
    reviewer: dict | None,
    adjudication: dict | None,
    fallback: dict,
    callbacks: IncidentRowCallbacks,
) -> IncidentReviewPresentation:
    if fallback:
        return _fallback_review_presentation(fallback)
    merged = _merge_reviewer(response, analysis, reviewer, callbacks)
    return _base_review_presentation(
        analysis, merged, adjudication, callbacks
    )


def _asset_presentation(
    item: dict,
    inventory: dict,
    inventory_error: object,
    callbacks: IncidentRowCallbacks,
) -> IncidentAssetPresentation:
    observed_at = (
        item.get('last_seen') or item.get('escalated_at') or item.get('updated_at')
    )
    if inventory_error:
        return IncidentAssetPresentation(
            observed_at,
            {'status': 'inventory_unavailable', 'ip': str(item.get('source_ip') or '')},
            {'status': 'inventory_unavailable', 'ip': str(item.get('destination_ip') or '')},
        )
    return IncidentAssetPresentation(
        observed_at,
        callbacks.resolve_asset_ip(item.get('source_ip'), observed_at, inventory),
        callbacks.resolve_asset_ip(
            item.get('destination_ip'), observed_at, inventory
        ),
    )


def _analysis_fields(
    analysis: dict,
    state: IncidentAnalysisPresentation,
) -> dict:
    response = state.response
    return {
        'analysis_id': _value_or(analysis.get('analysis_id'), ''),
        'analysis_generated_at': _value_or(analysis.get('generated_at'), ''),
        'analysis_model': _value_or(analysis.get('model'), ''),
        'detection_outcome': _value_or(analysis.get('detection_outcome'), ''),
        'primary_event_status': str(_value_or(response.get('event_status'), '')),
        'primary_detection_validity': str(
            _value_or(response.get('detection_validity'), '')
        ),
        'primary_activity_disposition': str(
            _value_or(response.get('activity_disposition'), '')
        ),
        'primary_handling': str(_value_or(response.get('handling'), '')),
        'primary_duplicate_of': response.get('duplicate_of'),
        'analysis_bluf': _value_or(analysis.get('bluf'), ''),
        'analysis_summary': _value_or(analysis.get('summary'), ''),
        'analysis_confidence': _value_or(analysis.get('confidence'), ''),
        'analysis_evidence_hash': _value_or(analysis.get('evidence_hash'), ''),
        'analysis_available': bool(analysis.get('analysis_id')),
        'freshness_status': state.freshness_status,
        'coverage_status': state.coverage_status,
        'evidence_gap_count': state.evidence_gap_count,
    }


def _review_fields(
    state: IncidentReviewPresentation,
    callbacks: IncidentRowCallbacks,
) -> dict:
    return {
        'primary_outcome': state.primary_outcome,
        'primary_confidence': state.primary_confidence,
        'effective_outcome': state.effective_outcome,
        'effective_outcome_label': callbacks.outcome_label(
            state.effective_outcome
        ),
        'effective_confidence': state.effective_confidence,
        'reviewer_status': state.reviewer_status,
        'reviewer_error': state.reviewer_error,
        'reviewer_outcome': state.reviewer_outcome,
        'reviewer_confidence': state.reviewer_confidence,
        'reviewer_agreement': state.reviewer_agreement,
        'automation_authorization': state.automation_authorization,
        'material_disagreement': state.material_disagreement,
        'final_review_status': state.final_status,
        'adjudication': state.adjudication,
    }


def compose_incident_row(
    item: dict,
    analysis: dict,
    reviewer: dict | None,
    adjudication: dict | None,
    fallback_review: dict | None,
    inventory: dict,
    inventory_error: object,
    callbacks: IncidentRowCallbacks,
) -> dict:
    """Compose one incident list row without database or filesystem access."""
    analysis = dict(analysis or {})
    fallback_review = dict(fallback_review or {})
    analysis_id = str(analysis.get('analysis_id') or '')
    analysis_state = _analysis_presentation(item, analysis, callbacks)
    review_state = _review_presentation(
        analysis,
        analysis_state.response,
        reviewer,
        adjudication,
        fallback_review,
        callbacks,
    )
    agent_display_status, agent_display_label = callbacks.agent_display_state(
        item.get('agent_status'), analysis_id, review_state.reviewer_status
    )
    count = max(
        int(_value_or(item.get('raw_alert_count'), 0)),
        int(_value_or(item.get('total_seen_count'), 0)),
    )
    asset_state = _asset_presentation(
        item, inventory, inventory_error, callbacks
    )
    return {
        **item,
        'seen_count': count,
        'asset_observed_at': str(_value_or(asset_state.observed_at, '')),
        'source_asset': asset_state.source,
        'destination_asset': asset_state.destination,
        **_analysis_fields(analysis, analysis_state),
        **_review_fields(review_state, callbacks),
        'agent_display_status': agent_display_status,
        'agent_display_label': agent_display_label,
    }
