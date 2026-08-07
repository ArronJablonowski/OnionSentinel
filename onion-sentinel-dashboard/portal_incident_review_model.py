"""Pure presentation policy for one Incident Response detail review."""
from __future__ import annotations

from dataclasses import dataclass
import json

from portal_incident_read_model import (
    IncidentReviewPresentation,
    IncidentRowCallbacks,
    merge_incident_reviewer,
    present_incident_review,
)


@dataclass(frozen=True)
class IncidentEvidencePresentation:
    updated_at: str
    used_count: int
    gap_count: int
    coverage_status: str
    freshness_status: str


def _nonempty_count(value: object) -> int:
    if isinstance(value, list):
        return len([item for item in value if str(item or '').strip()])
    return 1 if str(value or '').strip() else 0


def parse_analysis_response(analysis: dict | None) -> dict:
    """Decode one persisted analysis response without leaking parser errors."""
    analysis = analysis if isinstance(analysis, dict) else {}
    value = analysis.get('response_json')
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(str(value or '{}'))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _coverage_status(gap_count: int, used_count: int, audit: dict) -> str:
    if gap_count or audit.get('partial'):
        return 'gaps'
    if used_count or audit.get('complete'):
        return 'complete'
    return 'unknown'


def _freshness_status(
    generated_at: str,
    evidence_updated_at: str,
    callbacks: IncidentRowCallbacks,
) -> str:
    if not generated_at:
        return 'not_analyzed'
    if callbacks.epoch(evidence_updated_at) > callbacks.epoch(generated_at):
        return 'stale'
    return 'current'


def _evidence_presentation(
    response: dict,
    generated_at: str,
    evidence_updated_at: str,
    callbacks: IncidentRowCallbacks,
) -> IncidentEvidencePresentation:
    report = response.get('incident_response_report')
    report = report if isinstance(report, dict) else {}
    audit = response.get('_incident_query_audit')
    audit = audit if isinstance(audit, dict) else {}
    used_count = _nonempty_count(report.get('evidence_used'))
    gap_count = _nonempty_count(report.get('evidence_gaps'))
    return IncidentEvidencePresentation(
        evidence_updated_at,
        used_count,
        gap_count,
        _coverage_status(gap_count, used_count, audit),
        _freshness_status(generated_at, evidence_updated_at, callbacks),
    )


def _disputed_fields(reviewer: dict) -> list:
    value = reviewer.get('disputed_fields_json')
    if isinstance(value, list):
        return value[:20]
    try:
        parsed = json.loads(str(value or '[]'))
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    return parsed[:20] if isinstance(parsed, list) else []


def _analysis_fields(analysis: dict, response: dict) -> dict:
    return {
        'analysis_id': str(analysis.get('analysis_id') or ''),
        'analysis_generated_at': str(analysis.get('generated_at') or ''),
        'analysis_confidence': str(analysis.get('confidence') or ''),
        'analysis_evidence_hash': str(analysis.get('evidence_hash') or ''),
        'primary_event_status': str(response.get('event_status') or ''),
        'primary_detection_validity': str(
            response.get('detection_validity') or ''
        ),
        'primary_activity_disposition': str(
            response.get('activity_disposition') or ''
        ),
        'primary_handling': str(response.get('handling') or ''),
        'primary_duplicate_of': response.get('duplicate_of'),
    }


def _evidence_fields(evidence: IncidentEvidencePresentation) -> dict:
    return {
        'freshness_status': evidence.freshness_status,
        'evidence_updated_at': evidence.updated_at,
        'coverage_status': evidence.coverage_status,
        'evidence_used_count': evidence.used_count,
        'evidence_gap_count': evidence.gap_count,
    }


def _review_fields(
    state: IncidentReviewPresentation,
    reviewer: dict,
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
        'reviewer_status': str(state.reviewer_status),
        'reviewer_error': str(state.reviewer_error)[:1000],
        'reviewer_outcome': str(state.reviewer_outcome),
        'reviewer_confidence': str(state.reviewer_confidence),
        'reviewer_agreement': str(state.reviewer_agreement),
        'automation_authorization': state.automation_authorization,
        'material_disagreement': state.material_disagreement,
        'disputed_fields': _disputed_fields(reviewer),
        'final_review_status': state.final_status,
        'adjudication': state.adjudication,
    }


def _case_fields(case: dict) -> dict:
    return {
        'case_resolution_reason': str(case.get('resolution_reason') or ''),
        'case_resolved_at': str(case.get('resolved_at') or ''),
        'case_resolved_by': str(case.get('resolved_by') or ''),
    }


def compose_incident_review_state(
    case: dict,
    analysis: dict,
    response: dict,
    evidence_updated_at: str,
    reviewer: dict | None,
    adjudication: dict | None,
    defaults: dict,
    callbacks: IncidentRowCallbacks,
) -> dict:
    """Compose one durable incident detail review without persistence access."""
    analysis = dict(analysis or {})
    response = dict(response or {})
    evidence = _evidence_presentation(
        response,
        str(analysis.get('generated_at') or ''),
        evidence_updated_at,
        callbacks,
    )
    merged = merge_incident_reviewer(
        response, analysis, reviewer, callbacks
    )
    review = present_incident_review(
        analysis, merged, adjudication, callbacks
    )
    return {
        **defaults,
        **_analysis_fields(analysis, response),
        **_review_fields(review, merged, callbacks),
        **_evidence_fields(evidence),
        **_case_fields(case),
    }


def compose_incident_detail_payload(
    case_id: str,
    case: dict,
    response: dict,
    review: dict,
    incident_html: str,
    prior_ai_html: str,
    query_count: int,
) -> dict:
    """Assemble the stable Incident Response detail API payload."""
    return {
        'ok': True,
        'case_id': case_id,
        'agent_status': case.get('agent_status') or 'queued',
        'analysis_available': bool(response.get('incident_response_report')),
        'query_count': query_count,
        'review': review,
        'incident_html': incident_html,
        'prior_ai_html': prior_ai_html,
    }
