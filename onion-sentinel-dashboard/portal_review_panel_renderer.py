"""Pure analyst review and adjudication panel rendering."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import html


@dataclass(frozen=True)
class ReviewPanelRenderCallbacks:
    """Shared review presentation policies supplied by the portal."""

    html_text: Callable[[object, str], str]
    outcome_label: Callable[[object], str]
    review_defaults: Callable[[], dict]


STATUS_LABELS = {
    "disputed_pending_human": "Disputed — human decision required",
    "review_required_failed": "Independent review failed — human decision required",
    "review_completed_not_authorized": (
        "Review completed — automation not authorized; human decision required"
    ),
    "adjudicated": "Adjudicated",
    "model_consensus": "Primary and reviewer agree",
    "reviewer_advisory": "Reviewer advisory — no material disagreement",
    "unreviewed": "Not independently reviewed",
}

REQUIRED_REVIEW_STATUSES = {
    "disputed_pending_human",
    "review_required_failed",
    "review_completed_not_authorized",
}


def _value(review: dict, *keys: str, fallback: str = "") -> str:
    for key in keys:
        value = review.get(key)
        if value:
            return str(value)
    return fallback


def _comparison(review: dict, callbacks: ReviewPanelRenderCallbacks) -> str:
    reviewer_outcome = _value(review, "reviewer_outcome")
    agreement = _value(review, "reviewer_agreement", "agreement")
    if not reviewer_outcome and not agreement:
        return '<p class="analyst-review-empty">No completed independent reviewer result is attached.</p>'
    text = callbacks.html_text
    primary_label = callbacks.outcome_label(
        _value(review, "primary_outcome", "detection_outcome")
    )
    reviewer_label = callbacks.outcome_label(reviewer_outcome)
    primary_confidence = _value(
        review, "primary_confidence", "analysis_confidence", fallback="confidence unknown"
    )
    reviewer_confidence = _value(
        review, "reviewer_confidence", fallback="confidence unknown"
    )
    return (
        '<div class="analyst-review-comparison">'
        f'<div><b>Primary</b><span>{text(primary_label, "n/a")} · '
        f'{text(primary_confidence, "n/a")}</span></div>'
        f'<div><b>Independent reviewer</b><span>{text(reviewer_label, "n/a")} · '
        f'{text(reviewer_confidence, "n/a")}</span></div></div>'
    )


def _reviewer_failure(review: dict, callbacks: ReviewPanelRenderCallbacks) -> str:
    error = _value(review, "reviewer_error").strip()[:1000]
    if not error:
        return ""
    return (
        '<p class="analyst-review-failure"><b>Reviewer failure:</b> '
        f'{callbacks.html_text(error, "n/a")}</p>'
    )


def _disputed_fields(review: dict, callbacks: ReviewPanelRenderCallbacks) -> str:
    fields = review.get("disputed_fields")
    fields = fields if isinstance(fields, list) else []
    if not fields:
        return ""
    rendered = ", ".join(callbacks.html_text(item, "n/a") for item in fields[:20])
    return f'<p class="analyst-review-disputed-fields"><b>Disputed fields:</b> {rendered}</p>'


def _factored_verdict(adjudication: dict, callbacks: ReviewPanelRenderCallbacks) -> str:
    factors = [
        (label, _value(adjudication, key).strip())
        for key, label in (
            ("event_status", "Event"),
            ("detection_validity", "Detection"),
            ("activity_disposition", "Activity"),
            ("handling", "Handling"),
            ("duplicate_of", "Duplicate of"),
        )
        if _value(adjudication, key).strip()
    ]
    if not factors:
        return ""
    text = callbacks.html_text
    items = "".join(
        f"<li>{text(label, 'n/a')}: {text(value, 'n/a')}</li>"
        for label, value in factors
    )
    return (
        '<div class="analyst-adjudication-factors">'
        f'<b>Analyst-confirmed verdict factors:</b><ul>{items}</ul></div>'
    )


def _optional_adjudication_details(
    adjudication: dict,
    callbacks: ReviewPanelRenderCallbacks,
) -> str:
    text = callbacks.html_text
    details = []
    for label, key in (
        ("Evidence gap", "evidence_gap"),
        ("Next action", "next_action"),
        ("Case resolution", "case_resolution_reason"),
    ):
        value = _value(adjudication, key).strip()
        if value:
            details.append(f'<p><b>{label}:</b> {text(value, "n/a")}</p>')
    return "".join(details)


def _adjudication(review: dict, callbacks: ReviewPanelRenderCallbacks) -> str:
    adjudication = review.get("adjudication")
    adjudication = adjudication if isinstance(adjudication, dict) else {}
    if not adjudication:
        return ""
    text = callbacks.html_text
    outcome = callbacks.outcome_label(adjudication.get("outcome_override"))
    return (
        '<div class="analyst-adjudication-summary">'
        f'<b>Final analyst decision:</b> {text(outcome, "n/a")} · '
        f'{text(adjudication.get("confidence") or "confidence unknown", "n/a")}'
        f'<p>{text(adjudication.get("rationale"), "n/a")}</p>'
        f'{_optional_adjudication_details(adjudication, callbacks)}'
        f'{_factored_verdict(adjudication, callbacks)}'
        f'<small>Reviewed by {text(adjudication.get("reviewer"), "n/a")} at '
        f'{text(adjudication.get("created_at"), "n/a")}</small></div>'
    )


def _case_resolution(review: dict, callbacks: ReviewPanelRenderCallbacks) -> str:
    reason = _value(review, "case_resolution_reason").strip()
    if not reason:
        return ""
    text = callbacks.html_text
    return (
        '<div class="analyst-case-resolution">'
        f'<b>Resolved:</b> {text(reason, "n/a")}<small> by '
        f'{text(review.get("case_resolved_by"), "n/a")} at '
        f'{text(review.get("case_resolved_at"), "n/a")}</small></div>'
    )


def _panel_attributes(review: dict, group_id: str, case_id: str) -> str:
    attributes = (
        ("data-review-group", group_id),
        ("data-review-case", case_id),
        ("data-review-analysis", _value(review, "analysis_id")),
        ("data-review-primary", _value(review, "primary_outcome", "detection_outcome")),
        ("data-review-event-status", _value(review, "primary_event_status")),
        ("data-review-detection-validity", _value(review, "primary_detection_validity")),
        ("data-review-activity-disposition", _value(review, "primary_activity_disposition")),
        ("data-review-handling", _value(review, "primary_handling")),
        ("data-review-duplicate-of", _value(review, "primary_duplicate_of")),
    )
    return " ".join(
        f'{name}="{html.escape(value, quote=True)}"' for name, value in attributes
    )


def _heading(review: dict, final_status: str) -> str:
    freshness = _value(review, "freshness_status", fallback="unknown")
    coverage = _value(review, "coverage_status", fallback="unknown")
    label = STATUS_LABELS.get(final_status, final_status.replace("_", " ").title())
    return (
        '<div class="analyst-review-heading">'
        '<div><span class="analyst-review-eyebrow">Human validation</span>'
        f'<h3>{html.escape(label)}</h3></div><div class="analyst-review-badges">'
        f'<span class="review-badge review-freshness-{html.escape(freshness, quote=True)}">'
        f'Freshness: {html.escape(freshness.replace("_", " "))}</span>'
        f'<span class="review-badge review-coverage-{html.escape(coverage, quote=True)}">'
        f'Coverage: {html.escape(coverage.replace("_", " "))}</span></div></div>'
    )


def _action_button(review: dict, required: bool) -> str:
    disabled = (
        ' disabled title="Run an analysis before recording an analyst decision"'
        if not _value(review, "analysis_id")
        else ""
    )
    label = "Resolve required review" if required else "Record analyst decision"
    return (
        f'<button class="analyst-adjudicate-button" type="button" '
        f'data-open-adjudication{disabled}>{label}</button>'
    )


def render_analyst_review_panel(
    review: dict | None,
    *,
    group_id: str,
    case_id: str = "",
    callbacks: ReviewPanelRenderCallbacks,
) -> str:
    """Render bounded review state and one explicit human-adjudication entry."""
    review = review if isinstance(review, dict) else callbacks.review_defaults()
    final_status = _value(
        review, "final_review_status", "final_status", fallback="unreviewed"
    )
    required = final_status in REQUIRED_REVIEW_STATUSES
    role = ' role="alert"' if required else ""
    return (
        f'<section class="analyst-review-panel review-status-'
        f'{html.escape(final_status, quote=True)}" '
        f'{_panel_attributes(review, group_id, case_id)}{role}>'
        f'{_heading(review, final_status)}{_comparison(review, callbacks)}'
        f'{_reviewer_failure(review, callbacks)}{_disputed_fields(review, callbacks)}'
        f'{_adjudication(review, callbacks)}{_case_resolution(review, callbacks)}'
        f'{_action_button(review, required)}</section>'
    )
