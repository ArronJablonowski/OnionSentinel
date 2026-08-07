"""Behavior contracts for analyst review and adjudication panel rendering."""
from __future__ import annotations

import html
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_review_panel_renderer import (  # noqa: E402
    ReviewPanelRenderCallbacks,
    render_analyst_review_panel,
)


OUTCOME_LABELS = {
    "true_positive_suspicious": "TP - Suspicious",
    "false_positive_logic_rule": "FP - Rule",
    "inconclusive": "Inconclusive",
}


def html_text(value: object, fallback: str = "n/a") -> str:
    return html.escape(str(value or "").strip() or fallback)


def outcome_label(value: object) -> str:
    key = re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")
    return OUTCOME_LABELS.get(key, key.replace("_", " ").title()) if key else "n/a"


def review_defaults() -> dict:
    return {
        "analysis_id": "",
        "freshness_status": "not_analyzed",
        "coverage_status": "unknown",
        "final_review_status": "unreviewed",
    }


class ReviewPanelRendererTests(unittest.TestCase):
    def setUp(self) -> None:
        self.callbacks = ReviewPanelRenderCallbacks(
            html_text=html_text,
            outcome_label=outcome_label,
            review_defaults=review_defaults,
        )

    def render(self, review: dict | None, *, group_id: str = "group-1", case_id: str = "ir-1") -> str:
        return render_analyst_review_panel(
            review,
            group_id=group_id,
            case_id=case_id,
            callbacks=self.callbacks,
        )

    def test_default_state_is_unreviewed_and_action_is_disabled(self) -> None:
        rendered = self.render(None)

        self.assertIn("review-status-unreviewed", rendered)
        self.assertIn("Not independently reviewed", rendered)
        self.assertIn("Freshness: not analyzed", rendered)
        self.assertIn("Coverage: unknown", rendered)
        self.assertIn("No completed independent reviewer result", rendered)
        self.assertIn("Record analyst decision", rendered)
        self.assertIn("data-open-adjudication disabled", rendered)
        self.assertNotIn('role="alert"', rendered)

    def test_each_required_review_state_is_alerting_and_actionable(self) -> None:
        cases = {
            "disputed_pending_human": "Disputed — human decision required",
            "review_required_failed": "Independent review failed — human decision required",
            "review_completed_not_authorized": (
                "Review completed — automation not authorized; human decision required"
            ),
        }
        for final_status, label in cases.items():
            with self.subTest(final_status=final_status):
                rendered = self.render(
                    {"analysis_id": "analysis-1", "final_review_status": final_status}
                )
                self.assertIn(f"review-status-{final_status}", rendered)
                self.assertIn(f"<h3>{label}</h3>", rendered)
                self.assertIn('role="alert"', rendered)
                self.assertIn("Resolve required review", rendered)
                self.assertNotIn("data-open-adjudication disabled", rendered)

    def test_comparison_and_attributes_are_escaped(self) -> None:
        rendered = self.render(
            {
                "analysis_id": 'analysis"><script>',
                "final_status": "model_consensus",
                "primary_outcome": "true_positive_suspicious",
                "primary_confidence": "high <confidence>",
                "primary_event_status": 'observed" onclick="bad',
                "primary_detection_validity": "valid",
                "primary_activity_disposition": "suspicious",
                "primary_handling": "investigate",
                "primary_duplicate_of": "group-0",
                "reviewer_outcome": "false_positive_logic_rule",
                "reviewer_confidence": "medium",
                "reviewer_agreement": "disagree",
                "freshness_status": "current",
                "coverage_status": "complete",
            },
            group_id='group"><bad>',
            case_id='ir"><bad>',
        )

        self.assertIn("Primary and reviewer agree", rendered)
        self.assertIn("TP - Suspicious · high &lt;confidence&gt;", rendered)
        self.assertIn("FP - Rule · medium", rendered)
        self.assertIn('data-review-group="group&quot;&gt;&lt;bad&gt;"', rendered)
        self.assertIn('data-review-case="ir&quot;&gt;&lt;bad&gt;"', rendered)
        self.assertIn("observed&quot; onclick=&quot;bad", rendered)
        self.assertNotIn("<script>", rendered)

    def test_adjudication_and_resolution_render_all_factored_evidence(self) -> None:
        rendered = self.render(
            {
                "analysis_id": "analysis-2",
                "final_review_status": "adjudicated",
                "disputed_fields": ["outcome", "confidence <level>"],
                "reviewer_error": "review failed <temporarily>",
                "adjudication": {
                    "outcome_override": "inconclusive",
                    "confidence": "medium",
                    "rationale": "Evidence remains <partial>.",
                    "evidence_gap": "No endpoint response",
                    "next_action": "Collect endpoint evidence",
                    "case_resolution_reason": "Monitoring",
                    "event_status": "observed",
                    "detection_validity": "valid",
                    "activity_disposition": "unknown",
                    "handling": "monitor",
                    "duplicate_of": "group-previous",
                    "reviewer": "analyst <one>",
                    "created_at": "2026-08-07T12:00:00Z",
                },
                "case_resolution_reason": "Resolved after review",
                "case_resolved_by": "analyst-two",
                "case_resolved_at": "2026-08-07T13:00:00Z",
            }
        )

        self.assertIn("Final analyst decision:</b> Inconclusive · medium", rendered)
        self.assertIn("Evidence remains &lt;partial&gt;.", rendered)
        self.assertIn("<b>Evidence gap:</b> No endpoint response", rendered)
        self.assertIn("<b>Next action:</b> Collect endpoint evidence", rendered)
        self.assertIn("<b>Case resolution:</b> Monitoring", rendered)
        self.assertIn("Event: observed", rendered)
        self.assertIn("Detection: valid", rendered)
        self.assertIn("Activity: unknown", rendered)
        self.assertIn("Handling: monitor", rendered)
        self.assertIn("Duplicate of: group-previous", rendered)
        self.assertIn("Reviewer failure:</b> review failed &lt;temporarily&gt;", rendered)
        self.assertIn("confidence &lt;level&gt;", rendered)
        self.assertIn("Resolved:</b> Resolved after review", rendered)

    def test_reviewer_error_and_disputed_fields_are_bounded(self) -> None:
        fields = [f"field-{index}" for index in range(25)]
        rendered = self.render(
            {
                "analysis_id": "analysis-3",
                "reviewer_error": "x" * 1200,
                "disputed_fields": fields,
            }
        )

        self.assertIn("x" * 1000, rendered)
        self.assertNotIn("x" * 1001, rendered)
        self.assertIn("field-19", rendered)
        self.assertNotIn("field-20", rendered)


if __name__ == "__main__":
    unittest.main()
