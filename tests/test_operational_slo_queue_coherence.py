"""Queue telemetry gaps must not masquerade as measured worker stalls."""

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "n8n/bin"))
from operational_slo_queue_policy import evaluate_jobs


class QueueCoherenceTests(unittest.TestCase):
    def test_processing_age_requires_measured_evidence(self):
        for job_type, label in (
            ("ai_analysis", "AI analysis"),
            ("incident_response_analysis", "incident-response analysis"),
        ):
            for age, expected in (
                (None, "processing-age telemetry is unavailable"),
                (0, None),
                (900, None),
                (901, "has been processing without state progress for 15 minutes"),
            ):
                with self.subTest(job_type=job_type, age=age):
                    metrics = {
                        "durable_jobs": [{"job_type": job_type, "status": "processing", "count": 1}],
                        "oldest_processing_jobs": [] if age is None else [
                            {"job_type": job_type, "seconds": age}
                        ],
                    }
                    failures, advisories = [], []
                    evaluate_jobs(metrics, {}, {}, failures, advisories)
                    self.assertEqual(failures, [] if expected is None else [f"{label} {expected}"])

    def test_idle_queue_does_not_require_processing_age(self):
        failures, advisories = [], []
        evaluate_jobs({"durable_jobs": []}, {}, {}, failures, advisories)
        self.assertEqual(failures, [])
