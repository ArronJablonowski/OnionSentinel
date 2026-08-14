#!/usr/bin/env python3
"""Contracts for late-bound portal operational runtime helpers."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_operational_runtime import load_cron_summaries  # noqa: E402


@dataclass(frozen=True)
class Summary:
    jid: str
    name: str
    schedule: str
    next_run: str
    enabled: bool
    state: str
    last_status: str
    sort_key: str


class CronFile:
    def __init__(self, value: str | Exception):
        self.value = value

    def read_text(self) -> str:
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


class PortalOperationalRuntimeTests(unittest.TestCase):
    def runtime(self, value: str | Exception, events: list | None = None):
        events = events if events is not None else []

        def next_run_label(next_run, enabled):
            events.append(("next", next_run, enabled))
            return (
                f"label:{next_run}:{enabled}",
                f"sort:{next_run}:{enabled}",
            )

        def schedule_label(job):
            events.append(("schedule", job.get("marker")))
            return f"schedule:{job.get('marker')}"

        def cron_job_summary(**kwargs):
            events.append(("summary", dict(kwargs)))
            return Summary(**kwargs)

        return SimpleNamespace(
            json=json,
            CRON_JOBS_FILE=CronFile(value),
            next_run_label=next_run_label,
            schedule_label=schedule_label,
            CronJobSummary=cron_job_summary,
        )

    def test_cron_loading_bounds_only_file_and_json_failures(self) -> None:
        for value in (OSError("unavailable"), "{not-json"):
            with self.subTest(value=value):
                self.assertEqual(
                    load_cron_summaries(self.runtime(value)),
                    ([], []),
                )

        with self.assertRaises(AttributeError):
            load_cron_summaries(self.runtime("[]"))
        with self.assertRaises(AttributeError):
            load_cron_summaries(self.runtime('{"jobs":[null]}'))

    def test_cron_projection_preserves_fallbacks_order_and_sorting(self) -> None:
        events: list = []
        jobs = [
            {
                "marker": "zulu",
                "id": "z",
                "name": "Zulu",
                "enabled": True,
                "state": "scheduled",
                "next_run_at": "2",
                "last_status": "ok",
            },
            {
                "marker": "paused",
                "job_id": "p",
                "name": "Beta",
                "enabled": 1,
                "state": "PAUSED",
                "next_run_at": "3",
            },
            {
                "marker": "fallback",
                "id": "",
                "job_id": 0,
                "name": "",
                "enabled": "yes",
                "state": "",
                "next_run_at": None,
                "last_status": "",
            },
            {
                "marker": "aardvark",
                "id": 7,
                "name": "aardvark",
                "enabled": False,
                "state": "running",
                "next_run_at": "4",
                "last_status": 0,
            },
        ]

        enabled, disabled = load_cron_summaries(
            self.runtime(json.dumps({"jobs": jobs}), events)
        )

        self.assertEqual([job.jid for job in enabled], ["z", "unknown"])
        self.assertEqual([job.jid for job in disabled], ["7", "p"])
        self.assertEqual(
            enabled[1],
            Summary(
                jid="unknown",
                name="Unnamed cron",
                schedule="schedule:fallback",
                next_run="label:None:True",
                enabled=True,
                state="scheduled",
                last_status="never",
                sort_key="sort:None:True",
            ),
        )
        self.assertEqual(disabled[1].state, "PAUSED")
        self.assertEqual(disabled[1].last_status, "never")
        self.assertEqual(disabled[0].last_status, "never")
        self.assertEqual(
            [event[0] for event in events],
            ["next", "schedule", "summary"] * len(jobs),
        )
        self.assertEqual(
            [event for event in events if event[0] == "next"],
            [
                ("next", "2", True),
                ("next", "3", False),
                ("next", None, True),
                ("next", "4", False),
            ],
        )


if __name__ == "__main__":
    unittest.main()
