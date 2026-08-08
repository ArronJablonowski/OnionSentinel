"""Behavior contracts for Hermes cron-failure collection and rendering."""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_cron_failures import (  # noqa: E402
    CronFailureSources,
    compose_cron_failure_records,
    render_cron_failure_log,
)


def parse_timestamp(value: object) -> dt.datetime:
    return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))


class CronFailureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.jobs_file = self.root / "jobs.json"
        self.output_dir = self.root / "output"
        self.output_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def sources(self) -> CronFailureSources:
        return CronFailureSources(
            jobs_file=self.jobs_file,
            output_dir=self.output_dir,
            parse_timestamp=parse_timestamp,
            format_timestamp=lambda value: value.isoformat(),
            redact=lambda value: value.replace("TOPSECRET", "[REDACTED]"),
        )

    def write_output(
        self,
        job_id: str,
        status: str,
        run_time: str,
        detail: str = "TOPSECRET traceback",
    ) -> Path:
        directory = self.output_dir / job_id
        directory.mkdir(exist_ok=True)
        path = directory / f"{run_time.replace(':', '-')}.md"
        path.write_text(
            f"# Cron Job: Job <{job_id}>\n\n"
            f"**Job ID:** {job_id}\n"
            f"**Run Time:** {run_time}\n"
            f"**Status:** {status}\n\n{detail}",
            encoding="utf-8",
        )
        stamp = parse_timestamp(run_time).timestamp()
        os.utime(path, (stamp, stamp))
        return path

    def test_collects_output_evidence_redacts_and_deduplicates_jobs_fallback(self) -> None:
        artifact = self.write_output("job-1", "FAILED", "2026-08-07T12:00:00Z")
        self.write_output("job-ok", "success", "2026-08-07T14:00:00Z")
        self.jobs_file.write_text(
            json.dumps(
                {
                    "jobs": [
                        {
                            "id": "job-1",
                            "name": "Fallback name",
                            "last_status": "failed",
                            "last_error": "duplicate error",
                            "last_run_at": "2026-08-07T12:00:03Z",
                        },
                        {
                            "job_id": "job-2",
                            "name": "Fallback job",
                            "last_status": "timeout",
                            "last_run_at": "2026-08-07T13:00:00Z",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )

        records = compose_cron_failure_records(self.sources())

        self.assertEqual([row["job_id"] for row in records], ["job-2", "job-1"])
        self.assertIsNone(records[0]["source"])
        self.assertEqual(records[1]["source"], artifact)
        self.assertIn("[REDACTED]", records[1]["detail"])
        self.assertNotIn("TOPSECRET", records[1]["detail"])
        self.assertEqual(records[1]["name"], "Job <job-1>")

    def test_file_mtime_is_used_when_run_time_is_missing(self) -> None:
        directory = self.output_dir / "mtime-job"
        directory.mkdir()
        path = directory / "run.md"
        path.write_text("**Status:** exception\ntrace")
        expected = dt.datetime(2026, 8, 7, 15, tzinfo=dt.timezone.utc)
        os.utime(path, (expected.timestamp(), expected.timestamp()))
        self.jobs_file.write_text('{"jobs": []}')

        records = compose_cron_failure_records(self.sources())

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["job_id"], "mtime-job")
        self.assertEqual(records[0]["when"].timestamp(), expected.timestamp())

    def test_malformed_stores_are_stable_and_limit_is_enforced(self) -> None:
        self.jobs_file.write_text("not json")
        self.assertEqual(compose_cron_failure_records(self.sources()), [])
        self.jobs_file.write_text(
            json.dumps(
                {
                    "jobs": [
                        {
                            "id": f"job-{index}",
                            "last_error": "failed",
                            "last_run_at": f"2026-08-07T1{index}:00:00Z",
                        }
                        for index in range(3)
                    ]
                }
            )
        )
        records = compose_cron_failure_records(self.sources(), limit=2)
        self.assertEqual([row["job_id"] for row in records], ["job-2", "job-1"])
        self.assertEqual(compose_cron_failure_records(self.sources(), limit=-1), [])

    def test_renderer_escapes_all_values_opens_only_first_and_bounds_detail(self) -> None:
        sources = self.sources()
        records = [
            {
                "job_id": 'id<script>',
                "name": "Name <unsafe>",
                "status": 'failed "hard"',
                "when": parse_timestamp("2026-08-07T12:00:00Z"),
                "detail": "A" * 9100 + "<tail>",
                "source": self.root / "bad<path>.md",
            },
            {
                "job_id": "second",
                "name": "Second",
                "status": "error",
                "when": None,
                "detail": "detail",
                "source": None,
            },
        ]

        rendered = render_cron_failure_log(records, sources)

        self.assertIn("Name &lt;unsafe&gt;", rendered)
        self.assertIn("id&lt;script&gt;", rendered)
        self.assertIn("bad&lt;path&gt;.md", rendered)
        self.assertIn("&lt;tail&gt;", rendered)
        self.assertNotIn("<unsafe>", rendered)
        self.assertEqual(rendered.count('cron-failure-detail" open'), 1)
        self.assertIn("unknown time", rendered)
        self.assertEqual(rendered.count("A"), 8994)

    def test_empty_renderer_names_both_authoritative_paths(self) -> None:
        rendered = render_cron_failure_log([], self.sources())
        self.assertIn(str(self.jobs_file), rendered)
        self.assertIn(str(self.output_dir), rendered)
        self.assertIn("No failed Hermes cron runs", rendered)


if __name__ == "__main__":
    unittest.main()
