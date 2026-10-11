from __future__ import annotations

from alert_store_pcap_retry_fixtures import (
    ALERT_STORE,
    ALERT_STORE_DIR,
    CONTROLLED_ROUTE_FIELDS,
    DEPLOYED_RELEASE,
    Path,
    REPO_ROOT,
    SCORING_RULES,
    available_port,
    closing,
    io,
    json,
    mock,
    os,
    request_json,
    socket,
    sqlite3,
    subprocess,
    tempfile,
    time,
    unittest,
    urllib,
)

class AlertStorePcapRetryTestExactAlertPcapUsesEventTimeNotLaterIngestRollupCases:
    def test_exact_alert_pcap_uses_event_time_not_later_ingest_rollup(
        self,
    ) -> None:
        alert_id = "synthetic-replayed-exact-pcap"
        event_time = "2026-07-16  08:00:00-06:00"
        replay_time = "2026-07-18  10:30:00-06:00"
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            connection.execute(
                """
                INSERT INTO alerts (
                  alert_id, first_seen, last_seen, timestamp, rule_name,
                  source_ip, source_port, destination_ip, destination_port,
                  transport_protocol, triage_level, filter_status, alert_json
                ) VALUES (?, ?, ?, ?, 'Synthetic replayed alert',
                          '192.0.2.10', 49152, '198.51.100.20', 443,
                          'tcp', 'high', 'accepted', ?)
                """,
                (
                    alert_id,
                    replay_time,
                    replay_time,
                    event_time,
                    json.dumps(
                        {
                            "alert_id": alert_id,
                            "timestamp": event_time,
                            "network": {
                                "community_id": "1:replayed-flow=",
                            },
                        }
                    ),
                ),
            )
            connection.commit()

        created = self.post(
            "/pcap/request",
            {
                "alert_id": alert_id,
                "reason": "Exact representative alert PCAP",
                "requested_by": "unit-test",
                # Caller-supplied rollup values cannot move the exact alert
                # away from its database-bound event timestamp.
                "first_seen": replay_time,
                "last_seen": replay_time,
            },
        )

        request = created["request"]
        self.assertEqual(request["first_seen"], event_time)
        self.assertEqual(request["last_seen"], event_time)
        self.assertEqual(request["source_port"], 49152)
        self.assertEqual(request["destination_port"], 443)
        self.assertEqual(request["community_id"], "1:replayed-flow=")


    def test_retry_preserves_progress_honors_backoff_and_exhausts(self) -> None:
        created = self.post(
            "/pcap/request",
            {
                "alert_id": "synthetic-pcap-retry",
                "group_id": "synthetic-group",
                "first_seen": "2026-07-16  08:00:00-06:00",
                "last_seen": "2026-07-16  08:01:00-06:00",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "destination_port": 443,
                "transport_protocol": "tcp",
                "reason": "synthetic retry validation",
            },
        )
        request_id = created["request"]["request_id"]
        first_claim = self.post("/pcap/claim", {"request_id": request_id, "relay_host": "relay-a"})
        self.assertEqual(first_claim["request"]["transfer_attempt_count"], 1)
        duplicate_claim = self.post("/pcap/claim", {"request_id": request_id, "relay_host": "relay-b"})
        self.assertFalse(duplicate_claim["claimed"])
        self.assertEqual(duplicate_claim["request"]["transfer_attempt_count"], 1)
        self.post(
            "/pcap/progress",
            {"request_id": request_id, "stage": "relay_to_mac", "transferred_bytes": 1024, "total_bytes": 4096},
        )
        retried = self.post(
            "/pcap/retry",
            {
                "request_id": request_id,
                "stage": "relay_to_mac",
                "error": "synthetic rsync connection failure",
                "retry_after_seconds": 120,
            },
        )
        request_row = retried["request"]
        self.assertTrue(retried["retry_scheduled"])
        self.assertEqual(request_row["status"], "pending")
        self.assertEqual(request_row["transfer_stage"], "relay_to_mac")
        self.assertEqual(request_row["transfer_bytes"], 1024)
        self.assertEqual(request_row["transfer_retry_count"], 1)
        self.assertEqual(request_row["transfer_last_failed_stage"], "relay_to_mac")

        _, delayed = request_json(f"{self.base_url}/pcap/requests?status=pending&limit=10")
        self.assertEqual(delayed["requests"], [])
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            connection.execute(
                "UPDATE pcap_requests SET next_attempt_at = '2000-01-01T00:00:00Z' WHERE request_id = ?",
                (request_id,),
            )
            connection.commit()
        _, ready = request_json(f"{self.base_url}/pcap/requests?status=pending&limit=10")
        self.assertEqual([item["request_id"] for item in ready["requests"]], [request_id])

        second_claim = self.post("/pcap/claim", {"request_id": request_id, "relay_host": "relay-a"})
        self.assertEqual(second_claim["request"]["transfer_attempt_count"], 2)
        exhausted = self.post(
            "/pcap/retry",
            {"request_id": request_id, "stage": "verifying", "error": "synthetic checksum mismatch"},
        )
        self.assertTrue(exhausted["exhausted"])
        self.assertFalse(exhausted["retry_scheduled"])
        self.assertEqual(exhausted["request"]["status"], "failed")
        self.assertEqual(exhausted["request"]["outcome"], "checksum_failed")


    def test_pending_requests_are_scheduled_by_severity(self) -> None:
        requests: dict[str, str] = {}
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            for level in ("low", "critical", "high"):
                group_id = f"synthetic-{level}-group"
                connection.execute(
                    """
                    INSERT INTO alert_group_summary (
                      group_id, group_key, triage_level, updated_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (group_id, f"synthetic-{level}-key", level, "2026-07-16  08:00:00-06:00"),
                )
            connection.commit()

        for level in ("low", "critical", "high"):
            created = self.post(
                "/pcap/request",
                {
                    "alert_id": f"synthetic-{level}-alert",
                    "group_id": f"synthetic-{level}-group",
                    "first_seen": "2026-07-16  08:00:00-06:00",
                    "last_seen": "2026-07-16  08:01:00-06:00",
                    "source_ip": "192.0.2.10",
                    "destination_ip": "198.51.100.20",
                    "destination_port": 443,
                    "transport_protocol": "tcp",
                    "reason": f"synthetic {level} scheduling validation",
                },
            )
            requests[level] = created["request"]["request_id"]

        _, pending = request_json(f"{self.base_url}/pcap/requests?status=pending&limit=10")
        self.assertEqual(
            [item["request_id"] for item in pending["requests"]],
            [requests["critical"], requests["high"], requests["low"]],
        )


    def test_aged_low_priority_request_precedes_fresh_medium_without_preempting_high(self) -> None:
        requests: dict[str, str] = {}
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            for level in ("low", "medium", "high"):
                group_id = f"synthetic-aged-{level}-group"
                connection.execute(
                    """
                    INSERT INTO alert_group_summary (
                      group_id, group_key, triage_level, updated_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (group_id, f"synthetic-aged-{level}-key", level, "2026-07-16  08:00:00-06:00"),
                )
            connection.commit()

        for level in ("low", "medium", "high"):
            created = self.post(
                "/pcap/request",
                {
                    "alert_id": f"synthetic-aged-{level}-alert",
                    "group_id": f"synthetic-aged-{level}-group",
                    "first_seen": "2026-07-16  08:00:00-06:00",
                    "last_seen": "2026-07-16  08:01:00-06:00",
                    "source_ip": "192.0.2.10",
                    "destination_ip": "198.51.100.20",
                    "destination_port": 443,
                    "transport_protocol": "tcp",
                    "reason": f"synthetic aged {level} scheduling validation",
                },
            )
            requests[level] = created["request"]["request_id"]

        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            connection.execute(
                "UPDATE pcap_requests SET created_at = datetime('now', '-1 hour') WHERE request_id = ?",
                (requests["low"],),
            )
            connection.commit()

        _, pending = request_json(f"{self.base_url}/pcap/requests?status=pending&limit=10")
        self.assertEqual(
            [item["request_id"] for item in pending["requests"]],
            [requests["high"], requests["low"], requests["medium"]],
        )


    def test_fulfilled_transfer_wakes_parser_and_completed_parse_requeues_ai(self) -> None:
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            connection.execute(
                """
                INSERT INTO alert_group_summary (
                  group_id, group_key, triage_level, updated_at
                ) VALUES (?, ?, ?, ?)
                """,
                ("synthetic-wake-group", "synthetic-wake-key", "high", "2026-07-16  08:00:00-06:00"),
            )
            connection.commit()
        created = self.post(
            "/pcap/request",
            {
                "alert_id": "synthetic-wake-alert",
                "group_id": "synthetic-wake-group",
                "group_key": "synthetic-wake-key",
                "first_seen": "2026-07-16  08:00:00-06:00",
                "last_seen": "2026-07-16  08:01:00-06:00",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "destination_port": 443,
                "transport_protocol": "tcp",
                "reason": "synthetic worker wake validation",
            },
        )
        request_id = created["request"]["request_id"]
        self.post("/pcap/claim", {"request_id": request_id, "relay_host": "relay-a"})
        self.post(
            "/pcap/complete",
            {
                "request_id": request_id,
                "status": "fulfilled",
                "artifact_path": "/tmp/synthetic-worker-wake.pcap",
                "artifact_sha256": "a" * 64,
                "artifact_size_bytes": 4096,
                "relay_host": "relay-a",
            },
        )
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not self.pcap_wake_path.exists():
            time.sleep(0.02)
        self.assertTrue(self.pcap_wake_path.exists())
        self.assertIn("pcap-transfer-completed", self.pcap_wake_path.read_text(encoding="utf-8"))

        self.post("/pcap/analysis-status", {"request_id": request_id, "status": "processing"})
        self.post("/pcap/analysis-status", {"request_id": request_id, "status": "completed"})
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not self.ai_wake_path.exists():
            time.sleep(0.02)
        self.assertTrue(self.ai_wake_path.exists())
        self.assertIn("pcap-analysis-completed", self.ai_wake_path.read_text(encoding="utf-8"))
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            queued = connection.execute(
                "SELECT status, priority FROM durable_jobs WHERE job_type = 'ai_analysis' AND dedupe_key = ?",
                ("synthetic-wake-group",),
            ).fetchone()
        self.assertEqual(queued, ("pending", 3))

        # A second evidence completion while inference is active must survive
        # the first run's completion callback as exactly one coalesced rerun.
        claimed = self.post(
            "/jobs/status",
            {"job_type": "ai_analysis", "dedupe_key": "synthetic-wake-group", "status": "processing"},
        )
        self.assertEqual(
            claimed["claim"],
            {
                "job_type": "ai_analysis",
                "dedupe_key": "synthetic-wake-group",
                "payload": {
                    "group_id": "synthetic-wake-group",
                    "group_key": "synthetic-wake-key",
                    "representative_alert_id": "synthetic-wake-alert",
                },
            },
        )
        lease_token = claimed["lease_token"]
        self.post("/pcap/analysis-status", {"request_id": request_id, "status": "completed"})
        self.post(
            "/jobs/status",
            {
                "job_type": "ai_analysis",
                "dedupe_key": "synthetic-wake-group",
                "status": "completed",
                "lease_token": lease_token,
            },
        )
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            rerun = connection.execute(
                """
                SELECT status, rerun_requested, processing_started_at
                FROM durable_jobs WHERE job_type = 'ai_analysis' AND dedupe_key = ?
                """,
                ("synthetic-wake-group",),
            ).fetchone()
        self.assertEqual(rerun, ("pending", 0, None))

        claimed = self.post(
            "/jobs/status",
            {"job_type": "ai_analysis", "dedupe_key": "synthetic-wake-group", "status": "processing"},
        )
        self.post(
            "/jobs/status",
            {
                "job_type": "ai_analysis",
                "dedupe_key": "synthetic-wake-group",
                "status": "completed",
                "lease_token": claimed["lease_token"],
            },
        )
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            completed = connection.execute(
                "SELECT status FROM durable_jobs WHERE job_type = 'ai_analysis' AND dedupe_key = ?",
                ("synthetic-wake-group",),
            ).fetchone()
        self.assertEqual(completed, ("completed",))


    def test_automatic_evidence_enqueue_cannot_replace_pending_manual_analysis(
        self,
    ) -> None:
        dashboard_group_id = "1234567890ab"
        stable_group_id = "1234567890abcdefabcd"
        stable_group_key = "manual-authority-live-group"
        alert_id = "manual-authority-live-alert"
        timestamp = "2026-07-16  09:00:00-06:00"
        alert = {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "rule_name": "Synthetic manual authority validation",
            "severity": 3,
            "severity_label": "high",
            "source": {"ip": "192.0.2.30"},
            "destination": {"ip": "198.51.100.30"},
        }
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            connection.execute(
                """
                INSERT INTO alerts (
                  alert_id, first_seen, last_seen, timestamp, rule_name,
                  severity, severity_label, source_ip, destination_ip,
                  triage_level, filter_status, stable_group_key,
                  stable_group_id, alert_json
                ) VALUES (?, ?, ?, ?, ?, 3, 'high', ?, ?, 'high',
                          'accepted', ?, ?, ?)
                """,
                (
                    alert_id,
                    timestamp,
                    timestamp,
                    timestamp,
                    alert["rule_name"],
                    alert["source"]["ip"],
                    alert["destination"]["ip"],
                    stable_group_key,
                    stable_group_id,
                    json.dumps(alert),
                ),
            )
            connection.execute(
                """
                INSERT INTO alert_group_summary (
                  group_id, group_key, representative_alert_id,
                  triage_level, updated_at
                ) VALUES (?, ?, ?, 'high', ?)
                """,
                (
                    dashboard_group_id,
                    stable_group_key,
                    alert_id,
                    timestamp,
                ),
            )
            connection.commit()

        status, requested = request_json(
            f"{self.base_url}/ai/request",
            "POST",
            {
                "group_id": dashboard_group_id,
                "requested_by": "live-authority-test",
                "reason": "Preserve this operator-authoritative request",
                "related_limit": 500,
                "pcap_analysis_limit": 25,
            },
        )
        self.assertEqual(status, 202, requested)
        self.assertTrue(requested["ok"])
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            before = connection.execute(
                """
                SELECT payload_json, priority, max_attempts, requested_at
                FROM durable_jobs
                WHERE job_type = 'ai_analysis' AND dedupe_key = ?
                """,
                (stable_group_id,),
            ).fetchone()
        manual_payload = json.loads(before[0])
        self.assertIs(manual_payload["manual_reanalysis"], True)
        self.assertEqual(before[1:3], (1000, 12))

        created = self.post(
            "/pcap/request",
            {
                "alert_id": alert_id,
                "group_id": dashboard_group_id,
                "group_key": stable_group_key,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "source_ip": alert["source"]["ip"],
                "destination_ip": alert["destination"]["ip"],
                "destination_port": 443,
                "transport_protocol": "tcp",
                "reason": "Synthetic lower-authority evidence refresh",
            },
        )
        request_id = created["request"]["request_id"]
        self.post(
            "/pcap/claim",
            {"request_id": request_id, "relay_host": "relay-a"},
        )
        self.post(
            "/pcap/complete",
            {
                "request_id": request_id,
                "status": "fulfilled",
                "artifact_path": "/tmp/manual-authority-live.pcap",
                "artifact_sha256": "b" * 64,
                "artifact_size_bytes": 2048,
                "relay_host": "relay-a",
            },
        )
        self.post(
            "/pcap/analysis-status",
            {"request_id": request_id, "status": "processing"},
        )
        self.post(
            "/pcap/analysis-status",
            {"request_id": request_id, "status": "completed"},
        )

        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            after = connection.execute(
                """
                SELECT payload_json, priority, max_attempts, requested_at
                FROM durable_jobs
                WHERE job_type = 'ai_analysis' AND dedupe_key = ?
                """,
                (stable_group_id,),
            ).fetchone()
        self.assertEqual(json.loads(after[0]), manual_payload)
        self.assertEqual(after[1:3], (1000, 12))
        self.assertEqual(after[3], before[3])

        claim = self.post(
            "/jobs/status",
            {
                "job_type": "ai_analysis",
                "dedupe_key": stable_group_id,
                "status": "processing",
            },
        )
        self.assertEqual(claim["claim"]["payload"], manual_payload)


    def test_manual_ai_request_pins_and_echoes_frozen_dispatch_identity(
        self,
    ) -> None:
        identity = self.seed_manual_dispatch_group()
        status, legacy = self.manual_dispatch_request(
            "/ai/request",
            {"group_id": identity["dashboard_group_id"]},
        )
        self.assertEqual(status, 202, legacy)
        self.assertEqual(
            legacy["representative_alert_id"],
            identity["current_alert_id"],
        )
        self.assertNotIn("stable_group_id", legacy)
        self.assertNotIn("cohort_id", legacy)
        self.assertNotIn("dispatch_id", legacy)
        self.assertNotIn("release_id", legacy)

        cohort_id = "newest-20-soc.2026_07_26"
        dispatch_id = "a" * 64
        status, pinned = self.manual_dispatch_request(
            "/ai/request",
            {
                "group_id": identity["dashboard_group_id"],
                "representative_alert_id": identity["pinned_alert_id"],
                "stable_group_id": identity["stable_group_id"],
                "stable_group_key": identity["stable_group_key"],
                "cohort_id": cohort_id,
                "dispatch_id": dispatch_id,
                "release_id": DEPLOYED_RELEASE,
                **CONTROLLED_ROUTE_FIELDS,
            },
        )
        self.assertEqual(status, 202, pinned)
        self.assertEqual(
            pinned["representative_alert_id"],
            identity["pinned_alert_id"],
        )
        self.assertEqual(pinned["stable_group_id"], identity["stable_group_id"])
        self.assertEqual(pinned["stable_group_key"], identity["stable_group_key"])
        self.assertEqual(pinned["cohort_id"], cohort_id)
        self.assertEqual(pinned["dispatch_id"], dispatch_id)
        self.assertEqual(pinned["release_id"], DEPLOYED_RELEASE)
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            payload_json = connection.execute(
                """
                SELECT payload_json FROM durable_jobs
                WHERE job_type = 'ai_analysis' AND dedupe_key = ?
                """,
                (identity["stable_group_id"],),
            ).fetchone()[0]
        durable_payload = json.loads(payload_json)
        self.assertEqual(
            durable_payload["alert_id"],
            identity["pinned_alert_id"],
        )
        self.assertEqual(
            durable_payload["representative_alert_id"],
            identity["pinned_alert_id"],
        )
        self.assertEqual(
            durable_payload["stable_group_id"],
            identity["stable_group_id"],
        )
        self.assertEqual(
            durable_payload["stable_group_key"],
            identity["stable_group_key"],
        )
        self.assertEqual(durable_payload["cohort_id"], cohort_id)
        self.assertEqual(durable_payload["dispatch_id"], dispatch_id)
        self.assertEqual(durable_payload["release_id"], DEPLOYED_RELEASE)

        conflicts = (
            {
                "representative_alert_id": identity["foreign_alert_id"],
                "stable_group_id": identity["stable_group_id"],
                "stable_group_key": identity["stable_group_key"],
                "cohort_id": cohort_id,
                "dispatch_id": "b" * 64,
                "release_id": DEPLOYED_RELEASE,
            },
            {
                "representative_alert_id": identity[
                    "key_collision_alert_id"
                ],
                "stable_group_id": identity["stable_group_id"],
                "stable_group_key": identity["stable_group_key"],
                "cohort_id": cohort_id,
                "dispatch_id": "c" * 64,
                "release_id": DEPLOYED_RELEASE,
            },
            {
                "representative_alert_id": identity["pinned_alert_id"],
                "stable_group_id": "fedcba0987654321fedc",
                "stable_group_key": identity["stable_group_key"],
                "cohort_id": cohort_id,
                "dispatch_id": "d" * 64,
                "release_id": DEPLOYED_RELEASE,
            },
            {
                "representative_alert_id": identity["pinned_alert_id"],
                "stable_group_id": identity["stable_group_id"],
                "stable_group_key": identity["stable_group_key"],
                "cohort_id": cohort_id,
                "release_id": DEPLOYED_RELEASE,
            },
            {
                "representative_alert_id": identity["pinned_alert_id"],
                "stable_group_id": identity["stable_group_id"],
                "stable_group_key": identity["stable_group_key"],
                "cohort_id": cohort_id,
                "dispatch_id": "4" * 64,
            },
            {
                "representative_alert_id": identity["pinned_alert_id"],
                "stable_group_id": identity["stable_group_id"],
                "stable_group_key": identity["stable_group_key"],
                "cohort_id": cohort_id,
                "dispatch_id": "5" * 64,
                "release_id": "e" * 40,
            },
            {
                "representative_alert_id": identity["pinned_alert_id"],
                "stable_group_id": identity["stable_group_id"].upper(),
                "stable_group_key": identity["stable_group_key"],
                "cohort_id": cohort_id,
                "dispatch_id": "1" * 64,
                "release_id": DEPLOYED_RELEASE,
            },
            {
                "representative_alert_id": identity["pinned_alert_id"],
                "stable_group_id": identity["stable_group_id"],
                "stable_group_key": identity["stable_group_key"],
                "cohort_id": f" {cohort_id}",
                "dispatch_id": "2" * 64,
                "release_id": DEPLOYED_RELEASE,
            },
            {
                "representative_alert_id": identity["pinned_alert_id"],
                "stable_group_id": identity["stable_group_id"],
                "stable_group_key": identity["stable_group_key"],
                "cohort_id": cohort_id,
                "dispatch_id": "A" * 64,
                "release_id": DEPLOYED_RELEASE,
            },
            {
                "representative_alert_id": identity["pinned_alert_id"],
                "stable_group_id": identity["stable_group_id"],
                "stable_group_key": "v2|wrong-frozen-key",
                "cohort_id": cohort_id,
                "dispatch_id": "3" * 64,
                "release_id": DEPLOYED_RELEASE,
            },
        )
        for conflict in conflicts:
            with self.subTest(conflict=conflict):
                status, rejected = self.manual_dispatch_request(
                    "/ai/request",
                    {
                        "group_id": identity["dashboard_group_id"],
                        **conflict,
                    },
                )
                self.assertEqual(status, 409, rejected)
                self.assertFalse(rejected["ok"])

        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            retained_json = connection.execute(
                """
                SELECT payload_json FROM durable_jobs
                WHERE job_type = 'ai_analysis' AND dedupe_key = ?
                """,
                (identity["stable_group_id"],),
            ).fetchone()[0]
        self.assertEqual(json.loads(retained_json), durable_payload)


    def test_frozen_stable_group_key_uses_utf8_bytes_at_request_boundary(
        self,
    ) -> None:
        identity = self.seed_manual_dispatch_group()
        exact_multibyte_key = "\u00e9" * 1024
        self.assertEqual(len(exact_multibyte_key.encode("utf-8")), 2048)
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            connection.executemany(
                "UPDATE alerts SET stable_group_key = ? WHERE alert_id = ?",
                (
                    (exact_multibyte_key, identity["current_alert_id"]),
                    (exact_multibyte_key, identity["pinned_alert_id"]),
                ),
            )
            connection.commit()

        request = {
            "group_id": identity["dashboard_group_id"],
            "representative_alert_id": identity["pinned_alert_id"],
            "stable_group_id": identity["stable_group_id"],
            "stable_group_key": exact_multibyte_key,
            "cohort_id": "newest-20-soc.utf8-boundary",
            "dispatch_id": "6" * 64,
            "release_id": DEPLOYED_RELEASE,
            **CONTROLLED_ROUTE_FIELDS,
        }
        status, queued = self.manual_dispatch_request("/ai/request", request)
        self.assertEqual(status, 202, queued)
        with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
            before = connection.execute(
                """
                SELECT id, payload_json, status, attempt_count, lease_token
                FROM durable_jobs
                WHERE job_type = 'ai_analysis' AND dedupe_key = ?
                """,
                (identity["stable_group_id"],),
            ).fetchone()

        invalid_keys = (
            "\u00e9" * 1025,
            "v2|bad\x00group",
        )
        for offset, invalid_key in enumerate(invalid_keys, start=7):
            with self.subTest(boundary="manual", key=repr(invalid_key)):
                status, rejected = self.manual_dispatch_request(
                    "/ai/request",
                    {
                        **request,
                        "stable_group_key": invalid_key,
                        "dispatch_id": str(offset) * 64,
                    },
                )
                self.assertEqual(status, 409, rejected)
                self.assertIn(
                    "stable_group_key is invalid",
                    rejected["reason"],
                )

            with closing(sqlite3.connect(self.db_path, timeout=3)) as connection:
                after_rejection = connection.execute(
                    """
                    SELECT id, payload_json, status, attempt_count, lease_token
                    FROM durable_jobs
                    WHERE job_type = 'ai_analysis' AND dedupe_key = ?
                    """,
                    (identity["stable_group_id"],),
                ).fetchone()
            self.assertEqual(after_rejection, before)
