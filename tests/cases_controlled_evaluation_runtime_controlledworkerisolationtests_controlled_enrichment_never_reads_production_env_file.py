from __future__ import annotations

from controlled_evaluation_runtime_fixtures import (
    ALERT_STORE,
    ALERT_STORE_DIR,
    BIN_DIR,
    BaseHTTPRequestHandler,
    CONTROLLED_CREDENTIAL_KEYS,
    CONTROLLED_ROUTE_FIELDS,
    DASHBOARD_SERVER,
    EVALUATION_TOKEN,
    INSTALLER_PATH,
    PIPELINE_ADAPTER_PATH,
    PRIMARY_ROUTE,
    Path,
    RELEASE_ID,
    REPLACEMENT_RELEASE_ID,
    REVIEWER_ROUTE,
    ROOT,
    RUNNER_PATH,
    SCHEDULER_PATH,
    SCORING_RULES,
    SimpleNamespace,
    ThreadingHTTPServer,
    available_port,
    closing,
    dt,
    hashlib,
    importlib,
    io,
    json,
    load_python_module,
    mock,
    os,
    process_output,
    raw_request_status,
    request_json,
    request_json_bytes,
    request_status,
    sanitized_environment,
    shutil,
    socket,
    sqlite3,
    startup_failure_diagnostic,
    stop_process,
    subprocess,
    sys,
    tempfile,
    threading,
    time,
    unittest,
    urllib,
    write_controlled_route_fixture,
)

class ControlledWorkerIsolationTestsControlledEnrichmentNeverReadsProductionEnvFileCases:
    def test_controlled_enrichment_never_reads_production_env_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            production_env = home / "n8n-local" / ".env"
            production_env.parent.mkdir(parents=True, mode=0o700)
            production_env.write_text(
                "N8N_POST_COMMIT_TOKEN=" + ("p" * 64) + "\n",
                encoding="utf-8",
            )
            production_env.chmod(0o600)
            prompt_package = {
                "investigation_query_capability": {
                    "enabled": False,
                    "backends": {"enrichment": {"enabled": False}},
                }
            }
            environment = {
                "ONION_SENTINEL_EVALUATION_MODE": "1",
                "N8N_POST_COMMIT_TOKEN": "",
            }
            with (
                mock.patch.dict(os.environ, environment, clear=False),
                mock.patch.object(self.runner.Path, "home", return_value=home),
                mock.patch.object(
                    self.runner.Path,
                    "read_text",
                    side_effect=AssertionError(
                        "controlled evaluation read production .env"
                    ),
                ),
            ):
                config = self.runner.prepare_investigation_enrichment_context(
                    prompt_package,
                    "incident-responder",
                    "http://127.0.0.1:18787",
                )
            self.assertFalse(config["enabled"])
            self.assertEqual(config["token"], "")
            self.assertFalse(
                prompt_package["investigation_query_capability"][
                    "backends"
                ]["enrichment"]["enabled"]
            )


    def test_mode_off_exact_target_still_reconciles_global_jobs(self) -> None:
        args = SimpleNamespace(
            only_group_id="0123456789abcdefabcd",
            db=Path("/synthetic/production.sqlite3"),
            alert_store_url="http://127.0.0.1:8787",
        )
        connection = mock.MagicMock()
        with (
            mock.patch.object(
                self.scheduler.sqlite3,
                "connect",
                return_value=connection,
            ) as connect,
            mock.patch.object(
                self.scheduler,
                "indexed_reconcilable_ai_job_ids",
                return_value={"completed-group"},
            ),
            mock.patch.object(
                self.scheduler,
                "reconcile_completed_ai_jobs",
                return_value=1,
            ) as reconcile,
        ):
            self.assertEqual(
                self.scheduler.reconcile_worker_state(
                    args,
                    True,
                    controlled_evaluation=False,
                ),
                1,
            )
        connect.assert_called_once()
        connection.close.assert_called_once()
        reconcile.assert_called_once_with(
            args.alert_store_url,
            {"completed-group"},
        )


    def test_evaluation_spools_are_explicitly_wired_and_do_not_touch_global_dirs(
        self,
    ) -> None:
        source = PIPELINE_ADAPTER_PATH.read_text(encoding="utf-8")
        for wiring in (
            "queue_dir=runtime_paths.index_queue_dir",
            "quarantine_dir=runtime_paths.index_quarantine_dir",
            "pending_dir=runtime_paths.memory_pending_dir",
            "committed_dir=runtime_paths.memory_committed_dir",
            "receipt_dir=runtime_paths.memory_receipt_dir",
        ):
            self.assertIn(wiring, source)

        scheduler_startup_source = (
            ROOT / "n8n" / "bin" / "scheduler_startup.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "if not indexed_mode or controlled_dir is not None:",
            scheduler_startup_source,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            evaluation_queue = root / "evaluation" / "analysis-index-pending"
            evaluation_memory = root / "evaluation" / "memory-pending"
            global_queue = root / "global" / "analysis-index-pending"
            global_memory = root / "global" / "memory-pending"
            global_queue.mkdir(parents=True)
            global_memory.mkdir(parents=True)
            global_queue_sentinel = global_queue / "production.json"
            global_memory_sentinel = global_memory / "production.json"
            global_queue_sentinel.write_text("production", encoding="utf-8")
            global_memory_sentinel.write_text("production", encoding="utf-8")

            queued = self.runner.queue_analysis_index(
                {
                    "analysis_id": "controlled-spool-test",
                    "response": {"summary": "synthetic"},
                },
                queue_dir=evaluation_queue,
            )
            memory_task = self.runner.stage_memory_writeback_task(
                analysis_id="controlled-spool-test",
                response_digest="a" * 64,
                agent_role="soc-analyst",
                role_memory_file=root / "role.md",
                shared_memory_file=root / "shared.md",
                source_artifact="synthetic",
                primary_candidates=[
                    {
                        "scope": "agent",
                        "category": "investigation_pivot",
                        "finding": (
                            "Validate synthetic evidence using an independent "
                            "network pivot before drawing a conclusion."
                        ),
                        "use_when": "A later synthetic alert is investigated.",
                        "evidence_basis": [
                            "Two independent synthetic sources agreed."
                        ],
                        "confidence": "medium",
                        "tags": ["synthetic"],
                        "ttl_days": 30,
                    }
                ],
                primary_allowed=True,
                primary_reason="synthetic controlled evaluation",
                reviewer_candidates=[],
                reviewer_allowed=False,
                reviewer_reason="not applicable",
                pending_dir=evaluation_memory,
            )

            self.assertTrue(queued.is_file())
            self.assertIsNotNone(memory_task)
            self.assertTrue(memory_task.is_file())
            self.assertEqual(
                global_queue_sentinel.read_text(encoding="utf-8"),
                "production",
            )
            self.assertEqual(
                global_memory_sentinel.read_text(encoding="utf-8"),
                "production",
            )
            self.assertEqual(
                sorted(path.name for path in global_queue.iterdir()),
                ["production.json"],
            )
            self.assertEqual(
                sorted(path.name for path in global_memory.iterdir()),
                ["production.json"],
            )


