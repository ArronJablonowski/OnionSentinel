from __future__ import annotations

from onion_sentinel_harness_fixtures import (
    HARNESS,
    MODULE_PATH,
    Path,
    ROOT,
    SPEC,
    contextlib,
    dataclasses,
    gc,
    importlib,
    inspect,
    json,
    mock,
    os,
    sqlite3,
    stat,
    subprocess,
    sys,
    tempfile,
    threading,
    unittest,
    warnings,
)

class OnionSentinelHarnessTestsFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "state" / "harness.sqlite3"
        self.policy_path = self.root / "config" / "harness-policy.json"


    def tearDown(self) -> None:
        self.tmp.cleanup()


    @staticmethod
    def policy_document(
        *,
        enabled: bool = True,
        mode: str = "shadow",
        budgets: dict | None = None,
        approval_required: list[str] | None = None,
    ) -> dict:
        effective_budgets = dict(HARNESS.DEFAULT_BUDGETS)
        effective_budgets.update(budgets or {})
        return {
            "schema": HARNESS.POLICY_SCHEMA,
            "version": "1.2.3",
            "enabled": enabled,
            "mode": mode,
            "budgets": effective_budgets,
            "role_capabilities": {
                role: sorted(capabilities)
                for role, capabilities in HARNESS.DEFAULT_ROLE_CAPABILITIES.items()
            },
            "approval_required": (
                [] if approval_required is None else approval_required
            ),
            "memory": {
                "require_independent_agreement": True,
                "shared_requires_human_approval": True,
            },
        }


    def write_policy(self, **overrides) -> HARNESS.HarnessPolicy:
        document = self.policy_document(**overrides)
        self.policy_path.parent.mkdir(parents=True)
        self.policy_path.write_text(
            json.dumps(document, sort_keys=True),
            encoding="utf-8",
        )
        return HARNESS.HarnessPolicy.from_dict(document)


    @staticmethod
    def prompt_package() -> dict:
        return {
            "alert": {
                "alert_id": "alert-42",
                "rule_name": "Synthetic read-only investigation alert",
            },
            "group_id": "group-42",
            "authorization": "Bearer never-persist-this-sensitive-value",
            "evidence_reference_contract": {
                "schema": "onion-sentinel-evidence-reference-contract-v1",
                "references": [
                    {
                        "ref": "alert:42",
                        "source": "security-onion-alert",
                        "source_class": "suricata_alert",
                        "status": "available",
                        "returned": 1,
                        "corroborating": True,
                    },
                    {
                        "ref": "zeek:uid-42",
                        "source": "zeek-conn",
                        "source_class": "zeek_conn",
                        "status": "available",
                        "returned": 1,
                        "corroborating": True,
                    },
                ],
            },
        }


    @staticmethod
    def investigation_skill_selection() -> dict:
        return {
            "schema": "onion-sentinel-investigation-skill-selection-v1",
            "mode": "shadow",
            "registry_version": 1,
            "registry_sha256": "a" * 64,
            "selected": [
                {
                    "id": "suricata-detection-validation",
                    "version": 3,
                    "skill_sha256": "c" * 64,
                    "guidance": "Do not copy this skill body into traces.",
                    "telemetry": {"source_ip": "192.0.2.10"},
                },
                {
                    "id": "dns-activity-investigation",
                    "version": 2,
                    "skill_sha256": "b" * 64,
                    "secret": "never-export-this-selection-secret",
                },
            ],
            "selected_count": 2,
            "truncated": False,
            "enforcement": "advisory_only",
        }


    @staticmethod
    def response() -> dict:
        return {
            "_analysis_model": "gpt-5.6-sol",
            "_analysis_model_path": "codex-cli",
            "_analysis_provider": "openai",
            "_analysis_harness": "codex",
            "_analysis_model_route": "codex-cli:gpt-5.6-sol:high",
            "event_status": "observed",
            "detection_outcome": "true_positive_suspicious",
            "final_disposition_status": "reviewed",
            "confidence": "high",
            "confidence_score": 0.94,
            "executive_summary": "Two independent sources corroborated the event.",
            "detection_outcome_reasoning": "The alert and Zeek flow agree.",
            "evidence_used": ["alert:42", "zeek:uid-42"],
            "hypotheses": [
                {
                    "id": "supported-hypothesis",
                    "statement": "The network event occurred.",
                    "status": "supported",
                    "supporting_evidence": ["alert:42", "unknown:ignored"],
                    "contradicting_evidence": [],
                    "next_discriminator": "Collect endpoint process telemetry.",
                },
                {
                    "id": "unsupported-hypothesis",
                    "statement": "An unsupported assertion must remain unresolved.",
                    "status": "supported",
                    "supporting_evidence": ["unknown:missing"],
                    "contradicting_evidence": [],
                },
            ],
            "_evidence_reference_validation": {
                "invalid_refs": [],
                "corroborating_source_classes": [
                    "suricata_alert",
                    "zeek_conn",
                ],
            },
            "_second_opinion": {
                "status": "completed",
                "comparison": {
                    "agreement": "agreement",
                    "material_disagreement": False,
                },
            },
        }


    @staticmethod
    def envelope(
        run_id: str,
        prompt_package: dict | None = None,
        *,
        role: str = "soc-analyst",
    ):
        return HARNESS.JobEnvelope.from_prompt(
            run_id=run_id,
            prompt_package=prompt_package or OnionSentinelHarnessTestsFixtures.prompt_package(),
            role=role,
            assigned_route="codex-cli:gpt-5.6-sol:high",
            configuration={
                "query_mode": "read-only",
                "max_rounds": 3,
                "reviewer_route": "codex-cli:gpt-5.6-terra:high",
            },
            source_revision="1" * 40,
            policy_version="1.2.3",
        )


    def make_run(
        self,
        run_id: str = "run-42",
        *,
        policy: HARNESS.HarnessPolicy | None = None,
        db_path: Path | None = None,
        role: str = "soc-analyst",
    ):
        policy = policy or HARNESS.HarnessPolicy.from_dict(
            self.policy_document()
        )
        store = HARNESS.HarnessStore(db_path or self.db_path)
        return HARNESS.HarnessRun(
            store,
            self.envelope(run_id, role=role),
            policy,
        )


    @staticmethod
    def budget_events(run) -> list[dict]:
        return [
            event
            for event in run.store.export_trace(run.run_id)["events"]
            if event["event_type"] == "policy.budget"
        ]


    @staticmethod
    def age_run(run) -> None:
        with HARNESS._connect(run.store.path) as connection:
            connection.execute(
                """
                UPDATE harness_runs
                SET started_at = '2000-01-01T00:00:00Z'
                WHERE run_id = ?
                """,
                (run.run_id,),
            )


    @staticmethod
    def replace_terminal_manifest(
        run,
        manifest: dict | None,
        *,
        legacy_identity: bool = False,
    ) -> None:
        """Rewrite terminal metadata while preserving a valid event hash chain."""
        with HARNESS._connect(run.store.path) as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM harness_events
                WHERE run_id = ?
                ORDER BY sequence
                """,
                (run.run_id,),
            ).fetchall()
            previous = "0" * 64
            for row in rows:
                payload = json.loads(row["payload_json"])
                if (
                    legacy_identity
                    and row["event_type"] == "run.started"
                ):
                    payload.pop("assigned_reviewer_route", None)
                    payload.pop("execution_contract", None)
                    payload.pop("execution_contract_digest", None)
                if row["event_type"] == "run.succeeded":
                    if manifest is None:
                        payload.pop("ledger_manifest", None)
                    else:
                        payload["ledger_manifest"] = manifest
                payload_json = HARNESS.canonical_json(payload)
                payload_sha256 = HARNESS.hashlib.sha256(
                    payload_json.encode("utf-8")
                ).hexdigest()
                body = {
                    "run_id": run.run_id,
                    "sequence": int(row["sequence"]),
                    "idempotency_key": row["idempotency_key"],
                    "event_type": row["event_type"],
                    "stage": row["stage"],
                    "created_at": row["created_at"],
                    "payload_sha256": payload_sha256,
                    "previous_event_sha256": previous,
                }
                event_sha256 = HARNESS.digest_json(body)
                connection.execute(
                    """
                    UPDATE harness_events
                    SET payload_json = ?, payload_sha256 = ?,
                        previous_event_sha256 = ?,
                        event_sha256 = ?, event_id = ?
                    WHERE run_id = ? AND sequence = ?
                    """,
                    (
                        payload_json,
                        payload_sha256,
                        previous,
                        event_sha256,
                        f"evt-{event_sha256[:32]}",
                        run.run_id,
                        row["sequence"],
                    ),
                )
                previous = event_sha256

