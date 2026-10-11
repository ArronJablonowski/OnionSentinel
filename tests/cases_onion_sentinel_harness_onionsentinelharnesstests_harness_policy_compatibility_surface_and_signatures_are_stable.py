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

class OnionSentinelHarnessTestsHarnessPolicyCompatibilitySurfaceAndSignaturesAreStableCases:
    def test_harness_policy_compatibility_surface_and_signatures_are_stable(self) -> None:
        expected_names = {
            "HARNESS_SCHEMA", "POLICY_SCHEMA", "TRACE_SCHEMA",
            "LEDGER_MANIFEST_SCHEMA_V1", "LEDGER_MANIFEST_SCHEMA_V2",
            "LEDGER_MANIFEST_SCHEMA",
            "SQL_SCHEMA_VERSION", "DEFAULT_POLICY_PATH", "DEFAULT_DB_PATH",
            "DEFAULT_HARNESS_LOG_PATH", "MAX_POLICY_BYTES",
            "MAX_EVENT_PAYLOAD_BYTES", "MAX_EVENT_STRING", "MAX_EVENT_ITEMS",
            "MAX_EVIDENCE_REFS", "MAX_HYPOTHESES",
            "MAX_DECISION_EVIDENCE_REFS", "IDENTIFIER_RE", "DIGEST_RE",
            "INVESTIGATION_SKILL_ADVISORY_MODE",
            "INVESTIGATION_SKILL_UNAVAILABLE_MODE",
            "MAX_ATTESTED_INVESTIGATION_SKILLS",
            "INVESTIGATION_SKILL_ATTESTATION_KEYS",
            "EXTERNAL_AGENT_HARNESS_PROVIDERS", "HarnessError",
            "HarnessPolicyError", "HarnessIntegrityError", "AgentRole",
            "TaskKind", "RunStatus", "Stage", "TrustTier",
            "READ_ONLY_CAPABILITIES", "MUTATING_CAPABILITIES",
            "SENSITIVE_ACTIVE_CAPABILITIES", "APPROVAL_GATED_CAPABILITIES",
            "ALL_CAPABILITIES", "QUERY_BACKEND_CAPABILITIES",
            "DEFAULT_ROLE_CAPABILITIES", "DEFAULT_BUDGETS", "MIN_BUDGETS",
            "MAX_BUDGETS", "REQUIRED_POLICY_FIELDS",
            "REQUIRED_MEMORY_FIELDS", "SECRET_KEY_RE",
            "SECRET_VALUE_PATTERNS", "PolicyDecision", "HarnessPolicy",
            "external_agent_harness_provider",
            "should_start_onion_sentinel_harness", "query_backend_capability",
            "query_backend_is_approval_gated", "utc_now", "canonical_json",
            "digest_json", "_valid_identifier", "_model_route",
            "_digest_or_hash", "_nonnegative_int",
            "policy_decision_is_effective", "load_policy",
            "task_kind_for_role",
        }
        self.assertFalse(expected_names.difference(vars(HARNESS)))
        expected_signatures = {
            "external_agent_harness_provider": "(route: 'Any') -> 'str'",
            "should_start_onion_sentinel_harness": "(*, policy_enabled: 'bool', assigned_route: 'Any', reviewer_route: 'Any') -> 'tuple[bool, str]'",
            "query_backend_capability": "(backend: 'object') -> 'str'",
            "query_backend_is_approval_gated": "(backend: 'object') -> 'bool'",
            "policy_decision_is_effective": "(mode: 'str', decision: 'PolicyDecision') -> 'bool'",
            "load_policy": "(path: 'Path' = PosixPath('/Users/aj_lobster/n8n-local/config/investigation_harness_policy.json')) -> 'HarnessPolicy'",
            "task_kind_for_role": "(role: 'str', *, reanalysis_attempt_id: 'str' = '', manual_reanalysis: 'bool' = False) -> 'str'",
        }
        observed = {
            name: str(inspect.signature(getattr(HARNESS, name)))
            for name in expected_signatures
        }
        # The default path is host-derived; normalize only that representation.
        observed["load_policy"] = observed["load_policy"].replace(
            str(HARNESS.DEFAULT_POLICY_PATH),
            "/Users/aj_lobster/n8n-local/config/investigation_harness_policy.json",
        )
        self.assertEqual(observed, expected_signatures)
        self.assertEqual(
            tuple(field.name for field in dataclasses.fields(HARNESS.PolicyDecision)),
            ("allowed", "capability", "reason", "requires_approval"),
        )
        self.assertEqual(
            tuple(field.name for field in dataclasses.fields(HARNESS.HarnessPolicy)),
            (
                "version", "enabled", "mode", "budgets",
                "role_capabilities", "approval_required",
                "memory_require_independent_agreement",
                "shared_memory_requires_human_approval",
            ),
        )


    def test_harness_policy_imports_from_an_isolated_flat_bin(self) -> None:
        policy_paths = [
            ROOT / "n8n" / "bin" / name
            for name in (
                "harness_policy.py",
                "harness_policy_capabilities.py",
                "harness_policy_document.py",
                "harness_policy_primitives.py",
            )
        ]
        with tempfile.TemporaryDirectory() as directory:
            for policy_path in policy_paths:
                target = Path(directory) / policy_path.name
                target.write_bytes(policy_path.read_bytes())
            result = subprocess.run(
                [sys.executable, "-I", "-B", str(Path(directory) / "harness_policy.py")],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)


    def test_future_schema_rejection_does_not_mutate_sqlite_journal(self) -> None:
        self.db_path.parent.mkdir(parents=True)
        with contextlib.closing(sqlite3.connect(self.db_path)) as connection:
            with connection:
                connection.execute(
                    """
                    CREATE TABLE harness_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    "INSERT INTO harness_metadata(key, value) VALUES(?, ?)",
                    ("schema_version", str(HARNESS.SQL_SCHEMA_VERSION + 1)),
                )
                journal_mode = connection.execute(
                    "PRAGMA journal_mode = DELETE"
                ).fetchone()[0]
        self.assertEqual(str(journal_mode).lower(), "delete")
        self.assertFalse(Path(f"{self.db_path}-wal").exists())
        self.assertFalse(Path(f"{self.db_path}-shm").exists())

        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "newer runtime",
        ):
            HARNESS.HarnessStore(self.db_path)

        with contextlib.closing(sqlite3.connect(self.db_path)) as connection:
            observed_mode = connection.execute(
                "PRAGMA journal_mode"
            ).fetchone()[0]
        self.assertEqual(str(observed_mode).lower(), "delete")
        self.assertFalse(Path(f"{self.db_path}-wal").exists())
        self.assertFalse(Path(f"{self.db_path}-shm").exists())


    def test_policy_parsing_is_default_deny_and_all_mutations_require_approval(
        self,
    ) -> None:
        # Even an empty approval list cannot accidentally remove the mandatory
        # mutation approval gate.
        policy = HARNESS.HarnessPolicy.from_dict(
            self.policy_document(approval_required=[])
        )
        read = policy.authorize(
            HARNESS.AgentRole.SOC_ANALYST.value,
            "security-onion.events.query",
        )
        self.assertTrue(read.allowed)
        self.assertFalse(read.requires_approval)

        mutation = policy.authorize(
            HARNESS.AgentRole.SOC_ANALYST.value,
            "cases.write",
        )
        self.assertFalse(mutation.allowed)
        self.assertTrue(mutation.requires_approval)
        self.assertIn("human approval", mutation.reason)
        self.assertFalse(
            HARNESS.policy_decision_is_effective("shadow", mutation)
        )
        self.assertFalse(
            HARNESS.policy_decision_is_effective("enforce", mutation)
        )
        self.assertTrue(
            policy.authorize(
                HARNESS.AgentRole.SOC_ANALYST.value,
                "cases.write",
                approved=True,
            ).allowed
        )

        self.assertFalse(
            policy.authorize(
                HARNESS.AgentRole.SOC_ANALYST.value,
                "response.contain",
                approved=True,
            ).allowed
        )
        self.assertFalse(
            policy.authorize("unregistered-role", "alerts.read").allowed
        )
        self.assertFalse(
            policy.authorize(
                HARNESS.AgentRole.SOC_ANALYST.value,
                "shell.execute",
            ).allowed
        )
        ordinary_shadow_denial = HARNESS.PolicyDecision(
            False,
            "synthetic.read",
            "synthetic qualification denial",
        )
        self.assertTrue(
            HARNESS.policy_decision_is_effective(
                "shadow",
                ordinary_shadow_denial,
            )
        )
        self.assertFalse(
            HARNESS.policy_decision_is_effective(
                "enforce",
                ordinary_shadow_denial,
            )
        )
        self.assertTrue(
            HARNESS.query_backend_is_approval_gated("osquery")
        )
        self.assertFalse(
            HARNESS.query_backend_is_approval_gated("elastic")
        )
        self.assertEqual(
            HARNESS.query_backend_capability("osquery"),
            "endpoint.osquery.query",
        )


    def test_policy_rejects_unknown_fields_capabilities_and_unsafe_shapes(
        self,
    ) -> None:
        document = self.policy_document()
        document["unexpected"] = True
        with self.assertRaisesRegex(
            HARNESS.HarnessPolicyError,
            "unsupported harness policy fields",
        ):
            HARNESS.HarnessPolicy.from_dict(document)

        document = self.policy_document()
        document["role_capabilities"]["soc-analyst"].append("shell.execute")
        with self.assertRaisesRegex(
            HARNESS.HarnessPolicyError,
            "unknown capabilities",
        ):
            HARNESS.HarnessPolicy.from_dict(document)

        document = self.policy_document()
        document["enabled"] = "yes"
        with self.assertRaisesRegex(
            HARNESS.HarnessPolicyError,
            "enabled must be boolean",
        ):
            HARNESS.HarnessPolicy.from_dict(document)

        document = self.policy_document(
            budgets={"max_queries_total": 0},
        )
        with self.assertRaisesRegex(
            HARNESS.HarnessPolicyError,
            "outside its safe range",
        ):
            HARNESS.HarnessPolicy.from_dict(document)


    def test_policy_rejects_incomplete_and_weakly_typed_documents(self) -> None:
        cases = []

        document = self.policy_document()
        del document["version"]
        cases.append(("missing top-level field", document, "missing required"))

        document = self.policy_document()
        del document["budgets"]["max_model_calls"]
        cases.append(("missing budget", document, "missing required harness budgets"))

        document = self.policy_document()
        del document["memory"]
        cases.append(("missing memory object", document, "missing required"))

        document = self.policy_document()
        del document["memory"]["require_independent_agreement"]
        cases.append(("missing memory flag", document, "missing required memory"))

        for label, raw_value in (
            ("numeric string", "6"),
            ("floating point", 6.0),
        ):
            document = self.policy_document()
            document["budgets"]["max_model_calls"] = raw_value
            cases.append((label, document, "must be an integer"))

        document = self.policy_document()
        capability = document["role_capabilities"]["soc-analyst"][0]
        document["role_capabilities"]["soc-analyst"].append(capability)
        cases.append(("duplicate capability", document, "unique array"))

        document = self.policy_document()
        document["role_capabilities"]["soc-analyst"].append(7)
        cases.append(("non-string capability", document, "entries must be strings"))

        document = self.policy_document(
            approval_required=["cases.write", "cases.write"]
        )
        cases.append(("duplicate approval", document, "unique array"))

        document = self.policy_document(approval_required=["cases.write", 7])
        cases.append(("non-string approval", document, "array of strings"))

        for label, document, message in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    HARNESS.HarnessPolicyError,
                    message,
                ):
                    HARNESS.HarnessPolicy.from_dict(document)


    def test_policy_schema_limits_align_with_runtime_constants(self) -> None:
        schema_path = (
            ROOT
            / "n8n"
            / "config"
            / "investigation_harness_policy.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(set(schema["required"]), set(HARNESS.REQUIRED_POLICY_FIELDS))

        budget_schema = schema["properties"]["budgets"]
        self.assertEqual(
            set(budget_schema["required"]),
            set(HARNESS.DEFAULT_BUDGETS),
        )
        for name in HARNESS.DEFAULT_BUDGETS:
            with self.subTest(budget=name):
                definition = budget_schema["properties"][name]
                self.assertEqual(definition["type"], "integer")
                self.assertEqual(definition["minimum"], HARNESS.MIN_BUDGETS[name])
                self.assertEqual(definition["maximum"], HARNESS.MAX_BUDGETS[name])

        memory_schema = schema["properties"]["memory"]
        self.assertEqual(
            set(memory_schema["required"]),
            set(HARNESS.REQUIRED_MEMORY_FIELDS),
        )
        self.assertEqual(
            set(schema["properties"]["role_capabilities"]["required"]),
            {role.value for role in HARNESS.AgentRole},
        )
        capabilities_schema = schema["$defs"]["capabilities"]
        self.assertTrue(capabilities_schema["uniqueItems"])
        self.assertEqual(
            set(capabilities_schema["items"]["enum"]),
            set(HARNESS.ALL_CAPABILITIES),
        )


    def test_checked_in_policy_uses_runtime_budget_defaults(self) -> None:
        policy_path = (
            ROOT
            / "n8n"
            / "config"
            / "investigation_harness_policy.json"
        )
        document = json.loads(policy_path.read_text(encoding="utf-8"))
        self.assertEqual(document["budgets"], HARNESS.DEFAULT_BUDGETS)
        self.assertEqual(
            document["budgets"]["max_prompt_evidence_rows"],
            1_200,
        )


    def test_policy_loader_rejects_group_or_world_writable_file(self) -> None:
        self.write_policy()
        self.policy_path.chmod(0o666)
        with self.assertRaisesRegex(
            HARNESS.HarnessPolicyError,
            "must not be group- or world-writable",
        ):
            HARNESS.load_policy(self.policy_path)


    def test_missing_or_disabled_policy_does_not_create_runtime_state(self) -> None:
        missing_policy = self.root / "missing-policy.json"
        policy = HARNESS.load_policy(missing_policy)
        self.assertFalse(policy.enabled)
        self.assertEqual(policy.mode, "shadow")

        result = HARNESS.start_harness_run(
            run_id="disabled-run",
            prompt_package=self.prompt_package(),
            role=HARNESS.AgentRole.SOC_ANALYST.value,
            assigned_route="codex-cli:gpt-5.6-sol:high",
            configuration={"mode": "read-only"},
            policy_path=missing_policy,
            db_path=self.db_path,
        )
        self.assertIsNone(result)
        self.assertFalse(self.db_path.exists())

        self.write_policy(enabled=False)
        result = HARNESS.start_harness_run(
            run_id="explicitly-disabled-run",
            prompt_package=self.prompt_package(),
            role=HARNESS.AgentRole.SOC_ANALYST.value,
            assigned_route="codex-cli:gpt-5.6-sol:high",
            configuration={"mode": "read-only"},
            policy_path=self.policy_path,
            db_path=self.db_path,
        )
        self.assertIsNone(result)
        self.assertFalse(self.db_path.exists())


    def test_enabled_native_harness_requires_exact_source_revision(self) -> None:
        policy = HARNESS.HarnessPolicy.from_dict(self.policy_document())
        with self.assertRaisesRegex(ValueError, "source revision"):
            HARNESS.start_harness_run(
                run_id="missing-source-revision",
                prompt_package=self.prompt_package(),
                role=HARNESS.AgentRole.SOC_ANALYST.value,
                assigned_route="codex-cli:gpt-5.6-sol:high",
                configuration={"mode": "read-only"},
                policy=policy,
                db_path=self.db_path,
            )
        self.assertFalse(self.db_path.exists())


    def test_prompt_execution_lineage_drives_soc_manual_and_automatic_tasks(
        self,
    ) -> None:
        stable_group_id = "abcdef1234567890abcd"
        manual_package = self.prompt_package()
        manual_package.update(
            {
                "group_id": stable_group_id,
                "manual_reanalysis": True,
            }
        )
        automatic_package = self.prompt_package()
        automatic_package.update(
            {
                "group_id": stable_group_id,
                "manual_reanalysis": False,
            }
        )

        manual = self.envelope(
            "manual-lineage-run",
            prompt_package=manual_package,
        )
        automatic = self.envelope(
            "automatic-lineage-run",
            prompt_package=automatic_package,
        )

        self.assertEqual(manual.correlation_id, stable_group_id)
        self.assertEqual(manual.task_kind, "reanalysis")
        self.assertEqual(automatic.correlation_id, stable_group_id)
        self.assertEqual(automatic.task_kind, "alert-triage")


    def test_skill_selection_attestation_is_sanitized_and_digest_bound(
        self,
    ) -> None:
        prompt = self.prompt_package()
        prompt["investigation_skills"] = self.investigation_skill_selection()
        envelope = self.envelope(
            "skill-attestation-run",
            prompt_package=prompt,
        )
        expected = {
            "registry_version": 1,
            "registry_sha256": "a" * 64,
            "selected": [
                {
                    "id": "dns-activity-investigation",
                    "version": 2,
                    "skill_sha256": "b" * 64,
                },
                {
                    "id": "suricata-detection-validation",
                    "version": 3,
                    "skill_sha256": "c" * 64,
                },
            ],
            "selected_count": 2,
            "truncated": False,
            "advisory_mode": "advisory_only",
        }
        self.assertEqual(envelope.skill_selection_attestation, expected)
        self.assertEqual(
            set(envelope.skill_selection_attestation),
            HARNESS.INVESTIGATION_SKILL_ATTESTATION_KEYS,
        )

        changed_prompt = json.loads(json.dumps(prompt))
        changed_prompt["investigation_skills"]["selected"][0][
            "skill_sha256"
        ] = "d" * 64
        changed = self.envelope(
            "skill-attestation-run",
            prompt_package=changed_prompt,
        )
        self.assertNotEqual(envelope.job_digest, changed.job_digest)

        run = HARNESS.HarnessRun(
            HARNESS.HarnessStore(self.db_path),
            envelope,
            HARNESS.HarnessPolicy.from_dict(self.policy_document()),
        )
        started = next(
            event
            for event in run.store.export_trace(run.run_id)["events"]
            if event["event_type"] == "run.started"
        )
        started_payload = json.loads(started["payload_json"])
        self.assertEqual(
            started_payload["skill_selection_attestation"],
            expected,
        )
        self.assertEqual(started_payload["job_digest"], envelope.job_digest)
        serialized = json.dumps(started_payload, sort_keys=True)
        self.assertNotIn("Do not copy this skill body", serialized)
        self.assertNotIn("192.0.2.10", serialized)
        self.assertNotIn("never-export-this-selection-secret", serialized)


    def test_execution_contract_is_first_class_durable_and_fail_closed(
        self,
    ) -> None:
        prompt = self.prompt_package()
        prompt["investigation_skills"] = self.investigation_skill_selection()
        envelope = self.envelope("execution-contract-run", prompt_package=prompt)
        policy = HARNESS.HarnessPolicy.from_dict(self.policy_document())
        store = HARNESS.HarnessStore(self.db_path)

        row = store.start_run(envelope, policy)
        contract = json.loads(row["execution_contract_json"])
        self.assertEqual(contract["source_revision"], "1" * 40)
        self.assertEqual(contract["harness_version"], HARNESS.HARNESS_SCHEMA)
        self.assertEqual(contract["policy_version"], policy.version)
        self.assertEqual(
            contract["primary"],
            {
                "route": "codex-cli:gpt-5.6-sol:high",
                "provider": "codex-cli",
                "model": "gpt-5.6-sol",
                "reasoning_level": "high",
            },
        )
        self.assertEqual(
            contract["reviewer"],
            {
                "route": "codex-cli:gpt-5.6-terra:high",
                "provider": "codex-cli",
                "model": "gpt-5.6-terra",
                "reasoning_level": "high",
            },
        )
        self.assertEqual(
            contract["skill_versions"],
            [
                {"id": "dns-activity-investigation", "version": 2, "sha256": "b" * 64},
                {"id": "suricata-detection-validation", "version": 3, "sha256": "c" * 64},
            ],
        )
        self.assertEqual(
            row["execution_contract_digest"],
            envelope.execution_contract_digest,
        )
        started = next(
            event
            for event in store.export_trace(envelope.run_id)["events"]
            if event["event_type"] == "run.started"
        )
        started_payload = json.loads(started["payload_json"])
        self.assertEqual(started_payload["execution_contract"], contract)
        self.assertEqual(
            started_payload["execution_contract_digest"],
            envelope.execution_contract_digest,
        )

        tampered = dataclasses.replace(
            envelope,
            execution_contract_digest="0" * 64,
        )
        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "execution contract does not match",
        ):
            store.start_run(tampered, policy)

        different_policy_document = self.policy_document()
        different_policy_document["version"] = "different-policy"
        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "execution contract does not match",
        ):
            HARNESS.HarnessStore(
                self.root / "different-policy.sqlite3"
            ).start_run(
                envelope,
                HARNESS.HarnessPolicy.from_dict(different_policy_document),
            )


    def test_v2_skill_decision_is_durable_and_provider_bound(self) -> None:
        prompt = self.prompt_package()
        prompt["investigation_skills"] = {
            "schema": "onion-sentinel-investigation-skill-selection-v2",
            "mode": "active",
            "registry_version": 8,
            "registry_digest": "a" * 64,
            "provider": "codex-cli",
            "provider_compatible": True,
            "selected": [{
                "id": "dns-triage",
                "version": "2.3.1",
                "artifact_digest": "b" * 64,
                "selection_reason": "exact_match_capability_and_promotion_gates_satisfied",
            }],
            "selected_count": 1,
            "truncated": False,
            "rejected": [
                {"id": "legacy-dns", "reason": "artifact_revoked"},
            ],
            "aggregate_budget": {
                "max_queries": 4,
                "max_rows": 400,
                "max_bytes": 4000,
                "timeout_seconds": 40,
            },
            "enforcement": "identity_only_no_execution",
        }
        envelope = self.envelope("v2-skill-contract-run", prompt_package=prompt)
        contract = json.loads(envelope.execution_contract_json)

        self.assertEqual(
            contract["schema"],
            "onion-sentinel-harness-execution-contract-v2",
        )
        self.assertEqual(contract["skill_selection"]["provider"], "codex-cli")
        self.assertEqual(
            contract["skill_selection"]["rejected"],
            [{"id": "legacy-dns", "reason": "artifact_revoked"}],
        )
        self.assertEqual(
            contract["skill_versions"][0]["selection_reason"],
            "exact_match_capability_and_promotion_gates_satisfied",
        )
        row = HARNESS.HarnessStore(self.db_path).start_run(
            envelope,
            HARNESS.HarnessPolicy.from_dict(self.policy_document()),
        )
        self.assertEqual(json.loads(row["execution_contract_json"]), contract)

        incompatible = json.loads(json.dumps(prompt))
        incompatible["investigation_skills"].update({
            "provider": "ollama",
            "provider_compatible": True,
        })
        with self.assertRaisesRegex(
            ValueError,
            "compatible native provider",
        ):
            self.envelope(
                "v2-provider-mismatch-run",
                prompt_package=incompatible,
            )


    def test_skill_selection_attestation_rejects_inconsistent_count(
        self,
    ) -> None:
        prompt = self.prompt_package()
        prompt["investigation_skills"] = self.investigation_skill_selection()
        prompt["investigation_skills"]["selected_count"] = 1
        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "selected count does not match",
        ):
            self.envelope(
                "invalid-skill-attestation-run",
                prompt_package=prompt,
            )


    def test_version_zero_skill_registry_is_attested_as_unavailable(
        self,
    ) -> None:
        missing = self.envelope(
            "missing-skill-registry-run",
            prompt_package=self.prompt_package(),
        )
        self.assertEqual(
            missing.skill_selection_attestation,
            {
                "registry_version": 0,
                "registry_sha256": "",
                "selected": [],
                "selected_count": 0,
                "truncated": False,
                "advisory_mode": "unavailable",
            },
        )

        prompt = self.prompt_package()
        selection = self.investigation_skill_selection()
        selection.update(
            {
                "registry_version": 0,
                "selected": [],
                "selected_count": 0,
                "truncated": False,
            }
        )
        prompt["investigation_skills"] = selection

        envelope = self.envelope(
            "unavailable-skill-registry-run",
            prompt_package=prompt,
        )

        self.assertEqual(
            envelope.skill_selection_attestation,
            {
                "registry_version": 0,
                "registry_sha256": "a" * 64,
                "selected": [],
                "selected_count": 0,
                "truncated": False,
                "advisory_mode": "unavailable",
            },
        )


    def test_external_agent_routes_never_start_or_create_harness_state(
        self,
    ) -> None:
        policy = self.write_policy(enabled=True)
        cases = (
            (
                "Hermes primary",
                "hermes-agent:gpt-5.6-sol:medium",
                "ollama:gemma4:31b",
            ),
            (
                "OpenClaw primary",
                "openclaw:ollama/gemma4:26b-mlx:high",
                "",
            ),
            (
                "Hermes reviewer",
                "codex-cli:gpt-5.6-sol:high",
                "hermes-agent:gpt-5.6-sol:medium",
            ),
            (
                "OpenClaw malformed reviewer",
                "ollama:devstral-small-2:24b",
                "openclaw:malformed",
            ),
        )
        for index, (label, assigned, reviewer) in enumerate(cases):
            with self.subTest(label=label):
                db_path = self.root / f"external-{index}" / "harness.sqlite3"
                result = HARNESS.start_harness_run(
                    run_id=f"external-route-{index}",
                    prompt_package=self.prompt_package(),
                    role=HARNESS.AgentRole.SOC_ANALYST.value,
                    assigned_route=assigned,
                    configuration={
                        "mode": "read-only",
                        "reviewer_route": reviewer,
                    },
                    policy=policy,
                    db_path=db_path,
                )
                self.assertIsNone(result)
                self.assertFalse(db_path.exists())
                self.assertFalse(db_path.parent.exists())
