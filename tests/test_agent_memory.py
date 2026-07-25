import concurrent.futures
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n" / "bin" / "agent_memory.py"
SPEC = importlib.util.spec_from_file_location("agent_memory_test_module", MODULE_PATH)
MEMORY = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MEMORY)


class AgentMemoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.role = self.root / "soc-analyst-memory.md"
        self.shared = self.root / "shared-agent-memory.md"
        self.role.write_text("# SOC Analyst Memory\n\n## Operator Notes\n\n- Preserve this note.\n", encoding="utf-8")
        self.shared.write_text("# Shared Memory\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @staticmethod
    def candidate(scope: str = "agent", finding: str = "Repeated TLS SNI activity should be compared with certificate and destination history.") -> dict:
        return {
            "scope": scope,
            "category": "investigation_pivot",
            "finding": finding,
            "use_when": "A later TLS alert has the same SNI or destination infrastructure.",
            "evidence_basis": ["Zeek TLS records and the grouped detection timeline agreed."],
            "confidence": "high" if scope == "shared" else "medium",
            "tags": ["tls", "sni", "certificate"],
            "ttl_days": 30,
        }

    def persist(self, candidates: list[dict]) -> dict:
        return MEMORY.persist_memory_candidates(
            agent_role="soc-analyst",
            role_memory_file=self.role,
            shared_memory_file=self.shared,
            candidates=candidates,
            analysis_id="analysis-test-1",
            source_artifact="/tmp/synthetic-analysis.json",
        )

    def test_persists_role_and_shared_records_without_overwriting_operator_notes(self) -> None:
        result = self.persist([self.candidate(), self.candidate(scope="shared")])
        self.assertEqual(result["accepted"], 2)
        self.assertIn("Preserve this note", self.role.read_text(encoding="utf-8"))
        self.assertIn(MEMORY.MANAGED_START, self.role.read_text(encoding="utf-8"))
        self.assertIn(MEMORY.MANAGED_START, self.shared.read_text(encoding="utf-8"))
        _, role_records = MEMORY.read_memory_file(self.role)
        _, shared_records = MEMORY.read_memory_file(self.shared)
        self.assertEqual(len(role_records), 1)
        self.assertEqual(len(shared_records), 1)

    def test_reinforces_duplicate_instead_of_appending_it(self) -> None:
        self.persist([self.candidate()])
        result = self.persist([self.candidate()])
        _, records = MEMORY.read_memory_file(self.role)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["reinforced_count"], 2)
        self.assertEqual(result["role"]["reinforced"], 1)

    def test_relevance_retrieval_prefers_matching_memory(self) -> None:
        self.persist([
            self.candidate(finding="Repeated TLS SNI activity should be compared with certificate and destination history."),
            {
                **self.candidate(finding="DNS lookup bursts should be compared with resolver and query-name history."),
                "tags": ["dns", "resolver"],
            },
        ])
        context = MEMORY.build_agent_memory_context(
            agent_role="soc-analyst",
            role_memory_file=self.role,
            shared_memory_file=self.shared,
            evidence={"protocol": "tls", "server_name": "example.test", "field": "sni"},
            limit_bytes=4000,
        )
        records = context["role_memory"]["records"]
        self.assertTrue(records)
        self.assertIn("TLS SNI", records[0]["finding"])
        self.assertIn("Preserve this note", context["role_memory"]["manual_notes"])

    def test_rejects_low_confidence_shared_and_secret_like_candidates(self) -> None:
        low_shared = self.candidate(scope="shared")
        low_shared["confidence"] = "medium"
        secret = self.candidate()
        secret["finding"] = "Authorization: Bearer this-value-must-never-be-written-to-memory"
        result = self.persist([low_shared, secret])
        self.assertEqual(result["accepted"], 0)
        self.assertEqual(result["rejected"], 2)
        self.assertNotIn(MEMORY.MANAGED_START, self.role.read_text(encoding="utf-8"))

    def test_bpfdoor_code_zero_quarantine_is_dry_run_first_and_model_only(self) -> None:
        poisoned = self.candidate(
            scope="shared",
            finding=(
                "BPFDoor SID 2069174 is a false positive when ICMP code 0 "
                "does not match the required code."
            ),
        )
        self.persist([poisoned])
        _, records = MEMORY.read_memory_file(self.shared)
        self.assertEqual(len(records), 1)

        preview = MEMORY.quarantine_bpfdoor_code_zero_memory(self.shared)
        self.assertTrue(preview["dry_run"])
        self.assertEqual(preview["matched"], 1)
        self.assertEqual(preview["predicate_match_ids"], preview["record_ids"])
        self.assertEqual(preview["explicit_id_match_ids"], [])
        _, unchanged = MEMORY.read_memory_file(self.shared)
        self.assertEqual(unchanged[0]["status"], "model-observed")

        applied = MEMORY.quarantine_bpfdoor_code_zero_memory(
            self.shared,
            apply=True,
        )
        self.assertEqual(applied["applied"], 1)
        _, quarantined = MEMORY.read_memory_file(self.shared)
        self.assertEqual(quarantined[0]["status"], "quarantined")
        context = MEMORY.build_agent_memory_context(
            agent_role="soc-analyst",
            role_memory_file=self.role,
            shared_memory_file=self.shared,
            evidence={"rule": "BPFDoor", "icmp": {"code": 0}},
        )
        self.assertEqual(context["shared_memory"]["records"], [])

        # An operator-confirmed record is never eligible for automated quarantine.
        quarantined[0]["status"] = "operator-confirmed"
        managed = MEMORY._record_markdown(quarantined[0])
        self.shared.write_text(
            f"# Shared Memory\n\n{MEMORY.MANAGED_START}\n\n{managed}\n\n{MEMORY.MANAGED_END}\n",
            encoding="utf-8",
        )
        confirmed = MEMORY.quarantine_bpfdoor_code_zero_memory(
            self.shared,
            apply=True,
            record_ids=[quarantined[0]["id"]],
        )
        self.assertEqual(confirmed["matched"], 0)
        _, confirmed_records = MEMORY.read_memory_file(self.shared)
        self.assertEqual(confirmed_records[0]["status"], "operator-confirmed")

    def test_exact_id_can_quarantine_generic_model_only_bpfdoor_memory(self) -> None:
        generic = self.candidate(
            scope="shared",
            finding=(
                "ICMP heartbeat activity should be treated as suspicious until "
                "endpoint evidence resolves the behavior."
            ),
        )
        generic["evidence_basis"] = [
            "The model associated the prior alert with BPFDoor without analyst adjudication."
        ]
        self.persist([generic])
        _, records = MEMORY.read_memory_file(self.shared)
        record_id = records[0]["id"]

        no_id = MEMORY.quarantine_bpfdoor_code_zero_memory(self.shared)
        self.assertEqual(no_id["matched"], 0)
        explicit = MEMORY.quarantine_bpfdoor_code_zero_memory(
            self.shared,
            record_ids=[record_id],
        )
        self.assertEqual(explicit["predicate_match_ids"], [])
        self.assertEqual(explicit["explicit_id_match_ids"], [record_id])
        applied = MEMORY.quarantine_bpfdoor_code_zero_memory(
            self.shared,
            apply=True,
            record_ids=[record_id],
        )
        self.assertEqual(applied["applied"], 1)

    def test_concurrent_writers_preserve_all_distinct_records(self) -> None:
        def write(index: int) -> dict:
            candidate = self.candidate(finding=f"Reusable TLS investigation pivot number {index} compares SNI and certificate history.")
            return MEMORY.persist_memory_candidates(
                agent_role="soc-analyst",
                role_memory_file=self.role,
                shared_memory_file=self.shared,
                candidates=[candidate],
                analysis_id=f"analysis-{index}",
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(write, range(20)))
        _, records = MEMORY.read_memory_file(self.role)
        self.assertEqual(len(records), 20)

    def test_cli_friendly_context_is_json_serializable(self) -> None:
        self.persist([self.candidate()])
        context = MEMORY.build_agent_memory_context(
            agent_role="soc-analyst",
            role_memory_file=self.role,
            shared_memory_file=self.shared,
            evidence={"rule": "TLS SNI"},
        )
        self.assertIsInstance(json.dumps(context), str)

    def test_initializer_preserves_legacy_operator_notes(self) -> None:
        legacy = self.root / "legacy-memory.md"
        legacy.write_text("# Legacy Memory\n\n- Keep this operator note.\n", encoding="utf-8")
        first = MEMORY.initialize_memory_file(legacy, "Legacy Memory")
        second = MEMORY.initialize_memory_file(legacy, "Legacy Memory")
        text = legacy.read_text(encoding="utf-8")
        self.assertTrue(first["changed"])
        self.assertFalse(second["changed"])
        self.assertIn("Keep this operator note", text)
        self.assertEqual(text.count(MEMORY.MANAGED_START), 1)
        self.assertEqual(text.count(MEMORY.MANAGED_END), 1)

    def test_every_agent_role_has_primary_reviewer_and_memory_contracts(self) -> None:
        expected_roles = {
            "soc-analyst",
            "incident-responder",
            "siem-engineer",
            "cyber-threat-intel",
            "threat-hunter",
        }
        self.assertEqual(set(MEMORY.MEMORY_ROLES), expected_roles)
        self.assertEqual(set(MEMORY.AGENT_MEMORY_FILES), expected_roles)
        self.assertEqual(set(MEMORY.AGENT_PROMPT_FILES), expected_roles)
        self.assertEqual(set(MEMORY.AGENT_SECOND_OPINION_PROMPT_FILES), expected_roles)
        for role in expected_roles:
            memory = ROOT / "n8n" / "agent-memory" / MEMORY.AGENT_MEMORY_FILES[role]
            prompt = ROOT / "n8n" / "config" / MEMORY.AGENT_PROMPT_FILES[role]
            reviewer_prompt = (
                ROOT / "n8n" / "config" / MEMORY.AGENT_SECOND_OPINION_PROMPT_FILES[role]
            )
            self.assertTrue(memory.is_file())
            self.assertTrue(prompt.is_file())
            self.assertTrue(reviewer_prompt.is_file())
            prompt_text = prompt.read_text(encoding="utf-8").lower()
            reviewer_text = reviewer_prompt.read_text(encoding="utf-8").lower()
            self.assertIn("memory_candidates", prompt_text)
            self.assertIn("shared", prompt_text)
            self.assertIn("memory_candidates", reviewer_text)
            self.assertIn("shared", reviewer_text)
            self.assertIn("independent", reviewer_text)
            self.assertIn("withheld", reviewer_text)

    def test_deployment_verifier_accepts_repo_templates(self) -> None:
        command = [
            sys.executable,
            str(ROOT / "n8n" / "bin" / "verify-agent-memory.py"),
            "--config-dir",
            str(ROOT / "n8n" / "config"),
            "--memory-dir",
            str(ROOT / "n8n" / "agent-memory"),
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["agent_count"], len(MEMORY.MEMORY_ROLES))
        self.assertTrue(all(item["read_context_ready"] for item in payload["agents"].values()))
        self.assertTrue(all(item["execution_context_ready"] for item in payload["agents"].values()))
        self.assertTrue(all(item["second_opinion_prompt_file"] for item in payload["agents"].values()))
        self.assertEqual(set(payload["agents"]), set(MEMORY.MEMORY_ROLES))

    def test_installer_seeds_every_reviewer_prompt_without_overwriting_runtime_policy(self) -> None:
        installer = (ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh").read_text(
            encoding="utf-8"
        )
        for prompt_file in MEMORY.AGENT_SECOND_OPINION_PROMPT_FILES.values():
            self.assertIn(prompt_file, installer)
        self.assertIn('if [[ ! -f "$STACK_DIR/config/$reviewer_prompt" ]]', installer)

    def test_execution_context_binds_prompt_and_both_memories(self) -> None:
        for filename in MEMORY.AGENT_MEMORY_FILES.values():
            MEMORY.initialize_memory_file(self.root / filename, filename)
        MEMORY.initialize_memory_file(self.root / "shared-agent-memory.md", "Shared Memory")
        context = MEMORY.build_agent_execution_context(
            agent_role="threat-hunter",
            config_dir=ROOT / "n8n" / "config",
            memory_dir=self.root,
            evidence={"hunt": "tls certificate reuse"},
        )
        self.assertIn("senior threat hunt analyst", context["system_prompt"].lower())
        self.assertEqual(
            context["second_opinion_system_prompt_file"],
            str(ROOT / "n8n" / "config" / "threat_hunter_second_opinion_prompt.md"),
        )
        self.assertEqual(context["agent_memory"]["role_memory"]["agent_role"], "threat-hunter")
        self.assertEqual(context["agent_memory"]["shared_memory"]["agent_role"], "shared")
        self.assertEqual(context["memory_writeback_contract"]["response_field"], "memory_candidates")


if __name__ == "__main__":
    unittest.main()
