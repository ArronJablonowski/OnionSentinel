import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n" / "bin" / "investigation_skills.py"
REGISTRY_PATH = ROOT / "n8n" / "config" / "investigation_skills.json"
SPEC = importlib.util.spec_from_file_location("investigation_skills", MODULE_PATH)
skills = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(skills)


class InvestigationSkillsTests(unittest.TestCase):
    def test_checked_in_registry_is_shadow_only_and_digest_bound(self) -> None:
        first = skills.load_investigation_skills(REGISTRY_PATH)
        second = skills.load_investigation_skills(REGISTRY_PATH)

        self.assertEqual(first["mode"], "shadow")
        self.assertEqual(first["registry_sha256"], second["registry_sha256"])
        self.assertEqual(len(first["registry_sha256"]), 64)
        self.assertGreaterEqual(len(first["skills"]), 5)
        self.assertTrue(all(len(item["skill_sha256"]) == 64 for item in first["skills"]))
        self.assertTrue(first["learning_policy"]["agent_may_propose"])
        self.assertFalse(first["learning_policy"]["agent_may_activate"])
        self.assertTrue(first["learning_policy"]["require_replay_evaluation"])
        self.assertTrue(first["learning_policy"]["require_independent_review"])
        self.assertTrue(first["learning_policy"]["require_human_approval"])

    def test_dns_alert_selects_dns_and_suricata_skills_deterministically(self) -> None:
        registry = skills.load_investigation_skills(REGISTRY_PATH)
        context = {
            "event_dataset": "suricata.alert",
            "transport_protocol": "udp",
            "destination_port": 53,
            "rule_name": "ET INFO DNS lookup",
        }

        first = skills.resolve_investigation_skills(registry, context, "incident-responder")
        second = skills.resolve_investigation_skills(registry, context, "incident-responder")

        self.assertEqual(first, second)
        self.assertEqual(first["mode"], "shadow")
        self.assertEqual(first["enforcement"], "advisory_only")
        self.assertEqual(
            [item["id"] for item in first["selected"]],
            ["dns-activity-investigation", "suricata-rule-intent-validation"],
        )

    def test_role_scope_and_exact_match_prevent_unrelated_selection(self) -> None:
        registry = skills.load_investigation_skills(REGISTRY_PATH)
        context = {
            "event_dataset": "zeek.conn",
            "transport_protocol": "udp",
            "destination_port": 5353,
            "rule_name": "multicast dns",
        }

        selection = skills.resolve_investigation_skills(registry, context, "siem-engineer")

        self.assertEqual(selection["selected"], [])
        self.assertEqual(selection["selected_count"], 0)

    def test_candidate_skill_is_never_selected(self) -> None:
        payload = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        candidate = copy.deepcopy(payload["skills"][0])
        candidate["id"] = "candidate-dns-skill"
        candidate["status"] = "candidate"
        payload["skills"].append(candidate)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "skills.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            registry = skills.load_investigation_skills(path)

        selection = skills.resolve_investigation_skills(
            registry,
            {"transport_protocol": "udp", "destination_port": 53},
            "soc-analyst",
        )

        self.assertNotIn("candidate-dns-skill", [item["id"] for item in selection["selected"]])

    def test_registry_rejects_self_activation_or_bypassed_review(self) -> None:
        for field, unsafe in (
            ("agent_may_activate", True),
            ("require_replay_evaluation", False),
            ("require_independent_review", False),
            ("require_human_approval", False),
        ):
            with self.subTest(field=field):
                payload = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
                payload["learning_policy"][field] = unsafe
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "skills.json"
                    path.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "promotion gates"):
                        skills.load_investigation_skills(path)


if __name__ == "__main__":
    unittest.main()
