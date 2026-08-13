from __future__ import annotations

import copy
import importlib.machinery
import importlib.util
import inspect
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
EVALUATOR_PATH = BIN / "evaluate-investigation-skills-v2.py"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))


def load_module():
    name = "investigation_skills_v2_evaluator_projection_target"
    loader = importlib.machinery.SourceFileLoader(name, str(EVALUATOR_PATH))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


EVALUATOR = load_module()


class InvestigationSkillsV2EvaluatorProjectionTests(unittest.TestCase):
    def fixture_path(self, root: Path, value) -> Path:
        path = root / "fixtures.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def valid_fixture(self, **overrides):
        value = {
            "schema": "onion-sentinel-skill-offline-replay-v1",
            "field_catalog": {"synthetic": ["field.present"]},
            "cases": [],
        }
        value.update(overrides)
        return value

    def manifest(self, identifier, templates=None, marker=None):
        return {
            "id": identifier,
            "query_templates": templates or [],
            "marker": marker or identifier,
        }

    def test_public_signature_is_stable(self) -> None:
        self.assertEqual(
            str(inspect.signature(EVALUATOR.evaluate)),
            "(candidate_dir: 'Path', fixture_path: 'Path', wrapper_path: 'Path' = "
            f"{EVALUATOR.DEFAULT_SECURITY_ONION_WRAPPER!r}) -> 'dict[str, Any]'",
        )

    def test_fixture_schema_and_catalog_fail_before_candidate_or_wrapper_access(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate_dir = root / "candidates"
            candidate_dir.mkdir()
            cases = [
                ({}, "unsupported offline replay fixture schema"),
                (
                    self.valid_fixture(field_catalog=[]),
                    "field_catalog must be an object",
                ),
            ]
            for fixture, message in cases:
                with (
                    self.subTest(message=message),
                    mock.patch.object(EVALUATOR.skills, "load_manifest") as load,
                    mock.patch.object(EVALUATOR, "load_wrapper_field_catalog") as wrapper,
                    self.assertRaisesRegex(ValueError, message),
                ):
                    EVALUATOR.evaluate(
                        candidate_dir,
                        self.fixture_path(root, fixture),
                        root / "wrapper.py",
                    )
                load.assert_not_called()
                wrapper.assert_not_called()

    def test_candidates_preserve_sorted_load_duplicate_overwrite_and_record_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate_dir = root / "candidates"
            candidate_dir.mkdir()
            for name in ("z.candidate.json", "a.candidate.json", "m.candidate.json"):
                (candidate_dir / name).write_text("{}", encoding="utf-8")
            fixture_path = self.fixture_path(root, self.valid_fixture())
            calls = []
            manifests = {
                "a.candidate.json": self.manifest("duplicate", marker="first"),
                "m.candidate.json": self.manifest("other", marker="middle"),
                "z.candidate.json": self.manifest("duplicate", marker="last"),
            }

            def load(path):
                calls.append(("load", path.name))
                return manifests[path.name]

            def shadow(value):
                calls.append(("shadow", value["marker"]))
                return {"shadow_of": value["marker"]}

            with (
                mock.patch.object(EVALUATOR.skills, "load_manifest", side_effect=load),
                mock.patch.object(EVALUATOR, "simulated_shadow", side_effect=shadow),
                mock.patch.object(
                    EVALUATOR,
                    "load_wrapper_field_catalog",
                    side_effect=lambda path: calls.append(("wrapper", path.name)) or {},
                ),
            ):
                result = EVALUATOR.evaluate(
                    candidate_dir,
                    fixture_path,
                    root / "wrapper.py",
                )

            self.assertEqual(
                calls,
                [
                    ("load", "a.candidate.json"),
                    ("load", "m.candidate.json"),
                    ("load", "z.candidate.json"),
                    ("shadow", "last"),
                    ("shadow", "middle"),
                    ("wrapper", "wrapper.py"),
                ],
            )
            self.assertEqual(result["candidate_count"], 2)
            self.assertEqual(result["case_count"], 0)
            self.assertEqual(result["passed_count"], 0)
            self.assertEqual(result["failed_count"], 0)
            self.assertFalse(result["passed"])
            self.assertEqual(result["results"], [])

    def test_case_replay_preserves_resolver_calls_mapping_authority_and_projection(self) -> None:
        governed = self.manifest(
            "governed",
            [{
                "id": "dns-alert-context",
                "backend": "elastic",
                "expected_fields": ["wrapper.present", "wrapper.missing"],
            }],
        )
        synthetic = self.manifest(
            "synthetic",
            [{
                "id": "custom-template",
                "backend": "synthetic",
                "expected_fields": ["field.present", "field.missing"],
            }],
        )
        fixture = self.valid_fixture(cases=[
            {
                "id": "mixed",
                "expected_selected": ["governed", "synthetic"],
                "context": {"task": "alert-triage"},
                "role": "soc-analyst",
                "permitted_capabilities": ["events.read"],
            },
            {
                "id": "pass",
                "expected_selected": [],
                "context": {"task": "none"},
                "role": "",
                "permitted_capabilities": [],
            },
        ])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate_dir = root / "candidates"
            candidate_dir.mkdir()
            (candidate_dir / "a.candidate.json").write_text("{}", encoding="utf-8")
            (candidate_dir / "b.candidate.json").write_text("{}", encoding="utf-8")
            fixture_path = self.fixture_path(root, fixture)
            calls = []
            loads = iter((governed, synthetic))

            def resolve(records, context, role, capabilities, *, allow_shadow):
                calls.append((
                    "resolve",
                    records,
                    context,
                    role,
                    capabilities,
                    allow_shadow,
                ))
                if context["task"] == "none":
                    return {"selected": []}
                return {"selected": [{"id": "synthetic"}, {"id": "governed"}]}

            with (
                mock.patch.object(EVALUATOR.skills, "load_manifest", side_effect=lambda path: next(loads)),
                mock.patch.object(EVALUATOR, "simulated_shadow", side_effect=lambda value: {"shadow": value["id"]}),
                mock.patch.object(
                    EVALUATOR,
                    "load_wrapper_field_catalog",
                    side_effect=lambda path: calls.append(("wrapper", path))
                    or {"dns_activity": {"wrapper.present"}},
                ),
                mock.patch.object(EVALUATOR.skills, "resolve_manifests", side_effect=resolve),
            ):
                result = EVALUATOR.evaluate(
                    candidate_dir,
                    fixture_path,
                    root / "wrapper.py",
                )

        self.assertEqual(calls[0], ("wrapper", root / "wrapper.py"))
        resolver_calls = calls[1:]
        self.assertEqual(len(resolver_calls), 2)
        self.assertEqual(
            resolver_calls[0],
            (
                "resolve",
                [
                    {"state": "shadow", "manifest": {"shadow": "governed"}},
                    {"state": "shadow", "manifest": {"shadow": "synthetic"}},
                ],
                {"task": "alert-triage"},
                "soc-analyst",
                ["events.read"],
                True,
            ),
        )
        self.assertEqual(result["passed_count"], 1)
        self.assertEqual(result["failed_count"], 1)
        self.assertFalse(result["passed"])
        self.assertEqual(
            result["results"],
            [
                {
                    "id": "mixed",
                    "passed": False,
                    "expected_selected": ["governed", "synthetic"],
                    "actual_selected": ["governed", "synthetic"],
                    "mapping_gaps": [
                        {
                            "skill_id": "governed",
                            "template_id": "dns-alert-context",
                            "backend": "elastic",
                            "catalog": "security-onion-wrapper:dns_activity",
                            "missing_fields": ["wrapper.missing"],
                        },
                        {
                            "skill_id": "synthetic",
                            "template_id": "custom-template",
                            "backend": "synthetic",
                            "catalog": "synthetic-fixture:synthetic",
                            "missing_fields": ["field.missing"],
                        },
                    ],
                },
                {
                    "id": "pass",
                    "passed": True,
                    "expected_selected": [],
                    "actual_selected": [],
                    "mapping_gaps": [],
                },
            ],
        )
        self.assertEqual(
            {key: result[key] for key in (
                "schema",
                "simulation_only",
                "query_execution",
                "candidate_activation",
                "field_catalog",
            )},
            {
                "schema": "onion-sentinel-skill-offline-replay-result-v1",
                "simulation_only": True,
                "query_execution": False,
                "candidate_activation": False,
                "field_catalog": {
                    "security_onion": "governed-wrapper-pack-projections",
                    "pcap_derived": "synthetic-contract-only",
                },
            },
        )

    def test_invalid_case_stops_before_resolver_and_preserves_prior_call_count(self) -> None:
        fixture = self.valid_fixture(cases=[
            {
                "id": "first",
                "context": {},
                "role": "",
                "permitted_capabilities": [],
                "expected_selected": [],
            },
            "invalid",
        ])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate_dir = root / "candidates"
            candidate_dir.mkdir()
            fixture_path = self.fixture_path(root, fixture)
            resolve = mock.Mock(return_value={"selected": []})
            with (
                mock.patch.object(EVALUATOR, "load_wrapper_field_catalog", return_value={}),
                mock.patch.object(EVALUATOR.skills, "resolve_manifests", resolve),
                self.assertRaisesRegex(ValueError, "replay case must be an object"),
            ):
                EVALUATOR.evaluate(candidate_dir, fixture_path, root / "wrapper.py")
            self.assertEqual(resolve.call_count, 1)

    def test_evaluate_does_not_mutate_loaded_manifests_or_fixture_catalog(self) -> None:
        manifest = self.manifest("candidate")
        fixture = self.valid_fixture()
        manifest_before = copy.deepcopy(manifest)
        fixture_before = copy.deepcopy(fixture)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate_dir = root / "candidates"
            candidate_dir.mkdir()
            (candidate_dir / "a.candidate.json").write_text("{}", encoding="utf-8")
            fixture_path = self.fixture_path(root, fixture)
            with (
                mock.patch.object(EVALUATOR.skills, "load_manifest", return_value=manifest),
                mock.patch.object(
                    EVALUATOR,
                    "simulated_shadow",
                    side_effect=lambda value: copy.deepcopy(value),
                ),
                mock.patch.object(EVALUATOR, "load_wrapper_field_catalog", return_value={}),
            ):
                EVALUATOR.evaluate(candidate_dir, fixture_path, root / "wrapper.py")
        self.assertEqual(manifest, manifest_before)
        self.assertEqual(fixture, fixture_before)


if __name__ == "__main__":
    unittest.main()
