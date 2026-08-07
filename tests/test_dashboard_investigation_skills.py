#!/usr/bin/env python3
"""Contracts for dashboard investigation-skill loading and rendering."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
MODULE_PATH = SCRIPTS / "dashboard_investigation_skills.py"
BUILDER_PATH = SCRIPTS / "build_soc_alerts_dashboard.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class DashboardInvestigationSkillsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = load_module("dashboard_investigation_skills", MODULE_PATH)
        cls.builder = load_module("dashboard_investigation_skills_test_builder", BUILDER_PATH)

    def config(self, root: Path, *candidates: Path):
        return self.catalog.InvestigationSkillCatalogConfig(
            registry_path=root / "config" / "investigation_skills.json",
            loader_candidates=tuple(candidates),
            home=root,
        )

    def test_loader_uses_first_available_strict_runtime_validator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            loader = root / "investigation_skills.py"
            loader.write_text(
                "def load_investigation_skills(path):\n"
                "    return {'mode': 'shadow', 'skills': [], 'source': str(path)}\n",
                encoding="utf-8",
            )
            config = self.config(root, root / "missing.py", loader)
            result = self.catalog.load_investigation_skill_registry(config)

        self.assertEqual(result["mode"], "shadow")
        self.assertTrue(result["source"].endswith("config/investigation_skills.json"))

    def test_missing_loader_and_invalid_projection_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = self.catalog.load_investigation_skill_registry(
                self.config(root, root / "missing.py")
            )
            loader = root / "invalid_loader.py"
            loader.write_text(
                "def load_investigation_skills(path):\n    return ['invalid']\n",
                encoding="utf-8",
            )
            invalid = self.catalog.load_investigation_skill_registry(
                self.config(root, loader)
            )

        for result in (missing, invalid):
            self.assertEqual(result["mode"], "unavailable")
            self.assertEqual(result["skills"], [])
            self.assertIn("error", result)

    def test_renderer_escapes_all_operator_controlled_skill_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self.config(root)
            registry = {
                "mode": "shadow<script>",
                "registry_sha256": 'digest"><script>',
                "skills": ["invalid", {
                    "id": 'dns-investigation"><script>',
                    "status": "shadow<img>",
                    "version": "1<script>",
                    "skill_sha256": 'hash"><script>',
                    "objective": "Inspect <script>alert(1)</script>",
                    "match": {"protocols<script>": ["udp<", 53]},
                    "roles": ["soc_analyst<script>"],
                    "required_evidence": ["zeek_dns<script>"],
                    "pivot_plan": [{
                        "step": "timeline<script>",
                        "backend": "elastic<script>",
                        "pack": "dns<script>",
                        "purpose": "establish_timeline<script>",
                        "discriminator": "query <script>",
                        "required": True,
                    }],
                    "alternative_hypotheses": ["benign<script>"],
                    "stop_conditions": ["bounded<script>"],
                    "confidence_limiters": ["gap<script>"],
                    "known_false_positive_patterns": ["update<script>"],
                    "verification": ["cite<script>"],
                }],
                "error": "failure<script>",
            }
            rendered = self.catalog.render_investigation_skill_catalog(registry, config)

        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("DNS Investigation", rendered)
        self.assertIn("1 shadow&lt;script&gt;", rendered)
        self.assertIn("Required", rendered)
        self.assertIn("This catalog is read-only", rendered)

    def test_empty_projection_is_accessible_and_explicitly_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rendered = self.catalog.render_investigation_skill_catalog(
                {"mode": "unavailable", "skills": [], "error": "blocked <safely>"},
                self.config(Path(directory)),
            )
        self.assertIn('aria-labelledby="onion-sentinel-skills-title"', rendered)
        self.assertIn('role="status"', rendered)
        self.assertIn("Unavailable", rendered)
        self.assertIn("blocked &lt;safely&gt;", rendered)
        self.assertNotIn("data-investigation-skill=", rendered)

    def test_builder_wrappers_honor_runtime_path_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            loader = home / "n8n-local" / "bin" / "investigation_skills.py"
            registry = home / "custom" / "skills.json"
            loader.parent.mkdir(parents=True)
            registry.parent.mkdir(parents=True)
            registry.write_text("{}", encoding="utf-8")
            loader.write_text(
                "def load_investigation_skills(path):\n"
                "    return {'mode': 'active', 'skills': [], 'registry_sha256': 'abc'}\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(self.builder, "HOME", home),
                mock.patch.object(self.builder, "INVESTIGATION_SKILLS_FILE", registry),
            ):
                loaded = self.builder.load_dashboard_investigation_skills()
                rendered = self.builder.investigation_skill_catalog(loaded)

        self.assertEqual(loaded["mode"], "active")
        self.assertIn("Registry", rendered)
        self.assertIn("abc", rendered)

    def test_module_is_bounded_and_installed_with_its_runtime_validator(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 240)
        for forbidden in ("subprocess", "sqlite3", "urllib", "write_text("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_investigation_skills.py"), 2)
        self.assertLess(
            installer.index('investigation_skills.py" "$STACK_DIR/bin'),
            installer.index("dashboard_investigation_skills.py"),
        )


if __name__ == "__main__":
    unittest.main()
