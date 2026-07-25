import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
INSTALLER = BIN / "install-investigation-query-runtime.py"


def load_installer():
    spec = importlib.util.spec_from_file_location(
        "investigation_query_runtime_installer_test",
        INSTALLER,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load investigation query runtime installer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InvestigationQueryRuntimeInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.installer = load_installer()

    def install(self, root: Path, config: dict) -> tuple[Path, dict]:
        runtime = root / "runtime-bin"
        config_path = root / "incident-evidence.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        outcome = self.installer.install_query_runtime(
            repo_root=ROOT,
            runtime_bin=runtime,
            config_path=config_path,
        )
        return runtime, outcome

    def pythonpath(self, runtime: Path) -> str:
        return os.pathsep.join((str(runtime), str(BIN)))

    def test_absent_contract_installs_exact_v1_with_hardened_builder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime, outcome = self.install(Path(temporary), {"host": "example"})

            self.assertEqual(outcome["contract"], self.installer.V1)
            self.assertEqual(outcome["action"], "installed_bundled_v1")
            self.installer.validate_runtime(runtime, self.installer.V1)
            manifest = json.loads(
                (
                    ROOT
                    / "n8n"
                    / "compat"
                    / "investigation-pivots-v1"
                    / "manifest.json"
                ).read_text(encoding="utf-8")
            )
            for name, expected in manifest["files"].items():
                self.assertEqual(
                    hashlib.sha256((runtime / name).read_bytes()).hexdigest(),
                    expected,
                )
            self.assertEqual(
                (runtime / "build-ai-investigation-prompt.py").read_bytes(),
                (BIN / "build-ai-investigation-prompt.py").read_bytes(),
            )

    def test_v1_always_restores_pinned_bundle_and_refreshes_builder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime, _outcome = self.install(root, {
                "investigation_query_contract": self.installer.V1,
            })
            collector = runtime / "collect-investigation-pivots.py"
            collector.write_text(
                collector.read_text(encoding="utf-8")
                + "\n# operator-reviewed-v1-marker\n",
                encoding="utf-8",
            )
            builder = runtime / "build-ai-investigation-prompt.py"
            builder.write_text("# stale builder\n", encoding="utf-8")

            config_path = root / "incident-evidence.json"
            outcome = self.installer.install_query_runtime(
                repo_root=ROOT,
                runtime_bin=runtime,
                config_path=config_path,
            )

            self.assertEqual(outcome["action"], "installed_bundled_v1")
            self.assertNotIn(
                "operator-reviewed-v1-marker",
                collector.read_text(encoding="utf-8"),
            )
            manifest = json.loads(
                (
                    ROOT
                    / "n8n"
                    / "compat"
                    / "investigation-pivots-v1"
                    / "manifest.json"
                ).read_text(encoding="utf-8")
            )
            for name, expected in manifest["files"].items():
                self.assertEqual(
                    hashlib.sha256((runtime / name).read_bytes()).hexdigest(),
                    expected,
                )
            self.assertEqual(
                builder.read_bytes(),
                (BIN / "build-ai-investigation-prompt.py").read_bytes(),
            )

    def test_exact_v2_opt_in_installs_v2(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime, outcome = self.install(Path(temporary), {
                "investigation_query_contract": self.installer.V2,
            })

            self.assertEqual(outcome["action"], "installed_explicit_v2")
            self.installer.validate_runtime(runtime, self.installer.V2)
            self.assertIn(
                self.installer.V2,
                (runtime / "investigation_query_contract.py").read_text(
                    encoding="utf-8"
                ),
            )

    def test_unknown_contract_fails_before_installing_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime-bin"
            config = root / "incident-evidence.json"
            config.write_text(
                json.dumps({"investigation_query_contract": "latest"}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                self.installer.QueryRuntimeInstallError,
                "must be exactly",
            ):
                self.installer.install_query_runtime(
                    repo_root=ROOT,
                    runtime_bin=runtime,
                    config_path=config,
                )
            self.assertFalse(runtime.exists())

    def test_v1_builder_and_runner_project_only_v1_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime, _outcome = self.install(root, {
                "investigation_query_contract": self.installer.V1,
            })
            shutil.copy2(BIN / "run-local-ai-analysis.py", runtime)
            script = textwrap.dedent(
                f"""
                import importlib.util
                import json
                from pathlib import Path

                runtime = Path({str(runtime)!r})
                def load(name, path):
                    spec = importlib.util.spec_from_file_location(name, path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    return module

                builder = load("compat_v1_builder", runtime / "build-ai-investigation-prompt.py")
                runner = load("compat_v1_runner", runtime / "run-local-ai-analysis.py")
                row = {{
                    "alert_id": ".ds-logs-suricata.alerts-so-2026.07.24-000001:alert-1",
                    "alert_json": json.dumps({{
                        "elastic_index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
                        "elastic_id": "alert-1",
                        "event": {{"dataset": "suricata.alert"}},
                        "source": {{"ip": "192.0.2.10"}},
                        "destination": {{"ip": "198.51.100.20"}},
                    }}),
                    "source_ip": "192.0.2.10",
                    "destination_ip": "198.51.100.20",
                    "timestamp": "2026-07-24T18:30:00Z",
                }}
                capability, local = builder.investigation_query_context(
                    row, [row], "group-1", "incident-responder", False
                )
                print(json.dumps({{
                    "builder_contract": builder.INVESTIGATION_QUERY_CONTRACT,
                    "runner_contract": runner.INVESTIGATION_QUERY_CONTRACT,
                    "aggregations": sorted(runner.INVESTIGATION_QUERY_AGGREGATIONS),
                    "capability_aggregations": capability["backends"]["elastic"]["aggregations"],
                    "visible_tuple": capability["permitted_event_tuples"][0],
                    "local_tuple": local["permitted_event_tuples"][0],
                    "local_has_anchor_time": "anchor_time" in local,
                }}))
                """
            )
            proc = subprocess.run(
                [sys.executable, "-c", script],
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "PYTHONPATH": self.pythonpath(runtime),
                },
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            value = json.loads(proc.stdout)

            self.assertEqual(value["builder_contract"], self.installer.V1)
            self.assertEqual(value["runner_contract"], self.installer.V1)
            self.assertNotIn("anchor_nearest", value["aggregations"])
            self.assertNotIn("anchor_nearest", value["capability_aggregations"])
            self.assertFalse(value["local_has_anchor_time"])
            self.assertNotIn("event_tuple", value["visible_tuple"])
            self.assertNotIn("role_semantics", value["local_tuple"])

    def test_manual_reanalysis_uses_hardened_builder_on_v1(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime, _outcome = self.install(root, {
                "investigation_query_contract": self.installer.V1,
            })
            shutil.copy2(BIN / "auto-run-ai-analysis.py", runtime)
            script = textwrap.dedent(
                f"""
                import importlib.util
                import json
                from pathlib import Path
                from types import SimpleNamespace

                runtime = Path({str(runtime)!r})
                spec = importlib.util.spec_from_file_location(
                    "compat_v1_auto_runner",
                    runtime / "auto-run-ai-analysis.py",
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                captured = {{}}
                def fake_run(command, **_kwargs):
                    captured["command"] = command
                    prompt_output = runtime / "manual-v1-prompt.json"
                    prompt_output.write_text(
                        "{{}}",
                        encoding="utf-8",
                    )
                    return SimpleNamespace(
                        returncode=0,
                        stdout=str(prompt_output) + "\\n",
                        stderr="",
                    )
                module.run_command = fake_run
                args = SimpleNamespace(
                    prompt_dir=runtime,
                    related_limit=8,
                    correlation_limit=8,
                    correlation_min_score=15,
                    max_prompt_bytes=1048576,
                    include_tests=False,
                )
                module.build_prompt(
                    "alert-1",
                    args,
                    job_payload={{
                        "manual_reanalysis": True,
                        "agent_role": "incident-responder",
                    }},
                )
                print(json.dumps(captured))
                """
            )
            proc = subprocess.run(
                [sys.executable, "-c", script],
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "PYTHONPATH": self.pythonpath(runtime),
                },
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            command = json.loads(proc.stdout)["command"]

            self.assertEqual(
                command[1],
                str(runtime / "build-ai-investigation-prompt.py"),
            )
            self.assertIn("--blind-reanalysis", command)


if __name__ == "__main__":
    unittest.main()
