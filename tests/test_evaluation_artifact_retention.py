from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n/bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class EvaluationArtifactRetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_module(
            "evaluation_artifact_contract_test",
            BIN / "evaluation_artifact_contract.py",
        )
        cls.seal = load_module(
            "evaluation_artifact_seal_test",
            BIN / "evaluation_artifact_seal.py",
        )
        cls.retention = load_module(
            "evaluation_artifact_retention_test",
            BIN / "evaluation_artifact_retention.py",
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.stack = Path(self.temporary.name).resolve()
        self.root = self.stack / "harness-evaluations"
        self.root.mkdir(mode=0o700)
        self.now = dt.datetime(2026, 8, 15, 12, tzinfo=dt.timezone.utc)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_run(self, name: str, *, age_days: int) -> Path:
        run = self.root / name
        run.mkdir(mode=0o700)
        output = run / "result.json"
        output.write_text('{"qualified":true}\n', encoding="utf-8")
        output.chmod(0o600)
        temporary = run / "tmp"
        temporary.mkdir(mode=0o700)
        (temporary / "provider-transcript.txt").write_text(
            "synthetic transcript\n", encoding="utf-8"
        )
        when = (self.now - dt.timedelta(days=age_days)).timestamp()
        for path in (run, output, temporary, temporary / "provider-transcript.txt"):
            os.utime(path, (when, when))
        return run

    def seal_run(self, run: Path, *, age_days: int = 40) -> Path:
        return self.seal.write_seal(
            run,
            outputs=(run / "result.json",),
            completed_at=self.now - dt.timedelta(days=age_days),
        )

    def test_seal_is_owner_only_digest_bound_and_verifiable(self) -> None:
        run = self.make_run("sealed", age_days=40)
        seal_path = self.seal_run(run)
        self.assertEqual(seal_path.stat().st_mode & 0o777, 0o600)
        document = json.loads(seal_path.read_text(encoding="utf-8"))
        self.assertEqual(
            document["schema"], "onion-sentinel-evaluation-artifact-seal-v1"
        )
        self.assertEqual(document["outputs"][0]["path"], "result.json")
        verified = self.seal.verify_seal(run)
        self.assertEqual(verified["output_count"], 1)
        output = run / "result.json"
        original = output.read_bytes()
        output.write_bytes(original[::-1])
        with self.assertRaisesRegex(ValueError, "digest"):
            self.seal.verify_seal(run)

    def test_temp_cleanup_requires_a_valid_seal_and_preserves_outputs(self) -> None:
        unsealed = self.make_run("unsealed", age_days=2)
        sealed = self.make_run("sealed", age_days=2)
        self.seal_run(sealed, age_days=2)
        policy = self.contract.default_policy()

        preview = self.retention.maintain(
            self.stack, now=self.now, policy=policy, apply=False
        )
        self.assertEqual(preview["cleanup"]["temporary_candidates"], 1)
        self.assertTrue((sealed / "tmp").exists())
        self.assertTrue((unsealed / "tmp").exists())

        applied = self.retention.maintain(
            self.stack, now=self.now, policy=policy, apply=True
        )
        self.assertEqual(applied["cleanup"]["temporary_removed"], 1)
        self.assertFalse((sealed / "tmp").exists())
        self.assertTrue((sealed / "result.json").is_file())
        self.assertTrue((unsealed / "tmp").exists())

    def test_temporary_content_cannot_be_declared_as_a_final_output(self) -> None:
        run = self.make_run("temporary-output", age_days=2)
        with self.assertRaisesRegex(ValueError, "non-temporary"):
            self.seal.write_seal(
                run,
                outputs=(run / "tmp/provider-transcript.txt",),
                completed_at=self.now,
            )
        self.assertFalse((run / "evaluation-artifact-seal.json").exists())

    def test_expired_run_deletion_is_bounded_and_seal_gated(self) -> None:
        first = self.make_run("sealed-first", age_days=40)
        second = self.make_run("sealed-second", age_days=39)
        unsealed = self.make_run("unsealed-sensitive-case", age_days=50)
        self.seal_run(first)
        self.seal_run(second)
        policy = self.contract.default_policy(
            max_run_deletions_per_pass=1,
            preserve_newest_runs=1,
        )

        result = self.retention.maintain(
            self.stack, now=self.now, policy=policy, apply=True
        )
        self.assertEqual(result["cleanup"]["run_directories_removed"], 1)
        self.assertFalse(first.exists())
        self.assertTrue(second.exists())
        self.assertTrue(unsealed.exists())
        self.assertEqual(result["alerts"][0]["code"], "unsealed_expired_run")
        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn("unsealed-sensitive-case", rendered)
        self.assertNotIn("synthetic transcript", rendered)

    def test_report_files_have_age_and_count_bounds(self) -> None:
        reports = self.stack / "logs/soak-reports"
        reports.mkdir(parents=True, mode=0o700)
        for index in range(5):
            path = reports / f"report-{index}.json"
            path.write_text("{}\n", encoding="utf-8")
            path.chmod(0o600)
            when = (self.now - dt.timedelta(days=index)).timestamp()
            os.utime(path, (when, when))
        policy = self.contract.default_policy(
            soak_report_max_count=2,
            soak_report_retention_days=30,
        )
        result = self.retention.maintain(
            self.stack, now=self.now, policy=policy, apply=True
        )
        remaining = sorted(path.name for path in reports.iterdir())
        self.assertEqual(remaining, ["report-0.json", "report-1.json"])
        self.assertEqual(result["cleanup"]["report_files_removed"], 3)

    def test_count_pressure_skips_ineligible_runs_until_bound_can_shrink(self) -> None:
        self.make_run("oldest-unsealed", age_days=10)
        eligible = self.make_run("eligible-sealed", age_days=9)
        newest = self.make_run("newest-sealed", age_days=1)
        self.seal_run(eligible, age_days=9)
        self.seal_run(newest, age_days=1)
        policy = self.contract.default_policy(
            max_run_directories=2,
            preserve_newest_runs=1,
            max_run_deletions_per_pass=1,
        )

        result = self.retention.maintain(
            self.stack, now=self.now, policy=policy, apply=True
        )
        self.assertEqual(result["cleanup"]["run_directories_removed"], 1)
        self.assertFalse(eligible.exists())
        self.assertTrue(newest.exists())

    def test_bounded_report_cleanup_removes_oldest_candidate_first(self) -> None:
        reports = self.stack / "logs/soak-reports"
        reports.mkdir(parents=True, mode=0o700)
        for name, age_days in (
            ("z-oldest.json", 3),
            ("m-middle.json", 2),
            ("a-newer.json", 1),
            ("newest.json", 0),
        ):
            path = reports / name
            path.write_text("{}\n", encoding="utf-8")
            path.chmod(0o600)
            when = (self.now - dt.timedelta(days=age_days)).timestamp()
            os.utime(path, (when, when))
        policy = self.contract.default_policy(
            soak_report_max_count=1,
            soak_report_retention_days=30,
            max_report_deletions_per_pass=1,
        )

        result = self.retention.maintain(
            self.stack, now=self.now, policy=policy, apply=True
        )
        self.assertEqual(result["cleanup"]["report_files_removed"], 1)
        self.assertFalse((reports / "z-oldest.json").exists())
        self.assertTrue((reports / "a-newer.json").exists())

    def test_local_and_encrypted_storage_thresholds_are_independent(self) -> None:
        policy = self.contract.default_policy(
            local_warning_percent=65,
            local_failure_percent=75,
            encrypted_warning_percent=70,
            encrypted_failure_percent=85,
        )
        healthy = self.retention.storage_alerts(
            local_used_percent=64.9,
            encrypted_used_percent=69.9,
            policy=policy,
        )
        self.assertEqual(healthy, [])
        alerts = self.retention.storage_alerts(
            local_used_percent=76,
            encrypted_used_percent=71,
            policy=policy,
        )
        self.assertEqual(
            [(item["code"], item["severity"]) for item in alerts],
            [
                ("local_evaluation_storage_capacity", "failure"),
                ("encrypted_evaluation_storage_capacity", "warning"),
            ],
        )

    def test_installer_and_launchagent_own_the_runtime_policy(self) -> None:
        installer = (BIN / "install-macstudio-stack.zsh").read_text(
            encoding="utf-8"
        )
        for name in (
            "maintain-evaluation-artifacts.py",
            "seal-evaluation-artifacts.py",
            "evaluation_artifact_contract.py",
            "evaluation_artifact_seal.py",
            "evaluation_artifact_retention.py",
        ):
            self.assertIn(name, installer)
        launchagent = ROOT / (
            "n8n/launchd/"
            "com.arron.onion-sentinel.evaluation-artifact-maintenance.plist"
        )
        text = launchagent.read_text(encoding="utf-8")
        self.assertIn("maintain-evaluation-artifacts.py", text)
        self.assertIn("--apply", text)

    def test_flat_bin_clis_publish_owner_only_content_free_receipts(self) -> None:
        run = self.make_run("case-name-must-not-leak", age_days=2)
        seal_command = [
            sys.executable,
            str(BIN / "seal-evaluation-artifacts.py"),
            "--run-dir",
            str(run),
            "--output",
            str(run / "result.json"),
            "--completed-at",
            "2026-08-13T12:00:00Z",
        ]
        sealed = subprocess.run(
            seal_command, text=True, capture_output=True, check=False
        )
        self.assertEqual(sealed.returncode, 0, sealed.stderr)
        self.assertNotIn("case-name-must-not-leak", sealed.stdout)
        report = self.stack / "logs/evaluation-artifact-maintenance.json"
        maintained = subprocess.run(
            [
                sys.executable,
                str(BIN / "maintain-evaluation-artifacts.py"),
                "--stack-dir",
                str(self.stack),
                "--report",
                str(report),
                "--apply",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(maintained.returncode, 0, maintained.stderr)
        self.assertEqual(report.stat().st_mode & 0o777, 0o600)
        rendered = report.read_text(encoding="utf-8")
        self.assertNotIn("case-name-must-not-leak", rendered)
        self.assertNotIn("synthetic transcript", rendered)
        self.assertFalse((run / "tmp").exists())
        self.assertTrue((run / "result.json").is_file())


if __name__ == "__main__":
    unittest.main()
