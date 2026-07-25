import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n" / "bin" / "set-runtime-release-id.py"
INSTALLER = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load_module():
    spec = importlib.util.spec_from_file_location("runtime_release_id", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load runtime release helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RuntimeReleaseIdTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()
        cls.installer_source = INSTALLER.read_text(encoding="utf-8")

    def test_validates_release_ids_without_an_env_file(self) -> None:
        self.assertEqual(
            self.module.validate_release_id("abc1234-tested"),
            "abc1234-tested",
        )
        with self.assertRaises(self.module.ReleaseIdError):
            self.module.validate_release_id("bad value")

    def test_updates_only_release_key_and_preserves_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            env_path = Path(temporary) / ".env"
            env_path.write_text(
                "# operator config\nTOKEN=secret-$-value\n"
                "ONION_SENTINEL_RELEASE_ID=old-release\nCHAT_ID=123\n",
                encoding="utf-8",
            )
            os.chmod(env_path, 0o640)

            self.module.set_runtime_release_id(env_path, "abc1234-tested")

            self.assertEqual(
                env_path.read_text(encoding="utf-8"),
                "# operator config\nTOKEN=secret-$-value\n"
                "ONION_SENTINEL_RELEASE_ID=abc1234-tested\nCHAT_ID=123\n",
            )
            self.assertEqual(env_path.stat().st_mode & 0o777, 0o600)

    def test_appends_release_key_once_and_removes_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            env_path = Path(temporary) / ".env"
            env_path.write_text(
                "A=1\nONION_SENTINEL_RELEASE_ID=first\n"
                "ONION_SENTINEL_RELEASE_ID=second\n",
                encoding="utf-8",
            )

            self.module.set_runtime_release_id(env_path, "release-1234567")

            value = env_path.read_text(encoding="utf-8")
            self.assertEqual(value.count("ONION_SENTINEL_RELEASE_ID="), 1)
            self.assertIn("ONION_SENTINEL_RELEASE_ID=release-1234567", value)

    def test_rejects_invalid_ids_and_symlink_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env_path = root / ".env"
            env_path.write_text("A=1\n", encoding="utf-8")
            with self.assertRaises(self.module.ReleaseIdError):
                self.module.set_runtime_release_id(env_path, "bad value")

            link = root / "linked.env"
            link.symlink_to(env_path)
            with self.assertRaises(self.module.ReleaseIdError):
                self.module.set_runtime_release_id(link, "release-1234567")

    def test_installer_validates_release_before_quiescing_or_mutating_runtime(
        self,
    ) -> None:
        source = self.installer_source
        validation = source.index(
            '/usr/bin/python3 "$REPO_DIR/n8n/bin/set-runtime-release-id.py"'
        )
        quiesce = source.index(
            "trap keep_critical_agents_down_on_failure EXIT\n"
            "critical_launch_agents_down\n"
            "if ! critical_launch_agents_are_down"
        )
        first_mutation = source.index('mkdir -p "$STACK_DIR/alert_store/config"')
        self.assertLess(validation, quiesce)
        self.assertLess(quiesce, first_mutation)
        self.assertIn(
            'if [[ "${ALLOW_UNVERSIONED_RECOVERY:-0}" != "1" ]]',
            source,
        )
        self.assertIn('RUNTIME_RELEASE_ID="unversioned"', source)
        self.assertIn(
            '--release-id "$RUNTIME_RELEASE_ID" \\\n  --validate-only',
            source,
        )

    def test_installer_stops_only_code_consumers_before_runtime_copies(
        self,
    ) -> None:
        source = self.installer_source
        early_quiesce = source.index(
            "trap keep_critical_agents_down_on_failure EXIT\n"
            "critical_launch_agents_down\n"
            "if ! critical_launch_agents_are_down"
        )
        first_copy = source.index(
            'cp "$REPO_DIR/n8n/docker-compose.yml"'
        )
        unrelated_quiesce = source.index(
            'launchctl unload "$LAUNCHD_DIR/com.arron.n8n.ensure-stack.plist"'
        )
        docker_start = source.index(
            '/usr/local/bin/docker compose -f "$STACK_DIR/docker-compose.yml"'
        )
        first_critical_reload = source.index(
            'launchctl load "$LAUNCHD_DIR/com.arron.soc.alert-store.plist"'
        )
        self.assertLess(early_quiesce, first_copy)
        self.assertLess(first_copy, docker_start)
        self.assertLess(docker_start, unrelated_quiesce)
        self.assertLess(unrelated_quiesce, first_critical_reload)
        self.assertIn(
            "trap keep_critical_agents_down_on_failure EXIT",
            source,
        )
        self.assertIn(
            "Install failed; alert-store and both AI LaunchAgents remain stopped.",
            source,
        )


if __name__ == "__main__":
    unittest.main()
