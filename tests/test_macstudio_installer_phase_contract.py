import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n/install/macstudio_phase_contract.py"
CONTRACT_PATH = ROOT / "n8n/install/macstudio-phases.json"
INSTALLER_PATH = ROOT / "n8n/bin/install-macstudio-stack.zsh"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "macstudio_phase_contract",
        MODULE_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MacstudioInstallerPhaseContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = load_module()

    def load_current(self):
        return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

    def validate(self, value, installer=None):
        return self.contract.validate_phase_contract(
            value,
            INSTALLER_PATH.read_text(encoding="utf-8")
            if installer is None
            else installer,
        )

    def test_current_installer_obeys_complete_phase_contract(self):
        phases = self.validate(self.load_current())
        self.assertEqual(len(phases), 16)
        self.assertEqual(phases[0].phase_id, "cli_and_release_preflight")
        self.assertEqual(phases[-1].phase_id, "dashboard_wake_and_handoff")

    def test_duplicate_phase_id_fails_closed(self):
        value = self.load_current()
        value["phases"][1]["id"] = value["phases"][0]["id"]
        with self.assertRaisesRegex(self.contract.PhaseContractError, "duplicate"):
            self.validate(value)

    def test_unknown_dependency_and_cycle_fail_closed(self):
        value = self.load_current()
        value["phases"][1]["after"] = ["unknown"]
        with self.assertRaisesRegex(self.contract.PhaseContractError, "unknown"):
            self.validate(value)

        value = self.load_current()
        first = value["phases"][0]["id"]
        last = value["phases"][-1]["id"]
        value["phases"][0]["after"] = [last]
        value["phases"][-1]["after"] = [first]
        with self.assertRaisesRegex(self.contract.PhaseContractError, "cycle"):
            self.validate(value)

    def test_missing_or_duplicated_installer_marker_fails_closed(self):
        value = self.load_current()
        marker = value["phases"][0]["marker"]
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        with self.assertRaisesRegex(self.contract.PhaseContractError, "exactly once"):
            self.validate(value, installer.replace(marker, "", 1))
        with self.assertRaisesRegex(self.contract.PhaseContractError, "exactly once"):
            self.validate(value, installer + "\n" + marker + "\n")

    def test_source_order_inversion_fails_closed(self):
        value = self.load_current()
        first = value["phases"][0]["marker"]
        second = value["phases"][1]["marker"]
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        installer = installer.replace(first, "__FIRST__", 1)
        installer = installer.replace(second, first, 1)
        installer = installer.replace("__FIRST__", second, 1)
        with self.assertRaisesRegex(self.contract.PhaseContractError, "source order"):
            self.validate(value, installer)

    def test_contract_rejects_extra_fields_and_unsafe_identifiers(self):
        value = self.load_current()
        value["unexpected"] = True
        with self.assertRaisesRegex(self.contract.PhaseContractError, "root fields"):
            self.validate(value)

        value = self.load_current()
        value["phases"][0]["id"] = "../unsafe"
        with self.assertRaisesRegex(self.contract.PhaseContractError, "identifier"):
            self.validate(value)

    def test_cli_validates_without_runtime_or_network_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report.json"
            result = self.contract.main(
                [
                    "--contract",
                    str(CONTRACT_PATH),
                    "--installer",
                    str(INSTALLER_PATH),
                    "--report",
                    str(report),
                ]
            )
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(report.read_text())["phase_count"], 16)


if __name__ == "__main__":
    unittest.main()
