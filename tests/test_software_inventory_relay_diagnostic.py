"""Characterization for bounded Software Inventory relay diagnostics."""
from __future__ import annotations

import importlib.util
import json
import random
import string
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n" / "bin" / "software_inventory_transport.py"


def load_module():
    dependency = str(MODULE_PATH.parent)
    if dependency not in sys.path:
        sys.path.insert(0, dependency)
    spec = importlib.util.spec_from_file_location(
        "software_inventory_relay_diagnostic_target",
        MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Software Inventory transport")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SoftwareInventoryRelayDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def test_allowlist_order_string_filtering_and_bounds_are_exact(self) -> None:
        stdout = json.dumps(
            {
                "transport_detail": " fifth " + "e" * 400,
                "ignored": "must-not-appear",
                "detail": " second\tvalue ",
                "error": " first\u0000value ",
                "upstream_error": 7,
                "upstream_detail": " fourth\n" + "d" * 400,
            }
        )
        stderr = " stderr\r" + "s" * 400
        result = self.module.relay_failure_diagnostic(stdout, stderr)
        expected_messages = (
            "first value",
            "second value",
            ("fourth " + "d" * 400)[:300],
            ("fifth " + "e" * 400)[:300],
            ("stderr " + "s" * 400)[:300],
        )
        self.assertEqual(result, "; ".join(expected_messages)[:700])
        self.assertEqual(len(result), 700)
        self.assertNotIn("must-not-appear", result)
        self.assertNotIn("7", result)

    def test_invalid_or_non_object_stdout_falls_back_to_stderr_only(self) -> None:
        cases = (
            "not-json",
            "",
            "null",
            "[]",
            '"error"',
            "7",
        )
        for stdout in cases:
            with self.subTest(stdout=stdout):
                self.assertEqual(
                    self.module.relay_failure_diagnostic(
                        stdout,
                        " line\nwith\x00 control ",
                    ),
                    "line with control",
                )

    def test_empty_values_and_object_coercion_preserve_exact_output(self) -> None:
        class Value:
            def __str__(self) -> str:
                return " object\tstderr "

        self.assertEqual(
            self.module.relay_failure_diagnostic(
                json.dumps({"error": " \x00\n", "detail": "ok"}),
                Value(),
            ),
            "ok; object stderr",
        )
        self.assertEqual(
            self.module.relay_failure_diagnostic(None, None),
            "",
        )

    def test_seeded_projection_matches_the_characterized_reference(self) -> None:
        randomizer = random.Random(20260812)
        keys = (
            "error",
            "detail",
            "upstream_error",
            "upstream_detail",
            "transport_detail",
        )

        def normalize(value: object) -> str:
            return " ".join(
                "".join(
                    character if character.isprintable() else " "
                    for character in str(value or "")
                ).split()
            )[:300]

        alphabet = string.ascii_letters + string.digits + " \t\n\x00"
        for case in range(500):
            payload = {}
            for key in keys:
                choice = randomizer.randrange(4)
                if choice == 0:
                    payload[key] = "".join(
                        randomizer.choice(alphabet)
                        for _ in range(randomizer.randrange(0, 420))
                    )
                elif choice == 1:
                    payload[key] = randomizer.randrange(100)
                elif choice == 2:
                    payload[key] = None
            stderr = "".join(
                randomizer.choice(alphabet)
                for _ in range(randomizer.randrange(0, 420))
            )
            expected = [
                normalize(payload[key])
                for key in keys
                if isinstance(payload.get(key), str) and normalize(payload[key])
            ]
            normalized_stderr = normalize(stderr)
            if normalized_stderr:
                expected.append(normalized_stderr)
            with self.subTest(case=case):
                self.assertEqual(
                    self.module.relay_failure_diagnostic(
                        json.dumps(payload),
                        stderr,
                    ),
                    "; ".join(expected)[:700],
                )


if __name__ == "__main__":
    unittest.main()
