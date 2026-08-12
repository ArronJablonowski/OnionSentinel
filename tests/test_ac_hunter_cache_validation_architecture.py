from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
SERVICE_PATH = DASHBOARD / "ac_hunter_service.py"
CACHE_VALIDATION_PATH = DASHBOARD / "ac_hunter_cache_validation.py"
BASELINE = ROOT / "operations/quality/module-quality-baseline.json"


def load_service():
    if str(DASHBOARD) not in sys.path:
        sys.path.insert(0, str(DASHBOARD))
    spec = importlib.util.spec_from_file_location(
        "ac_hunter_cache_validation_architecture", SERVICE_PATH
    )
    if spec is None or spec.loader is None:
        raise AssertionError("AC Hunter service owner could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=repr
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def nested_tree(edges: int) -> object:
    value: object = "leaf"
    for _index in range(edges):
        value = {"child": value}
    return value


class AcHunterCacheValidationArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.service = load_service()

    def outcome(self, value: object, depth: int = 0) -> dict[str, object]:
        try:
            result = self.service._validate_cache_tree(value, depth)
        except Exception as exc:
            cause = exc.__cause__
            return {
                "status": "error",
                "type": type(exc).__name__,
                "message": str(exc),
                "cause": (
                    None
                    if cause is None
                    else [type(cause).__name__, str(cause)]
                ),
            }
        return {"status": "ok", "result": result}

    def test_signature_and_module_boundaries_are_exact(self) -> None:
        self.assertEqual(
            str(inspect.signature(self.service._validate_cache_tree)),
            "(value: 'object', depth: 'int' = 0) -> 'None'",
        )
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        self.assertNotIn(
            "onion-sentinel-dashboard/ac_hunter_service.py::_validate_cache_tree",
            baseline["functions"],
        )
        self.assertLessEqual(
            len(CACHE_VALIDATION_PATH.read_text().splitlines()), 600
        )
        self.assertNotIn(
            "from ac_hunter_service import",
            CACHE_VALIDATION_PATH.read_text(),
        )
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text()
        service_copy = (
            'ac_hunter_service.py" "$DASHBOARD_RUNTIME_DIR/ac_hunter_service.py"'
        )
        owner_copy = (
            'ac_hunter_cache_validation.py" '
            '"$DASHBOARD_RUNTIME_DIR/ac_hunter_cache_validation.py"'
        )
        self.assertIn(service_copy, installer)
        self.assertIn(owner_copy, installer)
        self.assertLess(installer.index(owner_copy), installer.index(service_copy))

    def test_exact_bounds_scalar_policy_and_error_precedence_are_stable(self) -> None:
        cases = [
            ("none", None, 0),
            ("false", False, 0),
            ("true", True, 0),
            ("int", 3, 0),
            ("float", 1.5, 0),
            ("nan", float("nan"), 0),
            ("inf", float("inf"), 0),
            ("depth12", "leaf", 12),
            ("depth13", "leaf", 13),
            ("nested12", nested_tree(12), 0),
            ("nested13", nested_tree(13), 0),
            ("dict1000", {str(index): index for index in range(1000)}, 0),
            ("dict1001", {str(index): index for index in range(1001)}, 0),
            ("list5000", [0] * 5000, 0),
            ("list5001", [0] * 5001, 0),
            ("key128", {"k" * 128: 1}, 0),
            ("key129", {"k" * 129: 1}, 0),
            ("keyint", {1: "x"}, 0),
            ("forbidden", {"TOKEN": "x"}, 0),
            ("text8192", "x" * 8192, 0),
            ("text8193", "x" * 8193, 0),
            ("controls_allowed", "\t\n\v\f\r\x7f", 0),
            ("control8", "a\x08b", 0),
            ("control14", "a\x0eb", 0),
            ("bytes", b"x", 0),
            ("tuple", (1,), 0),
            ("set", {1}, 0),
            ("complex", 1 + 2j, 0),
            (
                "object_precedence",
                {str(index): 0 for index in range(1001)}
                | {1: "x", "token": "x"},
                0,
            ),
            ("key_precedence", {1: "x", "token": "x"}, 0),
            ("forbidden_precedence", {"token": "x", "bad": b"x"}, 0),
        ]
        outcomes = [
            (name, self.outcome(value, depth))
            for name, value, depth in cases
        ]
        self.assertEqual(
            digest(outcomes),
            "879e2cb0eb2eae96195fb3d9e427247616ef0781b07c636f218c5d1ad1eda37e",
        )
        self.assertEqual(outcomes[7][1]["status"], "ok")
        self.assertEqual(
            outcomes[8][1]["message"],
            "AC Hunter cache nesting is invalid",
        )
        self.assertEqual(
            outcomes[28][1]["message"],
            "AC Hunter cache object is too large",
        )
        self.assertEqual(
            outcomes[29][1]["message"],
            "AC Hunter cache key is invalid",
        )
        self.assertEqual(
            outcomes[30][1]["message"],
            "AC Hunter cache contains authentication material",
        )

    def test_forbidden_keys_are_case_insensitive_and_exact(self) -> None:
        for key in sorted(self.service.FORBIDDEN_CACHE_KEYS):
            for candidate in (key, key.upper(), key.title()):
                with self.subTest(candidate=candidate):
                    outcome = self.outcome({candidate: "secret"})
                    self.assertEqual(
                        outcome,
                        {
                            "status": "error",
                            "type": "AcHunterConfigurationError",
                            "message": (
                                "AC Hunter cache contains authentication material"
                            ),
                            "cause": None,
                        },
                    )

    def test_tree_validation_never_mutates_success_or_failure_inputs(self) -> None:
        valid = {
            "modules": [{"nested": [1, 2, {"text": "safe"}]}],
            "metadata": {"count": 3},
        }
        valid_before = copy.deepcopy(valid)
        self.assertIsNone(self.service._validate_cache_tree(valid))
        self.assertEqual(valid, valid_before)

        invalid = {"modules": [{"nested": {"password": "secret"}}]}
        invalid_before = copy.deepcopy(invalid)
        with self.assertRaisesRegex(
            self.service.AcHunterConfigurationError,
            "contains authentication material",
        ):
            self.service._validate_cache_tree(invalid)
        self.assertEqual(invalid, invalid_before)

    def test_validate_cache_precedence_and_deep_copy_are_exact(self) -> None:
        valid = {
            "schema": self.service.REVIEW_SCHEMA,
            "version": self.service.REVIEW_VERSION,
            "ok": True,
            "modules": {},
            "metadata": {"dataset": self.service.FIXED_DATASET},
            "cache": {},
            "last_pulled_at": "2026-08-12T15:00:00Z",
        }
        before = copy.deepcopy(valid)
        result = self.service.validate_cache(valid)
        self.assertEqual(result, valid)
        self.assertIsNot(result, valid)
        result["modules"]["changed"] = True
        self.assertEqual(valid, before)

        cases = [
            (dict(valid, schema="bad", token="x"), "schema is unsupported"),
            (
                {**valid, "metadata": {"dataset": "bad"}, "token": "x"},
                "dataset is invalid",
            ),
            (
                {**valid, "last_pulled_at": "bad", "token": "x"},
                "timestamp is invalid",
            ),
            ({**valid, "token": "x"}, "contains authentication material"),
        ]
        for payload, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(
                    self.service.AcHunterConfigurationError,
                    message,
                ) as raised:
                    self.service.validate_cache(payload)
                self.assertIsNone(raised.exception.__cause__)


if __name__ == "__main__":
    unittest.main()
