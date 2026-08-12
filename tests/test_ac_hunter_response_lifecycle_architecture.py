from __future__ import annotations

import ast
import importlib
import inspect
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
SERVICE_PATH = DASHBOARD / "ac_hunter_service.py"


def load_service():
    if str(DASHBOARD) not in sys.path:
        sys.path.insert(0, str(DASHBOARD))
    return importlib.import_module("ac_hunter_service")


def function_metrics(class_name: str, function_name: str) -> tuple[int, int]:
    tree = ast.parse(SERVICE_PATH.read_text(encoding="utf-8"))
    owner = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == class_name
    )
    target = next(
        node
        for node in owner.body
        if isinstance(node, ast.FunctionDef) and node.name == function_name
    )
    complexity = 1
    for node in ast.walk(target):
        if node is target:
            continue
        if isinstance(node, (ast.If, ast.For, ast.While)):
            complexity += 1
        elif isinstance(node, ast.Try):
            complexity += len(node.handlers)
        elif isinstance(node, ast.BoolOp):
            complexity += max(0, len(node.values) - 1)
        elif isinstance(node, ast.IfExp):
            complexity += 1
    return target.end_lineno - target.lineno + 1, complexity


class TrackingLock:
    def __init__(self, trace):
        self.trace = trace

    def __enter__(self):
        self.trace.append(["lock", "enter"])
        return self

    def __exit__(self, exc_type, _exc, _traceback):
        self.trace.append(
            ["lock", "exit", exc_type.__name__ if exc_type else None]
        )
        return False


class TrackingConfig(dict):
    def __init__(self, values, trace):
        super().__init__(values)
        self.trace = trace

    def get(self, key, default=None):
        self.trace.append(["config.get", key])
        return super().get(key, default)

    def __getitem__(self, key):
        self.trace.append(["config[]", key])
        return super().__getitem__(key)


class AcHunterResponseLifecycleArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.service_module = load_service()

    def service(self, trace, **config):
        values = {
            "enabled": True,
            "cache_file": "/private/test/ac-hunter.json",
            "cache_ttl_seconds": 300,
            **config,
        }
        service = self.service_module.AcHunterReviewService(
            values,
            client=object(),
            clock=lambda: 1000.0,
            collector=lambda _client, _clock: {},
        )
        service.config = TrackingConfig(values, trace)
        service._lock = TrackingLock(trace)
        return service

    def test_signature_current_debt_and_compatibility_subclass_are_exact(self) -> None:
        signature = inspect.signature(
            self.service_module.AcHunterReviewService.response
        )
        self.assertEqual(list(signature.parameters), ["self", "force_refresh"])
        self.assertEqual(signature.parameters["force_refresh"].default, False)
        self.assertEqual(str(signature.return_annotation), "Tuple[int, Dict[str, Any]]")
        for name in (
            "_fresh_cached_response",
            "_refresh_response",
            "response",
        ):
            lines, complexity = function_metrics(
                "AcHunterReviewService", name
            )
            self.assertLessEqual(lines, 50)
            self.assertLessEqual(complexity, 10)
        facade = importlib.import_module("ac_hunter_review")
        self.assertTrue(
            issubclass(
                facade.AcHunterReviewService,
                self.service_module.AcHunterReviewService,
            )
        )
        self.assertLessEqual(len(SERVICE_PATH.read_text().splitlines()), 600)

    def test_disabled_and_missing_client_fail_inside_the_lock_only(self) -> None:
        for enabled, client, expected in (
            (False, object(), "AC Hunter Deep Review is disabled"),
            (True, None, "AC Hunter client is unavailable"),
        ):
            with self.subTest(enabled=enabled, client=client):
                trace = []
                service = self.service(trace, enabled=enabled)
                service.client = client
                payload = {"case": expected}

                def error_payload(error, *, stale):
                    trace.append(["error_payload", error, stale])
                    return payload

                with mock.patch.object(
                    self.service_module, "_error_payload", error_payload
                ):
                    result = service.response()
                self.assertEqual(result[0], 503)
                self.assertIs(result[1], payload)
                self.assertEqual(
                    trace,
                    [
                        ["lock", "enter"],
                        ["config.get", "enabled"],
                        ["error_payload", expected, False],
                        ["lock", "exit", None],
                    ],
                )

    def test_force_limited_fresh_cache_preserves_age_calls_and_view_identity(self) -> None:
        trace = []
        service = self.service(trace)
        cached = {"cached": True}
        view = {"cache": {}}

        def clock():
            trace.append(["clock"])
            return 1000.0

        def cached_value():
            trace.append(["cached"])
            return cached

        def cache_age(value, now):
            trace.append(["cache_age", value is cached, now])
            return 10.9

        def cache_view(value, **kwargs):
            trace.append(["cache_view", value is cached, kwargs])
            return view

        service.clock = clock
        service._cached = cached_value
        with mock.patch.object(
            self.service_module, "_cache_age", cache_age
        ), mock.patch.object(self.service_module, "_cache_view", cache_view):
            result = service.response(force_refresh=True)

        self.assertEqual(result[0], 200)
        self.assertIs(result[1], view)
        self.assertEqual(
            view["cache"],
            {
                "refresh_limited": True,
                "refresh_available_in_seconds": (
                    self.service_module.MIN_FORCE_REFRESH_INTERVAL_SECONDS - 10
                ),
            },
        )
        self.assertEqual(
            trace,
            [
                ["lock", "enter"],
                ["config.get", "enabled"],
                ["clock"],
                ["config[]", "cache_ttl_seconds"],
                ["cached"],
                ["cache_age", True, 1000.0],
                ["cache_age", True, 1000.0],
                [
                    "cache_view",
                    True,
                    {"now": 1000.0, "ttl": 300, "stale": False},
                ],
                ["cache_age", True, 1000.0],
                ["lock", "exit", None],
            ],
        )

    def test_cache_error_then_refresh_preserves_validation_write_and_state_order(self) -> None:
        trace = []
        service = self.service(trace)
        client = service.client
        raw = {"raw": True}
        fresh = {"fresh": True}
        view = {"view": True}
        times = iter((1000.0, 1001.0))

        def clock():
            value = next(times)
            trace.append(["clock", value])
            return value

        def cached_value():
            trace.append(["cached"])
            raise self.service_module.AcHunterConfigurationError("bad cache")

        def collector(actual_client, actual_clock):
            trace.append(
                ["collector", actual_client is client, actual_clock is clock]
            )
            return raw

        def validate(value):
            trace.append(["validate", value is raw])
            return fresh

        def write(path, value):
            trace.append(["write", str(path), value is fresh])

        def cache_view(value, **kwargs):
            trace.append(["cache_view", value is fresh, kwargs])
            return view

        service.clock = clock
        service._cached = cached_value
        service.collector = collector
        with mock.patch.object(
            self.service_module, "validate_cache", validate
        ), mock.patch.object(
            self.service_module, "atomic_write_cache", write
        ), mock.patch.object(self.service_module, "_cache_view", cache_view):
            result = service.response()

        self.assertEqual(result[0], 200)
        self.assertIs(result[1], view)
        self.assertIs(service._memory_cache, fresh)
        self.assertEqual(
            trace,
            [
                ["lock", "enter"],
                ["config.get", "enabled"],
                ["clock", 1000.0],
                ["config[]", "cache_ttl_seconds"],
                ["cached"],
                ["collector", True, True],
                ["validate", True],
                ["config[]", "cache_file"],
                ["write", "/private/test/ac-hunter.json", True],
                ["clock", 1001.0],
                [
                    "cache_view",
                    True,
                    {"now": 1001.0, "ttl": 300, "stale": False},
                ],
                ["lock", "exit", None],
            ],
        )

    def test_collection_failures_preserve_redacted_stale_and_unavailable_paths(self) -> None:
        cases = (
            (
                self.service_module.AcHunterTransportError(
                    "Authorization: Bearer hidden"
                ),
                {"cached": True},
                200,
                "stale-view",
                True,
            ),
            (RuntimeError("private generic detail"), {"cached": True}, 200, "stale-view", False),
            (RuntimeError("private generic detail"), None, 503, "error-view", False),
        )
        for failure, cached, expected_status, expected_view, safe_called in cases:
            with self.subTest(
                failure=type(failure).__name__, cached=cached is not None
            ):
                trace = []
                service = self.service(trace)
                times = iter((1000.0, 1001.0))

                def clock():
                    value = next(times)
                    trace.append(["clock", value])
                    return value

                def cached_value():
                    trace.append(["cached"])
                    return cached

                def age(value, now):
                    trace.append(["cache_age", value is cached, now])
                    return 301.0

                def collector(_client, _clock):
                    trace.append(["collector"])
                    raise failure

                def safe_error(error):
                    trace.append(["safe_error", error is failure])
                    return "redacted"

                def cache_view(value, **kwargs):
                    trace.append(["cache_view", value is cached, kwargs])
                    return "stale-view"

                def error_payload(error, *, stale):
                    trace.append(["error_payload", error, stale])
                    return "error-view"

                service.clock = clock
                service._cached = cached_value
                service.collector = collector
                with mock.patch.object(
                    self.service_module, "_cache_age", age
                ), mock.patch.object(
                    self.service_module, "_safe_error", safe_error
                ), mock.patch.object(
                    self.service_module, "_cache_view", cache_view
                ), mock.patch.object(
                    self.service_module, "_error_payload", error_payload
                ):
                    result = service.response()

                self.assertEqual(result, (expected_status, expected_view))
                self.assertEqual(
                    any(item[0] == "safe_error" for item in trace), safe_called
                )
                projected_error = (
                    "redacted"
                    if safe_called
                    else "AC Hunter normalized collection failed"
                )
                if cached is not None:
                    self.assertIn(
                        [
                            "cache_view",
                            True,
                            {
                                "now": 1001.0,
                                "ttl": 300,
                                "stale": True,
                                "error": projected_error,
                            },
                        ],
                        trace,
                    )
                else:
                    self.assertIn(
                        ["error_payload", projected_error, False], trace
                    )
                self.assertEqual(trace[0], ["lock", "enter"])
                self.assertEqual(trace[-1], ["lock", "exit", None])

    def test_non_ac_hunter_cache_failure_propagates_and_releases_lock(self) -> None:
        trace = []
        service = self.service(trace)

        def cached_value():
            trace.append(["cached"])
            raise TypeError("synthetic cache failure")

        service._cached = cached_value
        with self.assertRaisesRegex(TypeError, "synthetic cache failure") as raised:
            service.response()
        self.assertIsNone(raised.exception.__cause__)
        self.assertEqual(trace[0], ["lock", "enter"])
        self.assertEqual(trace[-1], ["lock", "exit", "TypeError"])

    def test_nan_cache_age_is_not_admitted_as_fresh(self) -> None:
        trace = []
        service = self.service(trace)
        cached = {"cached": True}
        service._cached = lambda: cached
        calls = []

        def collector(_client, _clock):
            calls.append("refresh")
            raise RuntimeError("refresh attempted")

        service.collector = collector
        with mock.patch.object(
            self.service_module, "_cache_age", return_value=float("nan")
        ):
            with self.assertRaisesRegex(ValueError, "NaN"):
                service.response(force_refresh=True)
        self.assertEqual(calls, ["refresh"])


if __name__ == "__main__":
    unittest.main()
