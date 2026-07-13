#!/usr/bin/env python3
"""Behavior checks for portal artifact index caching."""
from pathlib import Path
import importlib.util
import tempfile
import threading
import time
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "onion-sentinel-dashboard" / "artifact_cache.py"


def load_module():
    spec = importlib.util.spec_from_file_location("artifact_cache_under_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ArtifactCacheTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_cache_invalidates_when_directory_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir)
            cache = self.module.ArtifactCache(60)
            cache.put("index", path, {"value": 1})
            self.assertEqual(cache.get("index", path), {"value": 1})
            time.sleep(0.01)
            (path / "artifact.json").write_text("{}", encoding="utf-8")
            self.assertIsNone(cache.get("index", path))

    def test_cache_expires_by_ttl(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir)
            cache = self.module.ArtifactCache(0)
            cache.put("index", path, 1)
            self.assertIsNone(cache.get("index", path))

    def test_concurrent_misses_compute_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir)
            cache = self.module.ArtifactCache(60)
            calls = 0
            calls_lock = threading.Lock()

            def compute() -> dict:
                nonlocal calls
                with calls_lock:
                    calls += 1
                time.sleep(0.02)
                return {"ready": True}

            results: list[dict] = []
            threads = [
                threading.Thread(
                    target=lambda: results.append(cache.get_or_compute("index", path, compute))
                )
                for _ in range(12)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            self.assertEqual(calls, 1)
            self.assertEqual(results, [{"ready": True}] * 12)


if __name__ == "__main__":
    unittest.main()
