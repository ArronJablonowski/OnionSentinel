#!/usr/bin/env python3
"""Concurrency behavior for the dashboard response cache."""
from pathlib import Path
import importlib.util
import threading
import time
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "onion-sentinel-dashboard" / "response_cache.py"


def load_module():
    spec = importlib.util.spec_from_file_location("response_cache_under_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ResponseCacheTest(unittest.TestCase):
    def test_identical_concurrent_requests_compute_once(self) -> None:
        cache = load_module().ResponseCache(10)
        calls = 0
        calls_lock = threading.Lock()

        def compute() -> dict:
            nonlocal calls
            with calls_lock:
                calls += 1
            time.sleep(0.02)
            return {"ok": True}

        results: list[dict] = []
        threads = [threading.Thread(target=lambda: results.append(cache.get_or_compute("a", compute))) for _ in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(calls, 1)
        self.assertEqual(results, [{"ok": True}] * 20)

    def test_distinct_keys_do_not_block_each_other(self) -> None:
        cache = load_module().ResponseCache(10, lock_stripes=64)
        started = threading.Barrier(2)

        def compute() -> bool:
            started.wait(timeout=1)
            return True

        results: list[bool] = []
        threads = [threading.Thread(target=lambda key=key: results.append(cache.get_or_compute(key, compute))) for key in ("a", "b")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results, [True, True])

    def test_unique_query_growth_is_bounded(self) -> None:
        cache = load_module().ResponseCache(10, max_entries=8, lock_stripes=4)
        for index in range(100):
            cache.get_or_compute(f"query-{index}", lambda index=index: index)
        self.assertLessEqual(len(cache._entries), 8)
        self.assertEqual(len(cache._locks), 4)

    def test_clear_forces_recompute_after_mutation(self) -> None:
        cache = load_module().ResponseCache(10)
        self.assertEqual(cache.get_or_compute("alerts", lambda: 1), 1)
        cache.clear()
        self.assertEqual(cache.get_or_compute("alerts", lambda: 2), 2)


if __name__ == "__main__":
    unittest.main()
