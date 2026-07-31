#!/usr/bin/env python3
"""Behavior checks for provider-scoped enrichment scheduling."""
from pathlib import Path
import json
import subprocess
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEDULER = REPO_ROOT / "n8n" / "alert_store" / "lib" / "provider_scheduler.js"


class ProviderSchedulerTest(unittest.TestCase):
    def run_node(self, script: str) -> dict:
        result = subprocess.run(
            ["node", "-e", script],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout)

    def test_same_provider_serializes_while_different_provider_overlaps(self) -> None:
        payload = self.run_node(f"""
const {{createProviderScheduler}} = require({json.dumps(str(SCHEDULER))});
const scheduler = createProviderScheduler();
let activeA = 0; let maxA = 0; let activeAll = 0; let maxAll = 0;
const task = (provider) => scheduler.run(provider, async () => {{
  activeAll += 1; maxAll = Math.max(maxAll, activeAll);
  if (provider === 'a') {{ activeA += 1; maxA = Math.max(maxA, activeA); }}
  await new Promise((resolve) => setTimeout(resolve, 30));
  if (provider === 'a') activeA -= 1;
  activeAll -= 1;
}});
Promise.all([task('a'), task('a'), task('b')]).then(() => console.log(JSON.stringify({{maxA, maxAll}})));
""")
        self.assertEqual(payload["maxA"], 1)
        self.assertGreaterEqual(payload["maxAll"], 2)

    def test_circuit_opens_after_bounded_failures(self) -> None:
        payload = self.run_node(f"""
const {{createProviderScheduler}} = require({json.dumps(str(SCHEDULER))});
const scheduler = createProviderScheduler({{failureThreshold: 2, resetMs: 60000}});
(async () => {{
  for (let i = 0; i < 2; i += 1) {{ try {{ await scheduler.run('x', async () => {{ throw new Error('fail'); }}); }} catch {{}} }}
  let circuit = ''; try {{ await scheduler.run('x', async () => 'unexpected'); }} catch (error) {{ circuit = error.message; }}
  console.log(JSON.stringify({{circuit, snapshot: scheduler.snapshot()}}));
}})();
""")
        self.assertIn("provider circuit open", payload["circuit"])
        self.assertTrue(payload["snapshot"]["x"]["circuit_open"])
        self.assertEqual(payload["snapshot"]["x"]["queued"], 0)
        self.assertGreater(payload["snapshot"]["x"]["backoff_seconds"], 0)

    def test_repeated_failures_use_bounded_exponential_backoff(self) -> None:
        payload = self.run_node(f"""
const {{createProviderScheduler}} = require({json.dumps(str(SCHEDULER))});
let current = 0;
const realNow = Date.now;
Date.now = () => current;
const scheduler = createProviderScheduler({{failureThreshold: 1, resetMs: 1000, maxResetMs: 4000}});
(async () => {{
  try {{ await scheduler.run('x', async () => {{ throw new Error('first'); }}); }} catch {{}}
  const first = scheduler.snapshot().x;
  current = 1001;
  try {{ await scheduler.run('x', async () => {{ throw new Error('second'); }}); }} catch {{}}
  const second = scheduler.snapshot().x;
  current = 3002;
  try {{ await scheduler.run('x', async () => {{ throw new Error('third'); }}); }} catch {{}}
  const third = scheduler.snapshot().x;
  Date.now = realNow;
  console.log(JSON.stringify({{first, second, third}}));
}})();
""")
        self.assertEqual(payload["first"]["backoff_seconds"], 1)
        self.assertEqual(payload["second"]["backoff_seconds"], 2)
        self.assertEqual(payload["third"]["backoff_seconds"], 4)


if __name__ == "__main__":
    unittest.main()
