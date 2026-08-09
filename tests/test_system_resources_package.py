from pathlib import Path
from types import SimpleNamespace
import sys
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))

from onion_sentinel.analysis import system_resources  # noqa: E402


class SyntheticProcessError(RuntimeError):
    pass


def dependencies(run_command, environment=None):
    return system_resources.Dependencies(
        environment=environment or {},
        path_exists=lambda _path: False,
        run_command=run_command,
        process_error=SyntheticProcessError,
    )


class SystemResourcesPackageTests(unittest.TestCase):
    def test_parses_mactop_metrics_without_losing_zero_gpu_utilization(self) -> None:
        values = system_resources.parse_mactop_sample(
            '{"soc_metrics":{"gpu_temp":44.5,"cpu_temp":55,'
            '"soc_temp":50,"total_power":18},'
            '"gpu_metrics":{"active_percent":0},"gpu_usage":99,'
            '"cpu_usage":21,"memory":{"used":25,"total":100}}'
        )
        self.assertEqual(values, (44.5, 25.0, 18.0, 21.0, 0.0, 55.0, 50.0))

    def test_mactop_collection_uses_fixed_arguments_and_bounded_process(self) -> None:
        calls = []

        def run(command, **kwargs):
            calls.append((command, kwargs))
            return SimpleNamespace(
                returncode=0,
                stdout='{"soc_metrics":{"gpu_temp":42}}',
                stderr="",
            )

        result = system_resources.read_mactop_system_sample(
            dependencies=dependencies(
                run,
                {"SOC_MACTOP_COMMAND": "/custom/mactop --flag"},
            ),
        )
        self.assertEqual(result[0], 42.0)
        self.assertEqual(result[-1], "mactop sampled")
        self.assertEqual(calls[0][0], [
            "/custom/mactop", "--flag", "--headless", "--format", "json",
            "--count", "1",
        ])
        self.assertEqual(calls[0][1]["timeout_seconds"], 8)
        self.assertEqual(calls[0][1]["max_stdout_bytes"], 2 * 1024 * 1024)

    def test_sensor_failures_are_bounded_notes_not_monitor_failures(self) -> None:
        def unavailable(_command, **_kwargs):
            raise SyntheticProcessError("synthetic timeout")

        sample = system_resources.read_mactop_system_sample(
            dependencies=dependencies(
                unavailable,
                {"SOC_MACTOP_COMMAND": "/custom/mactop"},
            ),
        )
        self.assertTrue(all(value is None for value in sample[:-1]))
        self.assertEqual(
            sample[-1],
            "/custom/mactop unavailable: synthetic timeout",
        )

    def test_gpu_reader_honors_preexisting_cancellation(self) -> None:
        cancelled = threading.Event()
        cancelled.set()
        value, note = system_resources.read_gpu_temperature_celsius(
            dependencies=dependencies(lambda *_args, **_kwargs: None),
            cancel_event=cancelled,
        )
        self.assertIsNone(value)
        self.assertEqual(note, "GPU temperature sampling cancelled")

    def test_monitor_retains_maxima_and_uses_gpu_fallback(self) -> None:
        samples = iter([
            (None, 20.0, 5.0, 10.0, 3.0, 40.0, 42.0, "first"),
            (45.0, 30.0, 4.0, 8.0, 6.0, 39.0, 41.0, "second"),
        ])
        monitor = system_resources.SystemResourceMonitor(
            read_mactop=lambda **_kwargs: next(samples),
            read_gpu=lambda **_kwargs: (43.0, "fallback"),
        )
        monitor._sample_once()
        monitor._sample_once()

        self.assertEqual(monitor.max_gpu_celsius, 45.0)
        self.assertEqual(monitor.max_memory_percent, 30.0)
        self.assertEqual(monitor.max_power_watts, 5.0)
        self.assertEqual(monitor.max_cpu_percent, 10.0)
        self.assertEqual(monitor.max_gpu_percent, 6.0)
        self.assertEqual(monitor.max_cpu_celsius, 40.0)
        self.assertEqual(monitor.max_soc_celsius, 42.0)
        self.assertEqual(monitor.note, "second")


if __name__ == "__main__":
    unittest.main()
