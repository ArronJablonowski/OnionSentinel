from __future__ import annotations

import unittest

from onion_sentinel import telemetry


class PipelineTelemetryTests(unittest.TestCase):
    def ports(self, *, build_error: Exception | None = None):
        state = {"failed": [], "stopped": 0, "appended": [], "current": [], "cleaned": 0, "warnings": []}

        def build():
            if build_error:
                raise build_error
            return {"status": "done"}

        def stop():
            state["stopped"] += 1

        def clean():
            state["cleaned"] += 1

        return telemetry.FinalizationPorts(
            fail_harness=lambda reason: state["failed"].append(reason),
            stop_monitor=stop,
            build_record=build,
            append_record=lambda record: state["appended"].append(record),
            write_current=lambda record: state["current"].append(record),
            cleanup_active=clean,
            warn=lambda message: state["warnings"].append(message),
        ), state

    def test_failure_stops_monitor_and_publishes_terminal_record(self):
        ports, state = self.ports()
        telemetry.finalize(
            telemetry.FinalizationInputs("failure", "provider failed", True, True, object()),
            ports,
        )
        self.assertEqual(state["failed"], ["provider failed"])
        self.assertEqual(state["stopped"], 1)
        self.assertEqual(state["appended"], [{"status": "done"}])
        self.assertEqual(state["current"], [{"status": "done"}])
        self.assertEqual(state["cleaned"], 1)

    def test_success_does_not_fail_harness(self):
        ports, state = self.ports()
        telemetry.finalize(
            telemetry.FinalizationInputs("success", "", False, False, object()),
            ports,
        )
        self.assertEqual(state["failed"], [])
        self.assertEqual(state["appended"], [])
        self.assertEqual(state["cleaned"], 1)

    def test_telemetry_failure_warns_and_still_cleans_active_record(self):
        ports, state = self.ports(build_error=RuntimeError("disk full"))
        telemetry.finalize(
            telemetry.FinalizationInputs("failure", "", True, False), ports
        )
        self.assertIn("RuntimeError", state["warnings"][0])
        self.assertEqual(state["cleaned"], 1)


if __name__ == "__main__":
    unittest.main()
