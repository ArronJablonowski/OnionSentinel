#!/usr/bin/env python3
"""Direct contracts for CTI workspace read/write orchestration."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_cti_program_service import (  # noqa: E402
    CtiProgramCallbacks,
    prepare_cti_program_write,
    read_cti_program,
)
from portal_request_routes import classify_post_route  # noqa: E402


class ProgramError(ValueError):
    pass


class ProgramConflict(ProgramError):
    pass


def route(path: str):
    return classify_post_route(
        path,
        cti_program_path="/api/cyber-threat-intel/program",
        prompt_paths=frozenset(),
    )


def callbacks(**overrides) -> CtiProgramCallbacks:
    values = {
        "load": lambda: {"revision": 0},
        "save": lambda payload: {"revision": payload["expected_revision"] + 1},
        "public_response": lambda program: {"ok": True, "program": program},
        "audit": lambda _program: None,
        "conflict_error": ProgramConflict,
        "program_error": ProgramError,
    }
    values.update(overrides)
    return CtiProgramCallbacks(**values)


class CtiProgramWriteServiceTests(unittest.TestCase):
    def test_non_cti_route_is_declined_without_authorization(self) -> None:
        auth_calls: list[bool] = []
        result = prepare_cti_program_write(
            route("/api/assets/update"),
            "{}",
            same_origin_authorized=False,
            admin_authenticated=lambda: auth_calls.append(True) or False,
            callbacks=callbacks(save=lambda _payload: self.fail("must not save")),
        )
        self.assertIsNone(result)
        self.assertEqual(auth_calls, [])

    def test_same_origin_failure_precedes_admin_check_and_save(self) -> None:
        auth_calls: list[bool] = []
        result = prepare_cti_program_write(
            route("/api/cyber-threat-intel/program"),
            "{}",
            same_origin_authorized=False,
            admin_authenticated=lambda: auth_calls.append(True) or False,
            callbacks=callbacks(save=lambda _payload: self.fail("must not save")),
        )
        self.assertEqual(result.status, 403)
        self.assertIn("same-origin", result.payload["error"])
        self.assertEqual(auth_calls, [])

    def test_admin_failure_is_explicit_and_does_not_save(self) -> None:
        result = prepare_cti_program_write(
            route("/api/cyber-threat-intel/program"),
            "{}",
            same_origin_authorized=True,
            admin_authenticated=lambda: False,
            callbacks=callbacks(save=lambda _payload: self.fail("must not save")),
        )
        self.assertEqual(result.status, 403)
        self.assertTrue(result.payload["authentication_required"])

    def test_malformed_json_is_delegated_to_workspace_validation(self) -> None:
        received: list[object] = []

        def reject(payload):
            received.append(payload)
            raise ProgramError("Request body must be a JSON object.")

        result = prepare_cti_program_write(
            route("/api/cyber-threat-intel/program"),
            "{not-json",
            same_origin_authorized=True,
            admin_authenticated=lambda: True,
            callbacks=callbacks(save=reject),
        )
        self.assertEqual(result.status, 400)
        self.assertEqual(received, [None])

    def test_conflict_validation_and_storage_errors_keep_distinct_statuses(self) -> None:
        scenarios = (
            (ProgramConflict("changed"), 409, "changed"),
            (ProgramError("invalid"), 400, "invalid"),
            (OSError("private detail"), 500, "Could not persist the CTI workspace."),
        )
        for error, expected_status, expected_message in scenarios:
            with self.subTest(error=type(error).__name__):
                result = prepare_cti_program_write(
                    route("/api/cyber-threat-intel/program"),
                    '{"expected_revision":0}',
                    same_origin_authorized=True,
                    admin_authenticated=lambda: True,
                    callbacks=callbacks(
                        save=lambda _payload, error=error: (
                            _ for _ in ()
                        ).throw(error),
                    ),
                )
                self.assertEqual(result.status, expected_status)
                self.assertEqual(result.payload["error"], expected_message)

    def test_success_audits_saved_program_before_public_projection(self) -> None:
        events: list[tuple[str, dict]] = []
        saved = {"revision": 2}

        def audit(program):
            events.append(("audit", program))

        def public(program):
            events.append(("public", program))
            return {"ok": True, "program": program}

        result = prepare_cti_program_write(
            route("/api/cyber-threat-intel/program"),
            '{"expected_revision":1}',
            same_origin_authorized=True,
            admin_authenticated=lambda: True,
            callbacks=callbacks(
                save=lambda _payload: saved,
                audit=audit,
                public_response=public,
            ),
        )
        self.assertEqual(result.status, 200)
        self.assertEqual(events, [("audit", saved), ("public", saved)])


class CtiProgramReadServiceTests(unittest.TestCase):
    def test_read_projects_public_workspace(self) -> None:
        result = read_cti_program(callbacks(load=lambda: {"revision": 3}))
        self.assertEqual(result.status, 200)
        self.assertEqual(result.payload["program"]["revision"], 3)

    def test_read_validation_and_io_failures_are_bounded(self) -> None:
        invalid = read_cti_program(callbacks(
            load=lambda: (_ for _ in ()).throw(ProgramError("invalid workspace")),
        ))
        unavailable = read_cti_program(callbacks(
            load=lambda: (_ for _ in ()).throw(OSError("private path")),
        ))
        self.assertEqual(invalid.payload["error"], "invalid workspace")
        self.assertEqual(
            unavailable.payload["error"], "Could not read the CTI workspace.",
        )


if __name__ == "__main__":
    unittest.main()
