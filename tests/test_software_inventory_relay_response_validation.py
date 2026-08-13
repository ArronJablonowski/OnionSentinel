"""Characterization for Software Inventory relay-response phase ordering."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n" / "bin" / "software_inventory_validation.py"


def load_module():
    dependency = str(MODULE_PATH.parent)
    if dependency not in sys.path:
        sys.path.insert(0, dependency)
    spec = importlib.util.spec_from_file_location(
        "software_inventory_relay_response_validation_target",
        MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Software Inventory validation")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SoftwareInventoryRelayResponseValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def value(self, *, receipt=True):
        result = {
            "ok": True,
            "contract": self.module.CONTRACT,
            "read_only": True,
            "source": "zeek_software",
            "window": {"kind": "response"},
            "returned": 1,
            "complete": False,
            "truncated": True,
            "after": {"raw": "after"},
            "records": [{"raw": "record"}],
            "query_audit": {"raw": "audit"},
        }
        if receipt:
            result["audit_receipt"] = {"raw": "receipt"}
        return result

    def test_success_preserves_exact_phase_order_arguments_and_projection(self) -> None:
        calls = []
        value = self.value()
        expected_window = {"kind": "request"}
        normalized_window = {"normalized": "window"}
        expected_request = {"normalized": "request"}
        records = [{"accounted": "record"}]
        after = {"normalized": "after"}
        query_audit = {"normalized": "audit"}
        normalized_records = [{"normalized": "record"}]

        def normalize_window(raw):
            calls.append(("window", raw))
            return normalized_window

        def build_request(*args):
            calls.append(("build", args))
            return expected_request

        def receipt(raw, **kwargs):
            calls.append(("receipt", raw, kwargs))

        def accounting(raw, page_size):
            calls.append(("accounting", raw, page_size))
            return records, False, True

        def page_cursor(raw, **kwargs):
            calls.append(("cursor", raw, kwargs))
            return after

        def audit(raw, source):
            calls.append(("audit", raw, source))
            return query_audit

        def normalize_records(raw, **kwargs):
            calls.append(("records", raw, kwargs))
            return normalized_records

        def bind(*args):
            calls.append(("binding", args))

        with (
            mock.patch.object(
                self.module,
                "_normalize_window",
                side_effect=normalize_window,
            ),
            mock.patch.object(
                self.module,
                "_validate_audit_receipt",
                side_effect=receipt,
            ),
            mock.patch.object(
                self.module,
                "_validated_result_accounting",
                side_effect=accounting,
            ),
            mock.patch.object(
                self.module,
                "_validated_page_cursor",
                side_effect=page_cursor,
            ),
            mock.patch.object(
                self.module,
                "_validated_query_audit",
                side_effect=audit,
            ),
            mock.patch.object(
                self.module,
                "_normalize_response_records",
                side_effect=normalize_records,
            ),
            mock.patch.object(
                self.module,
                "_validate_cursor_binding",
                side_effect=bind,
            ),
        ):
            result = self.module.validate_relay_response(
                value,
                expected_source="zeek_software",
                expected_window=expected_window,
                requested_page_size=37,
                previous_after={"previous": "after"},
                build_request=build_request,
            )

        expected = dict(value)
        expected.update(
            window=normalized_window,
            after=after,
            records=normalized_records,
            query_audit=query_audit,
        )
        self.assertEqual(result, expected)
        self.assertIs(result["audit_receipt"], value["audit_receipt"])
        self.assertEqual(
            calls,
            [
                ("window", value["window"]),
                ("window", expected_window),
                (
                    "build",
                    (
                        "zeek_software",
                        expected_window,
                        37,
                        {"previous": "after"},
                    ),
                ),
                (
                    "receipt",
                    value["audit_receipt"],
                    {"value": value, "expected_request": expected_request},
                ),
                ("accounting", value, 37),
                (
                    "cursor",
                    value,
                    {
                        "expected_source": "zeek_software",
                        "complete": False,
                        "truncated": True,
                        "returned": 1,
                        "requested_page_size": 37,
                    },
                ),
                ("audit", value, "zeek_software"),
                (
                    "records",
                    records,
                    {
                        "expected_source": "zeek_software",
                        "window": normalized_window,
                    },
                ),
                (
                    "binding",
                    (
                        after,
                        {"previous": "after"},
                        normalized_records,
                        "zeek_software",
                    ),
                ),
            ],
        )

    def test_absent_receipt_never_builds_request_or_validates_receipt(self) -> None:
        value = self.value(receipt=False)
        with (
            mock.patch.object(
                self.module,
                "_normalize_window",
                return_value={"normalized": "window"},
            ),
            mock.patch.object(
                self.module,
                "_validate_audit_receipt",
            ) as receipt,
            mock.patch.object(
                self.module,
                "_validated_result_accounting",
                return_value=([], True, False),
            ),
            mock.patch.object(
                self.module,
                "_validated_page_cursor",
                return_value=None,
            ),
            mock.patch.object(
                self.module,
                "_validated_query_audit",
                return_value={"normalized": "audit"},
            ),
            mock.patch.object(
                self.module,
                "_normalize_response_records",
                return_value=[],
            ),
            mock.patch.object(self.module, "_validate_cursor_binding"),
        ):
            build = mock.Mock()
            self.module.validate_relay_response(
                value,
                expected_source="zeek_software",
                expected_window={"kind": "request"},
                requested_page_size=37,
                previous_after=None,
                build_request=build,
            )
        build.assert_not_called()
        receipt.assert_not_called()

    def test_shape_contract_and_window_rejections_short_circuit_in_order(self) -> None:
        value = self.value(receipt=False)
        invalid_shape = {**value, "extra": True}
        invalid_contract = {**value, "read_only": 1}
        with mock.patch.object(self.module, "_normalize_window") as normalize:
            with self.assertRaisesRegex(ValueError, "invalid software inventory shape"):
                self.module.validate_relay_response(
                    invalid_shape,
                    expected_source="zeek_software",
                    expected_window={},
                    requested_page_size=1,
                    previous_after=None,
                    build_request=mock.Mock(),
                )
            with self.assertRaisesRegex(ValueError, "failed the software inventory contract"):
                self.module.validate_relay_response(
                    invalid_contract,
                    expected_source="zeek_software",
                    expected_window={},
                    requested_page_size=1,
                    previous_after=None,
                    build_request=mock.Mock(),
                )
        normalize.assert_not_called()

        with (
            mock.patch.object(
                self.module,
                "_normalize_window",
                side_effect=({"window": 1}, {"window": 2}),
            ),
            mock.patch.object(
                self.module,
                "_validated_result_accounting",
            ) as accounting,
        ):
            with self.assertRaisesRegex(ValueError, "window does not match"):
                self.module.validate_relay_response(
                    value,
                    expected_source="zeek_software",
                    expected_window={},
                    requested_page_size=1,
                    previous_after=None,
                    build_request=mock.Mock(),
                )
        accounting.assert_not_called()


if __name__ == "__main__":
    unittest.main()
