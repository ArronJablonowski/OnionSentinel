"""Characterization for pure Software Inventory endpoint-cache admission."""
from __future__ import annotations

import datetime as dt
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
        "software_inventory_endpoint_cache_validation_target",
        MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Software Inventory validation")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SoftwareInventoryEndpointCacheValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    @staticmethod
    def value(*, records=None, targets=None, **changes):
        result = {
            "schema": "onion-sentinel-endpoint-software-cache-v1",
            "version": 1,
            "updated_at": "2026-08-12T11:00:00.000Z",
            "complete": True,
            "targets": [] if targets is None else targets,
            "records": [] if records is None else records,
        }
        result.update(changes)
        return result

    @staticmethod
    def target(asset_ref: str = "a" * 24, **changes):
        result = {
            "asset_ref": asset_ref,
            "status": "ok",
            "records": 1,
            "observed_at": "2026-08-12T11:00:00.000Z",
        }
        result.update(changes)
        return result

    def test_valid_projection_preserves_dependency_order_and_arguments(self) -> None:
        calls = []
        updated = dt.datetime(2026, 8, 12, 11, tzinfo=dt.timezone.utc)
        records = [{"raw": 1}, {"raw": 2}]
        normalized = [
            {"asset_ref": "a" * 24, "normalized": 1},
            {"asset_ref": "b" * 24, "normalized": 2},
        ]
        value = self.value(
            records=records,
            targets=[self.target("a" * 24), self.target("b" * 24)],
        )

        def parse(value):
            calls.append(("parse", value))
            return updated

        def assets(value):
            calls.append(("targets", value))
            return {"a" * 24, "b" * 24}

        def normalize(value, **kwargs):
            calls.append(("normalize", value, kwargs))
            return normalized[len([call for call in calls if call[0] == "normalize"]) - 1]

        def format_value(value):
            calls.append(("format", value))
            return "formatted-updated-at"

        with (
            mock.patch.object(self.module, "parse_timestamp", side_effect=parse),
            mock.patch.object(self.module, "_target_asset_refs", side_effect=assets),
            mock.patch.object(self.module, "_normalize_record", side_effect=normalize),
            mock.patch.object(self.module, "format_timestamp", side_effect=format_value),
        ):
            result = self.module.validated_endpoint_cache(
                value,
                dt.datetime(2026, 8, 12, 12, tzinfo=dt.timezone.utc),
                dt.timedelta(hours=36),
            )

        self.assertEqual(
            result,
            {
                "updated_at": "formatted-updated-at",
                "targets": 2,
                "records": normalized,
            },
        )
        self.assertEqual(
            calls,
            [
                ("parse", "2026-08-12T11:00:00.000Z"),
                ("targets", value["targets"]),
                ("normalize", records[0], {"expected_source": "osquery_apps"}),
                ("normalize", records[1], {"expected_source": "osquery_apps"}),
                ("format", updated),
            ],
        )

    def test_freshness_boundaries_are_inclusive_and_short_circuit(self) -> None:
        now = dt.datetime(2026, 8, 12, 12, tzinfo=dt.timezone.utc)
        maximum_age = dt.timedelta(hours=36)
        accepted = (
            now + dt.timedelta(minutes=5),
            now - maximum_age,
        )
        stale = (
            now + dt.timedelta(minutes=5, microseconds=1),
            now - maximum_age - dt.timedelta(microseconds=1),
        )
        for updated in accepted:
            value = self.value(
                updated_at=updated.isoformat(),
                targets=[self.target()],
            )
            with mock.patch.object(self.module, "_normalize_record"):
                result = self.module.validated_endpoint_cache(
                    value,
                    now,
                    maximum_age,
                )
            self.assertEqual(result["targets"], 1)
        for updated in stale:
            value = self.value(
                updated_at=updated.isoformat(),
                targets=[self.target()],
            )
            with (
                mock.patch.object(self.module, "_target_asset_refs") as targets,
                mock.patch.object(self.module, "_normalize_record") as normalize,
            ):
                self.assertIsNone(
                    self.module.validated_endpoint_cache(
                        value,
                        now,
                        maximum_age,
                    )
                )
            targets.assert_not_called()
            normalize.assert_not_called()

    def test_envelope_and_record_bounds_preserve_rejection_precedence(self) -> None:
        now = dt.datetime(2026, 8, 12, 12, tzinfo=dt.timezone.utc)
        valid = self.value(targets=[self.target()])
        cases = (
            None,
            {**valid, "extra": True},
            {**valid, "schema": "invalid"},
            {**valid, "version": 2},
            {**valid, "complete": 1},
        )
        for value in cases:
            with self.subTest(value=value), mock.patch.object(
                self.module,
                "parse_timestamp",
            ) as parse:
                with self.assertRaisesRegex(
                    ValueError,
                    "^endpoint software inventory cache is invalid$",
                ):
                    self.module.validated_endpoint_cache(
                        value,
                        now,
                        dt.timedelta(hours=36),
                    )
            parse.assert_not_called()

        boolean_version = {**valid, "version": True}
        self.assertEqual(
            self.module.validated_endpoint_cache(
                boolean_version,
                now,
                dt.timedelta(hours=36),
            )["targets"],
            1,
        )

        with (
            mock.patch.object(self.module, "MAX_TOTAL_RECORDS", 1),
            mock.patch.object(self.module, "_target_asset_refs") as targets,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "^endpoint software inventory cache is out of bounds$",
            ):
                self.module.validated_endpoint_cache(
                    self.value(
                        records=[{"raw": 1}, {"raw": 2}],
                        targets=[self.target()],
                    ),
                    now,
                    dt.timedelta(hours=36),
                )
        targets.assert_not_called()

    def test_target_admission_and_deduplication_are_exact(self) -> None:
        self.assertEqual(
            self.module._target_asset_refs(
                [self.target(), self.target()]
            ),
            {"a" * 24},
        )
        cases = (
            [],
            [self.target()] * 65,
            [None],
            [{**self.target(), "extra": True}],
            [self.target(status="failed")],
            [self.target("invalid")],
        )
        messages = (
            "out of bounds",
            "out of bounds",
            "target status is invalid",
            "target status is invalid",
            "target status is invalid",
            "target status is invalid",
        )
        for targets, message in zip(cases, messages):
            with self.subTest(message=message), self.assertRaisesRegex(
                ValueError,
                message,
            ):
                self.module._target_asset_refs(targets)

    def test_uncovered_normalized_record_retains_exact_failure(self) -> None:
        now = dt.datetime(2026, 8, 12, 12, tzinfo=dt.timezone.utc)
        with mock.patch.object(
            self.module,
            "_normalize_record",
            return_value={"asset_ref": "b" * 24},
        ):
            with self.assertRaisesRegex(
                ValueError,
                "^endpoint software inventory record has no target coverage$",
            ):
                self.module.validated_endpoint_cache(
                    self.value(
                        records=[{"raw": 1}],
                        targets=[self.target("a" * 24)],
                    ),
                    now,
                    dt.timedelta(hours=36),
                )


if __name__ == "__main__":
    unittest.main()
