from __future__ import annotations

import datetime as dt
import hashlib
import inspect
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

import software_inventory_transport as transport
import software_inventory_validation as validation_owner


class SoftwareInventoryTransportArchitectureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.now = dt.datetime(2026, 8, 12, 12, 0, tzinfo=dt.timezone.utc)
        self.window = {
            "start": "2026-08-11T12:00:00.000Z",
            "end": "2026-08-12T12:00:00.000Z",
        }

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @staticmethod
    def host_ref(hostname: str) -> str:
        normalized = hostname.strip().rstrip(".").lower()
        return hashlib.sha256(
            ("host\0" + normalized).encode("utf-8")
        ).hexdigest()[:24]

    def record(
        self,
        source: str,
        *,
        product: str = "Example",
        version: str = "1",
        asset: str | None = None,
    ) -> dict:
        policy = transport.SOURCE_POLICY[source]
        return {
            "evidence_id": "e" * 24,
            "source": source,
            "source_dataset": policy["dataset"],
            "tier": policy["tier"],
            "confidence": policy["confidence"],
            "asset_ref_type": policy["asset_ref_type"],
            "asset_ref": asset or (
                self.host_ref("studio.example")
                if source == "osquery_apps"
                else "10.66.6.20"
            ),
            "platform": policy["platform"],
            "operating_system_type": "",
            "operating_system_version": "",
            "operating_system_source": "",
            "operating_system_confidence": "",
            "product": product,
            "version": version,
            "category": "application" if source == "osquery_apps" else "software",
            "first_seen": self.window["start"],
            "last_seen": "2026-08-12T11:00:00.000Z",
            "observation_count": 1,
        }

    def response(
        self,
        source: str = "zeek_software",
        *,
        records: list[dict] | None = None,
        complete: bool = True,
        after: dict | None = None,
    ) -> dict:
        values = [] if records is None else records
        policy = transport.SOURCE_POLICY[source]
        return {
            "ok": True,
            "contract": transport.CONTRACT,
            "read_only": True,
            "source": source,
            "window": dict(self.window),
            "returned": len(values),
            "complete": complete,
            "truncated": not complete,
            "after": after,
            "records": values,
            "query_audit": {
                "index": policy["index"],
                "dataset": policy["dataset"],
                "query_digest": "d" * 64,
            },
        }

    def with_receipt(
        self,
        response: dict,
        *,
        page_size: int,
        previous_after: dict | None = None,
    ) -> dict:
        request = transport.build_request(
            response["source"],
            self.window,
            page_size,
            previous_after,
        )
        value = json.loads(json.dumps(response))
        value["audit_receipt"] = {
            "receipt_contract": transport.TRANSPORT_RECEIPT_CONTRACT,
            "correlation_id": "c" * 32,
            "request_digest": hashlib.sha256(
                json.dumps(
                    request,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest(),
            "response_payload_digest": hashlib.sha256(
                json.dumps(
                    response,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest(),
            "elastic_search_count": 0,
            "osquery_query_count": 0,
            "helper_invocation_count": 1,
            "read_only": True,
            "terminal_status": "complete" if response["complete"] else "partial",
        }
        return value

    def validate(
        self,
        value: object,
        *,
        source: str = "zeek_software",
        page_size: int = 2,
        previous_after: dict | None = None,
    ) -> dict:
        return transport.validate_response(
            value,
            expected_source=source,
            expected_window=self.window,
            requested_page_size=page_size,
            previous_after=previous_after,
        )

    def test_public_signatures_and_valid_terminal_response_are_exact(self) -> None:
        self.assertEqual(
            str(inspect.signature(transport.load_endpoint_cache)),
            "(path: 'Path', now: 'dt.datetime', *, maximum_age: 'dt.timedelta' = datetime.timedelta(days=1, seconds=43200)) -> 'Optional[Dict[str, Any]]'",
        )
        self.assertEqual(
            str(inspect.signature(transport.validate_response)),
            "(value: 'object', *, expected_source: 'str', expected_window: 'Dict[str, str]', requested_page_size: 'int', previous_after: 'Optional[Dict[str, Any]]') -> 'Dict[str, Any]'",
        )
        response = self.response(records=[self.record("zeek_software")])
        normalized = self.validate(response)
        self.assertEqual(normalized["window"], self.window)
        self.assertIsNone(normalized["after"])
        self.assertEqual(normalized["records"], response["records"])
        self.assertEqual(normalized["query_audit"], response["query_audit"])

        received = self.with_receipt(response, page_size=2)
        self.assertEqual(self.validate(received), received)
        with self.assertRaisesRegex(ValueError, "software inventory cursor"):
            self.validate(response, previous_after={"invalid": "cursor"})

    def test_validation_owner_is_inward_and_facades_are_bounded(self) -> None:
        source = inspect.getsource(validation_owner)
        self.assertNotIn("import software_inventory_transport", source)
        self.assertNotIn("from software_inventory_transport", source)
        self.assertNotIn("urlopen", source)
        self.assertNotIn("run_bounded_command", source)
        self.assertLessEqual(
            len(inspect.getsource(transport.validate_response).splitlines()),
            18,
        )
        self.assertLessEqual(
            len(inspect.getsource(transport.load_endpoint_cache).splitlines()),
            14,
        )

    def test_response_rejection_precedence_and_messages_are_exact(self) -> None:
        base = self.response(records=[self.record("zeek_software")])
        cases = (
            (None, "invalid software inventory shape"),
            ({**base, "extra": True}, "invalid software inventory shape"),
            ({**base, "ok": False}, "failed the software inventory contract"),
            ({**base, "window": {
                "start": "2026-08-10T12:00:00.000Z",
                "end": "2026-08-11T12:00:00.000Z",
            }}, "window does not match"),
            ({**base, "records": "invalid"}, "result accounting is invalid"),
            ({**base, "complete": "yes"}, "pagination state is invalid"),
            ({**base, "truncated": True}, "terminal software inventory page is inconsistent"),
            ({**base, "query_audit": {}}, "fixed-query audit is invalid"),
        )
        for value, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    self.validate(value)

        invalid_receipt = self.with_receipt(base, page_size=2)
        invalid_receipt["audit_receipt"]["helper_invocation_count"] = 0
        invalid_receipt["records"] = "also-invalid"
        with self.assertRaisesRegex(ValueError, "audit receipt failed validation"):
            self.validate(invalid_receipt)

    def test_nonterminal_cursor_binding_and_monotonicity_are_exact(self) -> None:
        record = self.record(
            "osquery_apps",
            product="Example",
            version="5",
        )
        after = {
            "asset": "Studio.Example.",
            "product": "Example",
            "version": "5",
        }
        response = self.response(
            "osquery_apps",
            records=[record],
            complete=False,
            after=after,
        )
        normalized = self.validate(response, source="osquery_apps", page_size=1)
        self.assertEqual(normalized["after"], after)
        with self.assertRaisesRegex(ValueError, "cursor did not advance"):
            self.validate(
                response,
                source="osquery_apps",
                page_size=1,
                previous_after=after,
            )
        mismatched = json.loads(json.dumps(response))
        mismatched["after"]["asset"] = "different.example"
        with self.assertRaisesRegex(ValueError, "last public record"):
            self.validate(mismatched, source="osquery_apps", page_size=1)

    def write_cache(self, value: dict, *, mode: int = 0o600) -> Path:
        path = self.root / "private" / "endpoint-cache.json"
        path.parent.mkdir(mode=0o700)
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(mode)
        return path

    def cache_value(self) -> dict:
        record = self.record("osquery_apps")
        return {
            "schema": "onion-sentinel-endpoint-software-cache-v1",
            "version": 1,
            "updated_at": "2026-08-12T11:00:00.000Z",
            "complete": True,
            "targets": [
                {
                    "asset_ref": record["asset_ref"],
                    "status": "ok",
                    "records": 1,
                    "observed_at": "2026-08-12T11:00:00.000Z",
                }
            ],
            "records": [record],
        }

    def test_endpoint_cache_missing_fresh_stale_and_validation_are_exact(self) -> None:
        missing = self.root / "missing.json"
        self.assertIsNone(transport.load_endpoint_cache(missing, self.now))

        value = self.cache_value()
        path = self.write_cache(value)
        loaded = transport.load_endpoint_cache(path, self.now)
        self.assertEqual(
            loaded,
            {
                "updated_at": "2026-08-12T11:00:00.000Z",
                "targets": 1,
                "records": value["records"],
            },
        )
        self.assertIsNone(
            transport.load_endpoint_cache(
                path,
                self.now + dt.timedelta(hours=37),
            )
        )
        self.assertIsNone(
            transport.load_endpoint_cache(
                path,
                dt.datetime(2026, 8, 12, 10, 54, tzinfo=dt.timezone.utc),
            )
        )

        bad_mode = self.root / "private" / "bad-mode.json"
        bad_mode.write_text(json.dumps(value), encoding="utf-8")
        bad_mode.chmod(0o640)
        with self.assertRaisesRegex(ValueError, "must have mode 0600"):
            transport.load_endpoint_cache(bad_mode, self.now)

        uncovered = self.cache_value()
        uncovered["records"][0]["asset_ref"] = "f" * 24
        uncovered_path = self.root / "private" / "uncovered.json"
        uncovered_path.write_text(json.dumps(uncovered), encoding="utf-8")
        uncovered_path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "no target coverage"):
            transport.load_endpoint_cache(uncovered_path, self.now)


if __name__ == "__main__":
    unittest.main()
