from __future__ import annotations

from dhcp_asset_discovery_fixtures import (
    BROKER,
    BUILDER,
    COLLECTOR,
    INSTALLER,
    PORTAL,
    PROMOTER,
    Path,
    QUERY_CLIENT,
    ROOT,
    SimpleNamespace,
    WRAPPER,
    contextlib,
    dt,
    hashlib,
    importlib,
    inspect,
    io,
    json,
    load_module,
    mock,
    shutil,
    stat,
    subprocess,
    sys,
    tempfile,
    unittest,
)

class SecurityOnionQueryClientTestsManualQueryRunsWhileScheduledCollectionIsDisabledCases:
    def test_manual_query_runs_while_scheduled_collection_is_disabled(self) -> None:
        fake_client = mock.Mock()
        now = dt.datetime(2026, 7, 29, 21, tzinfo=dt.timezone.utc)
        fake_client.utc_now.return_value = now
        fake_client.load_config.return_value = {
            "enabled": False,
            "host": "10.88.8.8",
        }
        fake_client.query_dhcp.return_value = {
            "ok": True,
            "contract": "onion-sentinel-dhcp-asset-discovery-v1",
            "generated_at": "2026-07-29T21:00:00.000Z",
            "status": "ok",
            "window": {
                "start": "2026-07-29T20:45:00.000Z",
                "end": "2026-07-29T21:00:00.000Z",
            },
            "hits_total": 2,
            "returned": 1,
            "truncated": False,
            "query_audit": {
                "index": "logs-zeek-so",
                "dataset": "zeek.dhcp",
                "query_digest": "a" * 64,
            },
            "observations": [{
                "ip_address": "10.66.6.210",
            }],
        }
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "query.jsonl"
            stdout = io.StringIO()
            with mock.patch.object(
                self.query_client,
                "load_dhcp_client",
                return_value=fake_client,
            ), mock.patch.object(
                sys,
                "argv",
                [
                    "query-security-onion",
                    "--log",
                    str(log),
                    "dhcp",
                    "--minutes",
                    "15",
                    "--size",
                    "25",
                    "--summary",
                ],
            ), contextlib.redirect_stdout(stdout):
                self.assertEqual(self.query_client.main(), 0)
            fake_client.query_dhcp.assert_called_once_with(
                fake_client.load_config.return_value,
                now - dt.timedelta(minutes=15),
                now,
                25,
            )
            output = json.loads(stdout.getvalue())
            self.assertEqual(output["hits_total"], 2)
            self.assertNotIn("observations", output)
            record = json.loads(log.read_text(encoding="utf-8"))
            self.assertTrue(record["timestamp"].endswith("Z"))
            self.assertEqual(record["event"], "security_onion_query.completed")
            self.assertNotIn("10.66.6.210", json.dumps(record))


