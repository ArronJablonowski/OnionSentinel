from __future__ import annotations

from alert_store_pcap_retry_fixtures import (
    ALERT_STORE,
    ALERT_STORE_DIR,
    CONTROLLED_ROUTE_FIELDS,
    DEPLOYED_RELEASE,
    Path,
    REPO_ROOT,
    SCORING_RULES,
    available_port,
    closing,
    io,
    json,
    mock,
    os,
    request_json,
    socket,
    sqlite3,
    subprocess,
    tempfile,
    time,
    unittest,
    urllib,
)

class RequestJsonOwnershipTestHttpErrorResponseIsClosedAfterReadCases:
    def test_http_error_response_is_closed_after_read(self) -> None:
        error = urllib.error.HTTPError(
            "http://127.0.0.1:9/pcap/retry",
            409,
            "Conflict",
            {},
            io.BytesIO(b'{"error":"synthetic"}'),
        )
        with mock.patch.object(
            urllib.request,
            "urlopen",
            side_effect=error,
        ):
            self.assertEqual(
                request_json("http://127.0.0.1:9/pcap/retry"),
                (409, {"error": "synthetic"}),
            )

        self.assertTrue(error.fp.closed)
