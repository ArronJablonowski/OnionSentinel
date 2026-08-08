#!/usr/bin/env python3
"""Direct security contracts for the Asset Store client."""
from __future__ import annotations

import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from urllib import error as urllib_error


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_asset_store_client import (  # noqa: E402
    AlertStoreRequestError,
    AssetStoreClient,
    load_asset_store_write_token,
)


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class AssetStoreCredentialTests(unittest.TestCase):
    def test_direct_token_is_bounded_without_reading_environment_file(self) -> None:
        token = "a" * 32
        loaded = load_asset_store_write_token(
            token, Path("/path/that/must/not/be/read"), owner_id=os.geteuid(),
        )
        self.assertEqual(loaded, token)
        with self.assertRaisesRegex(RuntimeError, "credential is invalid"):
            load_asset_store_write_token(
                "short", Path("/not/read"), owner_id=os.geteuid(),
            )

    def test_owner_only_environment_returns_only_the_selected_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            token = "b" * 32
            path.write_text(
                f"UNRELATED=private\nASSET_STORE_WRITE_TOKEN='{token}'\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            loaded = load_asset_store_write_token(
                "", path, owner_id=os.geteuid(),
            )
            self.assertEqual(loaded, token)

    def test_permissive_or_symlinked_environment_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / ".env"
            path.write_text(f"ASSET_STORE_WRITE_TOKEN={'c' * 32}\n")
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "not owner-controlled"):
                load_asset_store_write_token(
                    "", path, owner_id=os.geteuid(),
                )
            path.chmod(0o600)
            link = root / "linked.env"
            link.symlink_to(path)
            with self.assertRaisesRegex(RuntimeError, "not owner-controlled"):
                load_asset_store_write_token(
                    "", link, owner_id=os.geteuid(),
                )


class AssetStoreClientTests(unittest.TestCase):
    def client(self, *, urlopen, read_json) -> AssetStoreClient:
        return AssetStoreClient(
            base_url="http://127.0.0.1:8787",
            maximum_response_bytes=4096,
            token=lambda: "d" * 32,
            read_json=read_json,
            urlopen=urlopen,
        )

    def test_allowlisted_post_uses_token_and_bounded_reader(self) -> None:
        requests: list[object] = []
        reads: list[int] = []

        def open_request(request, timeout=10.0):
            requests.append((request, timeout))
            return FakeResponse()

        def read_json(_response, *, max_bytes):
            reads.append(max_bytes)
            return {"ok": True, "status": "edited"}

        result = self.client(urlopen=open_request, read_json=read_json).post(
            "/assets/update", {"asset_id": "known"}, 7.0,
        )
        request, timeout = requests[0]
        self.assertEqual(timeout, 7.0)
        self.assertEqual(request.full_url, "http://127.0.0.1:8787/assets/update")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(
            request.get_header("X-onion-sentinel-asset-token"), "d" * 32,
        )
        self.assertEqual(reads, [4096])
        self.assertEqual(result["status"], "edited")

    def test_disallowed_path_is_rejected_before_token_or_network(self) -> None:
        calls: list[str] = []
        client = AssetStoreClient(
            base_url="http://127.0.0.1:8787",
            maximum_response_bytes=4096,
            token=lambda: calls.append("token") or "d" * 32,
            read_json=lambda *_args, **_kwargs: {},
            urlopen=lambda *_args, **_kwargs: calls.append("network"),
        )
        with self.assertRaisesRegex(ValueError, "not allowlisted"):
            client.post("/assets/arbitrary", {})
        self.assertEqual(calls, [])

    def test_http_status_and_bounded_error_detail_are_preserved(self) -> None:
        error = urllib_error.HTTPError(
            "http://127.0.0.1:8787/assets/update",
            409,
            "Conflict",
            {},
            io.BytesIO(b"{}"),
        )
        self.addCleanup(error.close)

        def rejected(*_args, **_kwargs):
            raise error

        client = self.client(
            urlopen=rejected,
            read_json=lambda _response, *, max_bytes: {
                "reason": "version conflict",
            },
        )
        with self.assertRaises(AlertStoreRequestError) as raised:
            client.post("/assets/update", {})
        self.assertEqual(raised.exception.status_code, 409)
        self.assertEqual(str(raised.exception), "version conflict")

    def test_invalid_success_payload_is_fail_closed(self) -> None:
        client = self.client(
            urlopen=lambda *_args, **_kwargs: FakeResponse(),
            read_json=lambda *_args, **_kwargs: {"ok": False},
        )
        with self.assertRaises(AlertStoreRequestError) as raised:
            client.post("/assets/update", {})
        self.assertEqual(raised.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
