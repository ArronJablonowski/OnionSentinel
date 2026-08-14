#!/usr/bin/env python3
"""PCAP broker transport and compatibility exports for bounded streaming."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sys
import threading
from urllib import request

from relay_core import *  # noqa: F401,F403
from relay_pcap_capture_policy import (
    capture_protection_decision,
    require_capture_safe,
    security_onion_storage_status,
)
from relay_pcap_spool_policy import *  # noqa: F401,F403
from relay_pcap_streaming import (
    stream_chunk_idle_timeout,
    stream_one_security_onion_chunk,
    streamed_spool_artifact,
    wait_for_stream_progress,
)


def mac_transfer_config(config: dict) -> dict:
    broker = config.get("pcap_broker", {})
    transfer = broker.get("mac_transfer") if isinstance(broker.get("mac_transfer"), dict) else {}
    return transfer


def broker_path(config: dict, name: str, default_path: str) -> str:
    paths = config.get("pcap_broker", {}).get("paths", {})
    path = paths.get(name, default_path) if isinstance(paths, dict) else default_path
    return "/" + str(path or default_path).lstrip("/")


def broker_headers(config: dict) -> dict:
    token = config.get("pcap_broker", {}).get("token", "")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "so-alert-relay-dev/0.1",
    }
    if token:
        headers["X-Relay-Token"] = token
    return headers


def broker_request(config: dict, method: str, path: str, payload_data: dict | None = None) -> dict:
    broker = config.get("pcap_broker", {})
    base_url = str(broker.get("url") or "").rstrip("/")
    if not base_url:
        raise RuntimeError("pcap_broker.url is empty")
    timeout = broker.get("timeout_seconds", 20)
    data = None if payload_data is None else json.dumps(payload_data, sort_keys=True).encode("utf-8")
    req = request.Request(
        f"{base_url}{path}",
        data=data,
        headers=broker_headers(config),
        method=method,
    )
    try:
        with request.urlopen(req, timeout=timeout) as response:
            body = read_bounded_http_body(
                response,
                webhook_int(broker, "response_max_bytes", 1024 * 1024),
            ).decode("utf-8")
    except HTTPError as exc:
        raise RuntimeError(f"PCAP broker returned HTTP {exc.code}: {exc.reason}") from exc
    except URLError as exc:
        raise RuntimeError(f"PCAP broker request failed: {exc.reason}") from exc
    try:
        parsed = json.loads(body or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"PCAP broker returned invalid JSON: {exc}") from exc
    if not parsed.get("ok"):
        raise RuntimeError(parsed.get("reason") or parsed.get("error") or "PCAP broker rejected request")
    return parsed


class PcapProgressReporter:
    """Renew a PCAP claim while a long export or transfer is demonstrably active.

    Progress reporting is advisory: an unavailable health callback must never
    interrupt resumable evidence transfer. The broker's transfer timeout still
    bounds a process that is alive but no longer useful.
    """

    def __init__(self, config: dict, request_id: str):
        self.config = config
        self.request_id = safe_transfer_id(request_id)
        broker = config.get("pcap_broker", {})
        self.interval = max(10.0, float(broker.get("progress_interval_seconds", 30) or 30))
        self.stage = "claimed"
        self.total_bytes = 0
        self._probe = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def update(self, stage: str, total_bytes: int = 0, probe=None) -> None:
        self.stage = stage
        self.total_bytes = max(0, int(total_bytes or 0))
        self._probe = probe
        self.report()

    def report(self) -> None:
        transferred = 0
        try:
            if self._probe is not None:
                transferred = max(0, int(self._probe() or 0))
            broker_request(
                self.config,
                "POST",
                broker_path(self.config, "progress", "/pcap/progress"),
                {
                    "request_id": self.request_id,
                    "stage": self.stage,
                    "transferred_bytes": transferred,
                    "total_bytes": self.total_bytes,
                },
            )
        except Exception as exc:
            print(
                json.dumps(
                    {"event": "pcap_progress_report_failed", "request_id": self.request_id, "error": str(exc)[:300]},
                    sort_keys=True,
                ),
                file=sys.stderr,
            )

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self.report()

    def __enter__(self):
        self.report()
        self._thread = threading.Thread(target=self._run, name=f"pcap-progress-{self.request_id}", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=min(5.0, self.interval))


def upload_pcap_artifact(
    config: dict,
    pcap_request: dict,
    export_result: dict,
    progress: PcapProgressReporter | None = None,
) -> dict | None:
    broker = config.get("pcap_broker", {})
    upload_mode = str(broker.get("artifact_upload_mode") or "streamed_chunks").strip().lower()
    if upload_mode in {"streamed_chunks", "streaming", "relay_stream"}:
        return upload_pcap_artifact_via_rsync(config, pcap_request, export_result, progress)
    raise RuntimeError(
        f"unsupported PCAP artifact_upload_mode {upload_mode!r}; "
        "Security Onion PCAP transfer must use read-only streamed_chunks"
    )


def completed_artifact_path(export_result: dict, upload_result: dict | None) -> str | None:
    """Prefer Mac-side artifact metadata when the upload path provides it."""
    if upload_result:
        for key in ("path", "artifact_file"):
            value = upload_result.get(key)
            if value:
                return str(value)
    value = export_result.get("artifact_path")
    return str(value) if value else None


def streamed_chunk_mode(config: dict) -> bool:
    mode = str(config.get("pcap_broker", {}).get("artifact_upload_mode") or "streamed_chunks").strip().lower()
    if mode not in {"streamed_chunks", "streaming", "relay_stream"}:
        raise RuntimeError(
            "Security Onion PCAP transfer must use read-only streamed_chunks; "
            "Security Onion staging modes have been removed"
        )
    return True


def transfer_timeout(config: dict, artifact_size: int) -> int:
    transfer = mac_transfer_config(config)
    floor = max(300, int(transfer.get("rsync_timeout_seconds") or 1800))
    minimum_bps = max(256 * 1024, int(transfer.get("minimum_bytes_per_second", 2 * 1024 * 1024) or 1))
    # The relay-to-Mac leg crosses the monitored LAN. Its bandwidth ceiling is
    # deliberately part of timeout sizing so a safe low-rate transfer is not
    # mistaken for a stalled job merely because the artifact is large.
    maximum_bps = rsync_max_bytes_per_second(config)
    estimate_bps = min(minimum_bps, maximum_bps)
    estimate = int(artifact_size / estimate_bps) + 600
    return min(12 * 3600, max(floor, estimate))


def rsync_max_bytes_per_second(config: dict) -> int:
    """Return the enforced relay-to-Mac ceiling for monitored LAN traffic."""
    transfer = mac_transfer_config(config)
    configured = int(transfer.get("max_bytes_per_second", 4 * 1024 * 1024) or 1)
    return max(1024 * 1024, min(8 * 1024 * 1024, configured))
