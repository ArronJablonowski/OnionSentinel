#!/usr/bin/env python3
"""Restricted HTTPS requester for AC Hunter.

This program is invoked only by a source-restricted forced SSH key.  It accepts
the shared named-operation contract, connects to one configured AC Hunter
address over pinned TLS, and returns a bounded JSON envelope.  It never logs,
persists, or places Cookie, Authorization, credentials, or response content in
arguments, environment variables, configuration, diagnostics, or state.
"""
from __future__ import annotations

import fcntl
import hashlib
import http.client
import json
import os
import socket
import ssl
import stat
import sys
import time
from pathlib import Path
from typing import Any

from ac_hunter_contract import (
    CONTRACT,
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    AcHunterContractError,
    UpstreamRequest,
    compile_request,
)


DEFAULT_CONFIG = Path("/etc/so-alert-relay/ac-hunter.json")
DEFAULT_LOCK = Path("/opt/so-alert-relay/state/ac-hunter.lock")
MAX_CONFIG_BYTES = 64 * 1024
MAX_ERROR_BYTES = 512
MAX_SET_COOKIES = 8
MAX_LOCATION_BYTES = 2048
CONFIG_SCHEMA = "onion-sentinel-ac-hunter-relay-config-v1"


class BrokerError(RuntimeError):
    """A sanitized broker failure safe to return to the Mac."""


def _emit(
    *,
    request_id: str,
    ok: bool,
    status: int,
    content_type: str = "",
    headers: dict[str, object] | None = None,
    body: object = None,
    duration_ms: int = 0,
    error: str = "",
    exit_code: int = 0,
) -> int:
    safe_error = " ".join(str(error or "").split())
    if len(safe_error.encode("utf-8")) > MAX_ERROR_BYTES:
        safe_error = "AC Hunter relay request failed"
    payload = {
        "contract": CONTRACT,
        "request_id": request_id,
        "ok": bool(ok),
        "status": int(status),
        "content_type": str(content_type or "")[:256],
        "headers": headers or {"location": "", "set_cookie": []},
        "body": body,
        "duration_ms": max(0, min(300_000, int(duration_ms))),
        "error": safe_error,
    }
    sys.stdout.write(
        json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n"
    )
    return exit_code


def _secure_regular_file(
    path: Path,
    *,
    maximum_bytes: int,
    owner_uid: int = 0,
) -> os.stat_result:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or stat.S_IMODE(metadata.st_mode) & 0o027
        or metadata.st_size <= 0
        or metadata.st_size > maximum_bytes
    ):
        raise BrokerError("AC Hunter relay trust file failed validation")
    return metadata


def _read_config_snapshot(path: Path) -> object:
    before = _secure_regular_file(path, maximum_bytes=MAX_CONFIG_BYTES)
    with path.open("rb") as handle:
        after = os.fstat(handle.fileno())
        if (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_mode,
            before.st_size,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_mode,
            after.st_size,
        ):
            raise BrokerError("AC Hunter relay configuration changed while opening")
        raw = handle.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise BrokerError("AC Hunter relay configuration exceeds its byte limit")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise BrokerError("AC Hunter relay configuration is invalid")


def _validate_config_shape(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != CONFIG_SCHEMA:
        raise BrokerError("AC Hunter relay configuration schema is unsupported")
    allowed = {
        "schema",
        "enabled",
        "upstream_ip",
        "upstream_port",
        "tls_server_name",
        "ca_bundle",
        "certificate_sha256",
        "connect_timeout_seconds",
        "request_timeout_seconds",
        "max_response_bytes",
        "lock_file",
    }
    if set(value) - allowed:
        raise BrokerError("AC Hunter relay configuration has unsupported fields")
    return value


def _validate_upstream_identity(value: dict[str, Any]) -> None:
    if value.get("enabled") is not True:
        raise BrokerError("AC Hunter relay transport is disabled")
    if value.get("upstream_ip") != "192.168.1.12":
        raise BrokerError("AC Hunter relay upstream is outside the fixed allowlist")
    if value.get("upstream_port") != 443:
        raise BrokerError("AC Hunter relay upstream port is outside the fixed allowlist")
    if value.get("tls_server_name") != "localhost":
        raise BrokerError("AC Hunter relay TLS server name is outside the fixed allowlist")
    digest = value.get("certificate_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise BrokerError("AC Hunter relay certificate pin is invalid")


def _validated_ca_bundle(value: dict[str, Any]) -> Path:
    ca_bundle = Path(str(value.get("ca_bundle") or ""))
    _secure_regular_file(ca_bundle, maximum_bytes=128 * 1024)
    return ca_bundle


def _validate_config_limits(value: dict[str, Any]) -> None:
    connect_timeout = value.get("connect_timeout_seconds", 8)
    request_timeout = value.get("request_timeout_seconds", 30)
    maximum = value.get("max_response_bytes", MAX_RESPONSE_BYTES)
    for item, label, minimum, maximum_value in (
        (connect_timeout, "connect timeout", 1, 15),
        (request_timeout, "request timeout", 2, 60),
        (maximum, "response byte limit", 1024, MAX_RESPONSE_BYTES),
    ):
        if (
            isinstance(item, bool)
            or not isinstance(item, int)
            or not minimum <= item <= maximum_value
        ):
            raise BrokerError(f"AC Hunter relay {label} is invalid")


def _validated_lock_file(value: dict[str, Any]) -> Path:
    lock_file = Path(str(value.get("lock_file") or DEFAULT_LOCK))
    if lock_file != DEFAULT_LOCK:
        raise BrokerError("AC Hunter relay lock path is outside the fixed allowlist")
    return lock_file


def _load_config(path: Path) -> dict[str, Any]:
    value = _validate_config_shape(_read_config_snapshot(path))
    _validate_upstream_identity(value)
    ca_bundle = _validated_ca_bundle(value)
    _validate_config_limits(value)
    lock_file = _validated_lock_file(value)
    return {
        **value,
        "ca_bundle": ca_bundle,
        "lock_file": lock_file,
    }


def _acquire_lock(path: Path):
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise BrokerError("AC Hunter relay lock failed validation")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BrokerError("AC Hunter relay is busy")
        return os.fdopen(descriptor, "r+")
    except BaseException:
        os.close(descriptor)
        raise


def _tls_socket(config: dict[str, Any]) -> ssl.SSLSocket:
    try:
        context = ssl.create_default_context(cafile=str(config["ca_bundle"]))
        # The appliance certificate is intentionally pinned and signed for
        # localhost.  Validate its chain and exact DER digest while using the
        # configured localhost SNI, rather than disabling certificate checks.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
        raw_socket = socket.create_connection(
            (config["upstream_ip"], config["upstream_port"]),
            timeout=config["connect_timeout_seconds"],
        )
        try:
            secure = context.wrap_socket(
                raw_socket,
                server_hostname=config["tls_server_name"],
            )
        except BaseException:
            raw_socket.close()
            raise
        secure.settimeout(config["request_timeout_seconds"])
        actual = hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()
        if actual != config["certificate_sha256"]:
            secure.close()
            raise BrokerError("AC Hunter relay certificate pin did not match")
        return secure
    except BrokerError:
        raise
    except (OSError, ssl.SSLError):
        raise BrokerError("AC Hunter relay TLS connection failed")


def _response_headers(response: http.client.HTTPResponse) -> dict[str, object]:
    location = response.headers.get("Location", "")
    if not isinstance(location, str):
        location = ""
    if any(character in location for character in ("\r", "\n", "\x00")):
        location = ""
    encoded_location = location.encode("utf-8")
    if len(encoded_location) > MAX_LOCATION_BYTES:
        location = ""
    cookies = response.headers.get_all("Set-Cookie") or []
    safe_cookies: list[str] = []
    for cookie in cookies[:MAX_SET_COOKIES]:
        if (
            isinstance(cookie, str)
            and cookie
            and not any(character in cookie for character in ("\r", "\n", "\x00"))
            and len(cookie.encode("utf-8")) <= 16 * 1024
        ):
            safe_cookies.append(cookie)
    return {"location": location, "set_cookie": safe_cookies}


def _read_response(
    response: http.client.HTTPResponse,
    request: UpstreamRequest,
    maximum_bytes: int,
) -> tuple[str, object]:
    content_type = str(response.headers.get("Content-Type", "")).split(";", 1)[0]
    length = response.headers.get("Content-Length")
    if length:
        try:
            if int(length) > maximum_bytes:
                raise BrokerError("AC Hunter relay response exceeded its byte limit")
        except ValueError:
            raise BrokerError("AC Hunter relay response length was invalid")
    raw = response.read(maximum_bytes + 1)
    if len(raw) > maximum_bytes:
        raise BrokerError("AC Hunter relay response exceeded its byte limit")
    if request.response_kind == "none":
        return content_type, None
    if request.response_kind == "html":
        try:
            return content_type, raw.decode("utf-8")
        except UnicodeDecodeError:
            raise BrokerError("AC Hunter login form was not valid UTF-8")
    if response.status == 302:
        return content_type, None
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise BrokerError("AC Hunter returned a non-JSON API response")
    if not isinstance(body, (dict, list, int, float, str, bool)) and body is not None:
        raise BrokerError("AC Hunter returned an unsupported JSON value")
    return content_type, body


def _perform(
    config: dict[str, Any],
    request: UpstreamRequest,
) -> tuple[int, str, dict[str, object], object]:
    secure = _tls_socket(config)
    connection = http.client.HTTPConnection(
        config["upstream_ip"],
        config["upstream_port"],
        timeout=config["request_timeout_seconds"],
    )
    connection.sock = secure
    try:
        connection.request(
            request.method,
            request.path,
            body=request.body if request.body else None,
            headers=request.headers,
        )
        response = connection.getresponse()
        headers = _response_headers(response)
        content_type, body = _read_response(
            response,
            request,
            config["max_response_bytes"],
        )
        return response.status, content_type, headers, body
    except BrokerError:
        raise
    except (OSError, ssl.SSLError, http.client.HTTPException):
        raise BrokerError("AC Hunter upstream request failed")
    finally:
        connection.close()


def main() -> int:
    started = time.monotonic()
    request_id = "0" * 32
    if len(sys.argv) != 1 or os.environ.get("SSH_ORIGINAL_COMMAND", "").strip():
        return _emit(
            request_id=request_id,
            ok=False,
            status=0,
            error="commands and arguments are not accepted by this forced endpoint",
            exit_code=2,
        )
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        return _emit(
            request_id=request_id,
            ok=False,
            status=0,
            error="request exceeds the AC Hunter relay byte limit",
            exit_code=2,
        )
    try:
        payload = json.loads(raw.decode("utf-8"))
        if isinstance(payload, dict):
            candidate = payload.get("request_id")
            if isinstance(candidate, str) and len(candidate) == 32:
                request_id = candidate
        request_id, request = compile_request(payload)
        config_path = Path(
            os.environ.get("ONION_SENTINEL_AC_HUNTER_CONFIG", DEFAULT_CONFIG)
        )
        config = _load_config(config_path)
        with _acquire_lock(config["lock_file"]):
            status, content_type, headers, body = _perform(config, request)
        duration = int((time.monotonic() - started) * 1000)
        accepted = status in request.allowed_statuses
        return _emit(
            request_id=request_id,
            ok=accepted,
            status=status,
            content_type=content_type,
            headers=headers,
            body=body,
            duration_ms=duration,
            error="" if accepted else "AC Hunter returned an unexpected status",
            exit_code=0 if accepted else 5,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, AcHunterContractError):
        return _emit(
            request_id=request_id,
            ok=False,
            status=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error="invalid AC Hunter relay request",
            exit_code=2,
        )
    except BrokerError as exc:
        return _emit(
            request_id=request_id,
            ok=False,
            status=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error=str(exc),
            exit_code=4,
        )
    except BaseException:
        return _emit(
            request_id=request_id,
            ok=False,
            status=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error="AC Hunter relay request failed",
            exit_code=4,
        )


if __name__ == "__main__":
    raise SystemExit(main())
