"""CLI validation and lifecycle composition for the dedicated web service."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
from types import ModuleType
from urllib.parse import urlparse


def build_parser(c: ModuleType) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Dedicated Onion Sentinel web service"
    )
    parser.add_argument(
        "--host", default=os.environ.get("ONION_SENTINEL_HOST", c.DEFAULT_HOST)
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("ONION_SENTINEL_PORT", c.DEFAULT_PORT)),
    )
    parser.add_argument(
        "--dashboard-root",
        type=Path,
        default=Path(
            os.environ.get(
                "ONION_SENTINEL_DASHBOARD_ROOT", c.DEFAULT_DASHBOARD_ROOT
            )
        ),
    )
    parser.add_argument(
        "--max-active-requests",
        type=int,
        default=int(os.environ.get("ONION_SENTINEL_MAX_ACTIVE_REQUESTS", "96")),
    )
    parser.add_argument(
        "--request-timeout-seconds",
        type=float,
        default=float(
            os.environ.get("ONION_SENTINEL_REQUEST_TIMEOUT_SECONDS", "30")
        ),
    )
    return parser


def validate_controlled_arguments(c: ModuleType, args: argparse.Namespace) -> None:
    if not c.CONTROLLED_EVALUATION_MODE:
        return
    dashboard_root = args.dashboard_root.expanduser()
    try:
        metadata = dashboard_root.lstat()
        resolved = dashboard_root.resolve(strict=True)
    except OSError as exc:
        raise SystemExit(
            f"controlled evaluation dashboard root is unsafe: {exc}"
        ) from exc
    origin = urlparse(c.runtime.SOC_ALERT_STORE_API_URL)
    if not (
        _listener_identity_safe(c, args)
        and _dashboard_root_safe(dashboard_root, resolved, metadata)
        and _alert_store_origin_safe(origin)
    ):
        raise SystemExit(
            "controlled evaluation requires owner-only runtime content, "
            "loopback listeners, and an exact release ID"
        )


def _listener_identity_safe(c: ModuleType, args: argparse.Namespace) -> bool:
    return (
        args.host == "127.0.0.1"
        and 1024 <= args.port <= 65535
        and args.port != c.DEFAULT_PORT
        and re.fullmatch(r"[a-f0-9]{40}", c.RUNTIME_RELEASE_ID) is not None
        and re.fullmatch(r"[a-f0-9]{64}", c.CONTROLLED_EVALUATION_TOKEN)
        is not None
    )


def _dashboard_root_safe(root: Path, resolved: Path, metadata: object) -> bool:
    return (
        root.is_absolute()
        and resolved == root
        and not root.is_symlink()
        and root.is_dir()
        and (
            not hasattr(os, "getuid")
            or metadata.st_uid == os.getuid()  # type: ignore[attr-defined]
        )
        and metadata.st_mode & 0o022 == 0  # type: ignore[attr-defined]
    )


def _alert_store_origin_safe(origin: object) -> bool:
    return (
        origin.scheme == "http"  # type: ignore[attr-defined]
        and origin.hostname == "127.0.0.1"  # type: ignore[attr-defined]
        and origin.port is not None  # type: ignore[attr-defined]
        and origin.port != 8787  # type: ignore[attr-defined]
        and origin.username is None  # type: ignore[attr-defined]
        and origin.password is None  # type: ignore[attr-defined]
        and origin.path in {"", "/"}  # type: ignore[attr-defined]
        and not origin.params  # type: ignore[attr-defined]
        and not origin.query  # type: ignore[attr-defined]
        and not origin.fragment  # type: ignore[attr-defined]
    )


def main(c: ModuleType) -> None:
    args = build_parser(c).parse_args()
    validate_controlled_arguments(c, args)
    c.configure_runtime_paths(args.dashboard_root)
    if not c.CONTROLLED_EVALUATION_MODE:
        args.dashboard_root.mkdir(parents=True, exist_ok=True)
    server = c.OnionSentinelHTTPServer(
        (args.host, args.port),
        args.dashboard_root,
        max_active_requests=args.max_active_requests,
        request_timeout_seconds=args.request_timeout_seconds,
    )
    c.APPLICATION_LOGGER.log(
        "info",
        "service.ready",
        release_id=c.RUNTIME_RELEASE_ID or "unversioned",
        listen_host=args.host,
        listen_port=args.port,
        dashboard_root=str(args.dashboard_root),
        controlled_evaluation=c.CONTROLLED_EVALUATION_MODE,
    )
    print(
        f"Onion Sentinel listening on http://{c.runtime.local_ip()}:{args.port}/",
        flush=True,
    )
    server.serve_forever()
