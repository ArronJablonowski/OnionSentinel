#!/usr/bin/env python3
"""Persistent LAN report portal compatibility facade and entrypoint."""
from __future__ import annotations

import sys
from pathlib import Path

PORTAL_SOURCE_DIR = Path(__file__).resolve().parent
if str(PORTAL_SOURCE_DIR) not in sys.path:
    sys.path.insert(0, str(PORTAL_SOURCE_DIR))

import portal_runtime_config as _runtime_config

globals().update({
    name: value
    for name, value in vars(_runtime_config).items()
    if not (name.startswith("__") and name.endswith("__"))
})

import portal_compat_bindings as _compat_bindings

__all__ = (
    "PortalHandler",
    "main",
    "render_incident_response_report_html",
    "soc_incidents_query_response",
)

_compat_bindings.bind(sys.modules[__name__])


def main() -> None:
    parser = argparse.ArgumentParser(description="Arron's persistent LAN report portal")
    parser.add_argument("--host", default=os.environ.get("REPORT_PORTAL_HOST", DEFAULT_HOST))
    parser.add_argument("--port", type=int, default=int(os.environ.get("REPORT_PORTAL_PORT", DEFAULT_PORT)))
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), PortalHandler)
    print(f"Work LAN Portal listening on http://{local_ip()}:{args.port}/ (bind {args.host}:{args.port})", flush=True)
    server.serve_forever()

if __name__ == "__main__":
    main()
