# Onion Sentinel Dashboard Node

This directory contains the independently served Onion Sentinel dashboard,
SOC APIs, builder, and static assets. The separate Hermes LAN Portal may link
to Onion Sentinel, but it is not a build, publish, authentication, or runtime
dependency.

## Files

| Path | Purpose |
| --- | --- |
| `onion_sentinel_server.py` | Dedicated port `8766` service that exposes only Onion Sentinel static files, admin login, and SOC APIs. |
| `report_portal.py` | Transitional SOC API implementation imported from the dedicated server; non-SOC routes are not exposed by `onion_sentinel_server.py`. |
| `artifact_cache.py` | Thread-safe, single-flight cache for parsed Markdown/JSON artifacts. |
| `response_cache.py` | Short-lived, bounded cache for serialized read-only API responses. |
| `scripts/build_soc_alerts_dashboard.py` | Builds the static dashboard pages from SQLite/report artifacts. |
| `scripts/dashboard_metric_components.py` | Small tested render helpers for the SOC Alerts metric cards. |
| `scripts/dashboard_timeline_components.py` | Grouped-observation timeline rendering, including single-observation reports. |
| `scripts/dashboard_system_health_components.py` | System Health page markup, PCAP workflow panel styles, and browser refresh logic. |
| `assets/` | Onion Sentinel, metric, privacy, brand, and dashboard CSS assets used by the dashboard. |

## Runtime Locations

| Repo file | Production destination |
| --- | --- |
| `onion_sentinel_server.py` | `$HOME/n8n-local/onion-sentinel-dashboard/onion_sentinel_server.py` |
| `report_portal.py` and API helpers | `$HOME/n8n-local/onion-sentinel-dashboard/` |
| `scripts/` | `$HOME/n8n-local/onion-sentinel-dashboard/scripts/` |
| `assets/` | `$HOME/n8n-local/onion-sentinel-dashboard/assets/` and generated output |
| generated pages | `$HOME/SOC Alerts Web/` |

## Dashboard Features

- API-backed paginated SOC Alerts table.
- SOC Alerts table includes compact AI, enrichment, and PCAP analysis status columns.
- Shared SQLite analyst state for open, acknowledged, and suppressed grouped detections.
- Mobile SOC Alerts uses full-width expandable alert pills and a top collapsed
  navigation drawer opened from the logo/hamburger control.
- Short phone-landscape layouts collapse filters by default and present metric
  cards as a compact horizontal strip so alerts begin in the initial viewport.
- Lazy-loaded Detailed Alert Reports governed by layout contract
  `2026-07-15.1`. All 15 standard sections render exactly once in fixed order;
  absent evidence uses an explicit placeholder and a group with one observation
  still renders a one-point timeline.
- Cross-alert correlation renders only as a subsection inside `AI Analysis Output`;
  it must not add, remove, or reorder a top-level report section.
- Live System Health, PCAP ingest size, AI activity, and SOC count metrics.
- Paginated PCAP workflow history with artifact size and end-to-end transfer time.
- Flow page with data-flow diagram and privacy IP masking.
- Threat Hunter route with expandable hunt recommendations and copyable KQL/OQL/OSQuery pivots.
- Cyber Threat Intel route for future intelligence briefs, indicators, and enrichment context.
- SIEM Engineer menu route for model-backed tuning, detection recommendations, and a top ROI tuning candidate summary.
- Settings page for AI model routing plus SOC Analyst, Incident Responder, SIEM Engineer, Cyber Threat Intel Analyst, and Threat Hunter system prompts. Each collapsed agent row exposes a `Prompt` control that opens and focuses the matching editable prompt panel, plus allowlisted `Memory` and `Shared` controls that open the live Markdown file in a read-only viewer; the UI has no memory write action.

## Maintenance Notes

- Keep high-churn SOC metric-card styling in `assets/dashboard-metrics.css`.
- Keep SOC metric-card markup in the named render helpers inside `scripts/dashboard_metric_components.py`.
- Keep System Health beacon and PCAP workflow UI in `scripts/dashboard_system_health_components.py`.
- Avoid adding new metric-card HTML directly into the large page template string.
- Route API requests before scanning the report library. Recursive report scans belong
  only on report-library and view routes; placing them in the common request path makes
  SOC APIs scale with the entire Markdown corpus.
- Use `ArtifactCache` for parsed artifacts and `ResponseCache` for short-lived API
  payloads. Both caches coalesce concurrent misses so a burst does not duplicate the
  same disk or SQLite work. Invalidate response entries after analyst mutations rather
  than extending their TTL.
- Keep the SOC alert event stream on the shared cached snapshot path. Each
  browser must not independently rescan SQLite and report artifacts; uncached
  per-client snapshots can starve health and API requests when several tabs
  remain open.
- Keep primary alert reports separate from derived `ai-analysis`,
  `pcap-analysis`, prompt, memory, rollup, and LLM-log artifacts. Derived files
  may repeat an alert ID, but must never replace the primary Markdown report
  used to assemble the standardized Detailed Alert Report.
- Change Detailed Alert Report structure only by updating the versioned
  contract, builder validation, portal validation, tests, and architecture docs
  together. Never append late evidence after `Raw Logs`; the next dashboard
  rebuild must refresh the appropriate canonical section in place.
- Publish detail fragments with same-directory temporary files and atomic
  replacement. Remove stale group files only after every current fragment has
  been published; never empty the live details directory during a rebuild.
- The desktop selected-alert band must be fixed beneath a currently visible
  sticky header or at viewport top after the header leaves view. Do not use a
  cached header height as its unconditional top offset.
- Keep agent-memory reads behind `/api/soc-settings/agent-memory?key=<logical-key>`.
  Never accept a browser-supplied path, add a memory POST route, or render memory
  with `innerHTML`. The portal allowlist and 256 KiB bound are security controls,
  while the model harness remains the sole managed memory write path.

## Performance Verification

Exercise the live read APIs with concurrent clients after dashboard changes. A healthy
cached burst should complete without errors or serialized multi-second stalls:

```bash
python3 - <<'PY'
from concurrent.futures import ThreadPoolExecutor
from urllib.request import urlopen

url = "http://127.0.0.1:8766/api/soc-alerts?limit=1"
with ThreadPoolExecutor(max_workers=40) as pool:
    results = list(pool.map(lambda _: urlopen(url, timeout=5).status, range(120)))
assert results == [200] * 120
PY
```

Run this on the Mac Studio. Do not print response bodies because they contain live
alert data.

Also hold multiple `/api/soc-alerts/events` clients open while probing
`/healthz`. Health requests must remain responsive; this validates that event
clients share the coalesced snapshot rather than duplicating backend scans.

## Manual Rebuild

```bash
ssh <mac_user>@10.77.7.225 'python3 "$HOME/n8n-local/bin/refresh-soc-dashboard.py"'
```

The refresh worker writes the completed build directly to `$HOME/SOC Alerts Web`.
It must not invoke any file under `$HOME/.hermes`, copy into
`$HOME/report_portal`, or depend on Hermes/OpenClaw availability. The dedicated
LaunchAgent serves that directory directly.

## Dedicated Runtime

Onion Sentinel runs at `http://10.77.7.225:8766/` under
`com.arron.onion-sentinel.web`. Admin state and sessions live under
`$HOME/n8n-local`, are runtime-only, and are ignored by Git. The Hermes LAN
Portal at port `8765` is separately owned and may contain only an ordinary link
to this URL. It must not iframe, proxy, copy, rebuild, or delete Onion Sentinel
content.
