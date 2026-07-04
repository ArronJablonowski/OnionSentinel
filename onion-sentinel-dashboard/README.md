# Onion Sentinel Dashboard Node

This directory contains the Mac Studio LAN Portal backend and the generated SOC dashboard builder.

## Files

| Path | Purpose |
| --- | --- |
| `report_portal.py` | Serves the LAN Portal and SOC alert APIs. |
| `scripts/build_soc_alerts_dashboard.py` | Builds the static dashboard pages from SQLite/report artifacts. |
| `assets/` | Onion Sentinel, metric, privacy, and brand assets used by the dashboard. |

## Runtime Locations

| Repo file | Production destination |
| --- | --- |
| `scripts/build_soc_alerts_dashboard.py` | `$HOME/.hermes/scripts/build_soc_alerts_dashboard.py` |
| `report_portal.py` | `$HOME/report_portal/report_portal.py` |
| `assets/` | copied into generated SOC dashboard output |

## Dashboard Features

- API-backed paginated SOC Alerts table.
- Shared SQLite analyst state for open, acknowledged, and suppressed grouped detections.
- Lazy-loaded Detailed Alert Reports.
- Live `Latest Alert`, `Last n8n beacon`, AI activity, and SOC count metrics.
- Flow page with data-flow diagram and privacy IP masking.
- Threat Hunter route with expandable hunt recommendations and copyable KQL/OQL/OSQuery pivots.
- Cyber Threat Intel route for future intelligence briefs, indicators, and enrichment context.
- SIEM Engineer menu route for model-backed tuning, detection recommendations, and a top ROI tuning candidate summary.
- Settings page for AI model routing plus SOC Analyst, Incident Responder, SIEM Engineer, Cyber Threat Intel Analyst, and Threat Hunter system prompts.

## Manual Rebuild

```bash
ssh <mac_user>@10.77.7.225 'python3 ~/.hermes/scripts/build_soc_alerts_dashboard.py && python3 ~/.hermes/scripts/sync_report_portal.py'
```

## Portal Runtime

The LAN Portal server is expected to run on the Mac Studio at port `8765`. Admin state and session files are intentionally runtime-only and ignored by Git.
