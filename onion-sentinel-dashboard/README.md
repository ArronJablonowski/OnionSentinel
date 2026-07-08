# Onion Sentinel Dashboard Node

This directory contains the Mac Studio LAN Portal backend and the generated SOC dashboard builder.

## Files

| Path | Purpose |
| --- | --- |
| `report_portal.py` | Serves the LAN Portal and SOC alert APIs. |
| `scripts/build_soc_alerts_dashboard.py` | Builds the static dashboard pages from SQLite/report artifacts. |
| `scripts/dashboard_metric_components.py` | Small tested render helpers for the SOC Alerts metric cards. |
| `scripts/dashboard_system_health_components.py` | System Health page markup, PCAP workflow panel styles, and browser refresh logic. |
| `assets/` | Onion Sentinel, metric, privacy, brand, and dashboard CSS assets used by the dashboard. |

## Runtime Locations

| Repo file | Production destination |
| --- | --- |
| `scripts/build_soc_alerts_dashboard.py` | `$HOME/.hermes/scripts/build_soc_alerts_dashboard.py` |
| `scripts/dashboard_metric_components.py` | `$HOME/.hermes/scripts/dashboard_metric_components.py` |
| `scripts/dashboard_system_health_components.py` | `$HOME/.hermes/scripts/dashboard_system_health_components.py` |
| `report_portal.py` | `$HOME/report_portal/report_portal.py` |
| `assets/` | copied into generated SOC dashboard output |

## Dashboard Features

- API-backed paginated SOC Alerts table.
- SOC Alerts table includes compact AI, enrichment, and PCAP analysis status columns.
- Shared SQLite analyst state for open, acknowledged, and suppressed grouped detections.
- Mobile SOC Alerts uses full-width expandable alert pills and a top collapsed
  navigation drawer opened from the logo/hamburger control.
- Lazy-loaded Detailed Alert Reports.
- Live System Health, PCAP ingest size, AI activity, and SOC count metrics.
- Flow page with data-flow diagram and privacy IP masking.
- Threat Hunter route with expandable hunt recommendations and copyable KQL/OQL/OSQuery pivots.
- Cyber Threat Intel route for future intelligence briefs, indicators, and enrichment context.
- SIEM Engineer menu route for model-backed tuning, detection recommendations, and a top ROI tuning candidate summary.
- Settings page for AI model routing plus SOC Analyst, Incident Responder, SIEM Engineer, Cyber Threat Intel Analyst, and Threat Hunter system prompts.

## Maintenance Notes

- Keep high-churn SOC metric-card styling in `assets/dashboard-metrics.css`.
- Keep SOC metric-card markup in the named render helpers inside `scripts/dashboard_metric_components.py`.
- Keep System Health beacon and PCAP workflow UI in `scripts/dashboard_system_health_components.py`.
- Avoid adding new metric-card HTML directly into the large page template string.

## Manual Rebuild

```bash
ssh <mac_user>@10.77.7.225 'python3 ~/.hermes/scripts/build_soc_alerts_dashboard.py && python3 ~/.hermes/scripts/sync_report_portal.py'
```

## Portal Runtime

The LAN Portal server is expected to run on the Mac Studio at port `8765`. Admin state and session files are intentionally runtime-only and ignored by Git.
