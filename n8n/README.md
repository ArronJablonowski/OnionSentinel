# n8n, Alert-Store, and AI Analysis Node

This directory restores the Mac Studio Docker n8n stack, the Node.js alert-store service, SQLite storage, local AI analysis scripts, daily rollups, and launchd supervision.

## Files

| Path | Purpose |
| --- | --- |
| `docker-compose.yml` | Runs n8n and alert-store containers. |
| `.env.example` | Placeholder Telegram and enrichment settings. Copy to runtime `.env`; never commit live `.env`. |
| `workflows/security-onion-configurable-scoring.workflow.json` | n8n workflow export. |
| `alert_store/` | SQLite-backed alert scoring, suppression, notification, and report logic. |
| `alert_store/config/scoring_rules.json` | Tunable local filtering/scoring policy. |
| `bin/` | Local AI prompt, analysis, scheduler, rollup, and stack management scripts. |
| `config/soc_analyst_system_prompt.md` | SOC analyst system prompt used for alert analysis. |
| `config/siem_engineer_system_prompt.md` | SIEM engineering prompt used for periodic tuning and detection recommendations. |
| `config/threat_hunter_system_prompt.md` | Threat hunter prompt used for hunt hypothesis and query recommendation work. |
| `config/cyber_threat_intel_system_prompt.md` | Cyber threat intelligence analyst prompt used for intelligence briefs, indicators, and enrichment context. |
| `config/incident_responder_system_prompt.md` | Incident responder prompt used for response planning and future host artifact collection guidance. |
| `config/ai_model_settings.json` | Local/cloud/hybrid AI routing defaults. |
| `agent-memory/` | Sanitized starter Markdown memory files for individual Cyber Security Agents plus shared cross-agent memory. Installed into `$HOME/n8n-local/soc-alerts/agent-memory` only if missing. |
| `launchd/` | Mac Studio LaunchAgents for stack supervision and AI jobs. |

## Install on Mac Studio

```bash
cd /path/to/OnionSentinel
n8n/bin/install-macstudio-stack.zsh
```

The installer creates or updates:

- `$HOME/n8n-local`
- `$HOME/Documents/SOC Alerts` symlink
- `$HOME/.hermes/scripts/build_soc_alerts_dashboard.py`
- `$HOME/report_portal/report_portal.py`
- LaunchAgents under `~/Library/LaunchAgents`

It does not overwrite an existing `$HOME/n8n-local/.env`.

## Timestamp Format

Onion Sentinel records and displays project timestamps in the operator's local
timezone with an explicit UTC offset. Use ISO 8601 with the `T` separator
replaced by two spaces, for example:

```text
2026-07-05  21:34:40-06:00
```

Incoming UTC values from Security Onion, enrichment APIs, or older workflow
exports are normalized to this local-offset format before they are stored in
SQLite, generated reports, status JSON, and dashboard output.

## Configure Secrets

```bash
nano $HOME/n8n-local/.env
chmod 0600 $HOME/n8n-local/.env
```

Set:

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`
- `TELEGRAM_ALERT_LEVELS=critical,high`

Configure the relay token inside the imported n8n workflow validation node by replacing `REPLACE_WITH_RELAY_TOKEN`.

Optional enrichment keys are also set in `$HOME/n8n-local/.env`. Blank or
placeholder values are treated as disabled, so a source can be enabled or
rotated by editing `.env` and restarting `alert-store`.

| Source | Environment variable | Notes |
| --- | --- | --- |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | IP reputation; free accounts are commonly limited to 1,000 checks/day. |
| GreyNoise | `GREYNOISE_API_KEY` | Internet scanner/noise context; cache aggressively. |
| Shodan InternetDB | none | Keyless public IP exposure context; throttled locally. |
| OTX | `OTX_API_KEY` | IP/domain/URL/hash pulse context. |
| URLhaus | `URLHAUS_AUTH_KEY` | Malware URL lookups; URLs are redacted before submission. |
| VirusTotal | `VIRUSTOTAL_API_KEY` | High/critical only by default; throttled to 4 requests/minute. |
| urlscan.io | `URLSCAN_API_KEY` | Search-only by default; active URL submission remains disabled unless `URLSCAN_SUBMIT_ENABLED=true`. |
| Google Safe Browsing | `GOOGLE_SAFE_BROWSING_API_KEY` | Public redacted URL checks. |
| PhishTank | `PHISHTANK_API_KEY` | Public redacted URL phishing checks. |
| MalwareBazaar | `MALWAREBAZAAR_AUTH_KEY` | Hash lookups only; no file downloads. |
| ThreatFox | `THREATFOX_AUTH_KEY` | IOC lookups for domains, hashes, and C2 indicators. |
| Shodan | `SHODAN_API_KEY` | Authenticated host API; separate from keyless InternetDB. |
| Censys | `CENSYS_API_TOKEN` or `CENSYS_API_ID` + `CENSYS_API_SECRET` | Authenticated exposed-service IP context. Personal Access Tokens use the Censys Platform API; set optional `CENSYS_ORGANIZATION_ID` when your account requires an organization header. |
| CISA KEV | none | Public CVE catalog; cached with vulnerability TTL. |
| EPSS | none | Public CVE exploit probability; cached with vulnerability TTL. |
| NVD | `NVD_API_KEY` optional | CVE metadata; key raises NVD's allowed request rate. |

Enrichment behavior knobs:

- `ENRICHMENT_CACHE_TTL_SECONDS=86400`
- `ENRICHMENT_VULN_CACHE_TTL_SECONDS=86400`
- `ENRICHMENT_TIMEOUT_MS=5000`
- `VIRUSTOTAL_MINIMUM_LEVEL=high`
- `URLSCAN_SUBMIT_ENABLED=false`

Alert-store ingestion safety knob:

- `ALERT_STORE_MAX_REQUEST_BYTES=5242880`

`ALERT_STORE_MAX_REQUEST_BYTES` caps each `/alert` and `/enrich` POST body
before Node buffers it in memory. Keep it high enough for full-fidelity Security
Onion alert JSON, but low enough that a malformed relay/n8n request cannot
consume unbounded memory during a spike.

PCAP request broker safety knobs:

- `PCAP_REQUEST_DEFAULT_WINDOW_SECONDS=120`
- `PCAP_REQUEST_MAX_WINDOW_SECONDS=300`

Alert-store exposes a request-only broker for packet-capture evidence:

```text
POST /pcap/request
GET /pcap/requests?status=pending&limit=25
```

`POST /pcap/request` validates and queues a bounded request in SQLite. It never
contacts Security Onion and never runs shell commands. The request must include
a reason and enough tuple/timing information to identify the flow, or an
existing `alert_id`/`group_id` that alert-store can resolve from SQLite. The
relay/Security Onion fulfillment path is intentionally separate and should use
a dedicated forced-command SSH wrapper with its own time-window and size limits.

Example request body:

```json
{
  "group_id": "example-group-id",
  "requested_by": "soc-analyst",
  "reason": "Packet headers would confirm whether this repeated TLS alert is one flow or many short sessions.",
  "max_window_seconds": 120
}
```

The n8n workflow includes a dedicated `Enrich Alert` node between relay
validation and alert-store persistence. That node calls alert-store
`POST /enrich`; alert-store extracts only public indicators, redacts URL query
strings and credentials, skips private IPs/internal hostnames, checks configured
sources, writes normalized records into `alerts.enrichment_json`, and caches
results in SQLite.

Indicator extraction covers public IPv4s, domains, full URLs/URIs, file hashes,
and CVEs from common ECS, Suricata, and Security Onion raw-event shapes. Local
DNS traffic is still enriched when the queried DNS name is public; the local
source host and local resolver IP are skipped, but fields such as
`dns.question.name`, Suricata `dns.rrname`/`dns.query`, TLS SNI, HTTP host,
URL fields, and related host fields can produce public domain/URL lookups.
Existing enrichment provider responses are intentionally ignored during
extraction so refresh jobs do not submit indicators found only inside previous
third-party `raw_response` payloads.

To retroactively enrich rows stored before the dedicated enrichment stage, run
the backfill utility from inside the alert-store container. Start with a dry run
or small limit, confirm SQLite integrity, then run larger batches:

```bash
cd $HOME/n8n-local
/usr/local/bin/docker compose exec -T -e BACKFILL_DRY_RUN=1 -e BACKFILL_LIMIT=25 alert-store node /app/bin/backfill-public-enrichment.js
/usr/local/bin/docker compose exec -T -e BACKFILL_LIMIT=250 alert-store node /app/bin/backfill-public-enrichment.js
sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "PRAGMA quick_check;"
```

The backfill uses the same `/enrich` endpoint, API-key gating, cache, privacy
filters, and rate-limit handling as live workflow ingestion.

## Validate

```bash
cd $HOME/n8n-local
/usr/local/bin/docker compose ps
curl -fsS http://127.0.0.1:5678/healthz
/usr/local/bin/docker exec alert-store node -e 'fetch("http://127.0.0.1:8787/health").then(r=>r.text()).then(console.log)'
```

## AI Analysis

The scheduler picks unanalyzed grouped alerts by severity first, newest first within each severity:

1. Critical
2. High
3. Medium
4. Low
5. Informational

Run a dry check:

```bash
$HOME/n8n-local/bin/auto-run-ai-analysis.py --dry-run
```

Artifacts:

- prompts: `$HOME/n8n-local/soc-alerts/ai-prompts`
- analysis JSON/Markdown: `$HOME/n8n-local/soc-alerts/ai-analysis`
- daily rollups: `$HOME/n8n-local/soc-alerts/daily-rollups`
