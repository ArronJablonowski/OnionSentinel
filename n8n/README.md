# n8n, Alert-Store, and AI Analysis Node

This directory restores the Mac Studio Docker n8n stack, the Node.js alert-store service, SQLite storage, local AI analysis scripts, daily rollups, and launchd supervision.

## Files

| Path | Purpose |
| --- | --- |
| `docker-compose.yml` | Runs n8n and alert-store containers. |
| `.env.example` | Placeholder Telegram settings. Copy to runtime `.env`; never commit live `.env`. |
| `workflows/security-onion-configurable-scoring.workflow.json` | n8n workflow export. |
| `alert_store/` | SQLite-backed alert scoring, suppression, notification, and report logic. |
| `alert_store/config/scoring_rules.json` | Tunable local filtering/scoring policy. |
| `bin/` | Local AI prompt, analysis, scheduler, rollup, and stack management scripts. |
| `config/soc_analyst_system_prompt.md` | SOC analyst system prompt used for alert analysis. |
| `config/siem_engineer_system_prompt.md` | SIEM engineering prompt used for periodic tuning and detection recommendations. |
| `config/threat_hunter_system_prompt.md` | Threat hunter prompt used for hunt hypothesis and query recommendation work. |
| `config/incident_responder_system_prompt.md` | Incident responder prompt used for response planning and future host artifact collection guidance. |
| `config/ai_model_settings.json` | Local/cloud/hybrid AI routing defaults. |
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
