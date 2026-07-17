# Mac Studio Host Node

The Mac Studio hosts the n8n Docker stack, alert-store, SQLite database, local AI analysis jobs, SOC report corpus, and Onion Sentinel dashboard.

## Restore Order

1. Install Docker Desktop or Docker CLI compatible with `/usr/local/bin/docker`.
2. Clone this repo.
3. Run `n8n/bin/install-macstudio-stack.zsh`.
4. Edit `$HOME/n8n-local/.env`.
5. Import `n8n/workflows/security-onion-configurable-scoring.workflow.json` into n8n.
6. Create n8n variables for `RELAY_WEBHOOK_TOKEN` and, when PCAP fulfillment is enabled, `PCAP_BROKER_TOKEN`.
7. Activate the n8n workflow.
8. Start or reload the dedicated Onion Sentinel web LaunchAgent.
9. Run `operations/verify-stack.zsh`.

## Expected Runtime Paths

```text
$HOME/n8n-local
$HOME/n8n-local/alert_store_data/alerts.sqlite3
$HOME/n8n-local/soc-alerts
$HOME/n8n-local/onion-sentinel-dashboard
$HOME/Documents/SOC Alerts -> $HOME/n8n-local/soc-alerts
$HOME/SOC Alerts Web
```

## Do Not Commit

- `$HOME/n8n-local/.env`
- `$HOME/n8n-local/n8n_data/`
- `$HOME/n8n-local/alert_store_data/`
- `$HOME/n8n-local/soc-alerts/`
- `$HOME/n8n-local/admin-state/`
- `$HOME/n8n-local/config/onion-sentinel-admin-password.json`

The Hermes LAN Portal is a separate project. Its `$HOME/.hermes` and
`$HOME/report_portal` paths are outside Onion Sentinel's deployment and backup
ownership.
