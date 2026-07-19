#!/bin/zsh
set -euo pipefail

# Run on the Mac Studio from the DR repo checkout.
#
# This restores the Docker/n8n/alert-store runtime files plus the independently
# served Onion Sentinel dashboard. It intentionally does not overwrite live
# .env secrets or modify the separate Hermes LAN Portal project.
# STACK_DIR can be overridden for testing, but production uses
# $HOME/n8n-local.
REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
STACK_DIR="${STACK_DIR:-$HOME/n8n-local}"
LAUNCHD_DIR="${HOME}/Library/LaunchAgents"
DASHBOARD_RUNTIME_DIR="${STACK_DIR}/onion-sentinel-dashboard"

mkdir -p "$STACK_DIR/alert_store/config" "$STACK_DIR/alert_store/lib" "$STACK_DIR/bin" "$STACK_DIR/config" "$STACK_DIR/logs" "$STACK_DIR/run" "$STACK_DIR/alert_store_data" "$STACK_DIR/n8n_data" "$STACK_DIR/soc-alerts" "$STACK_DIR/soc-alerts/agent-memory" "$STACK_DIR/soc-alerts/pcap-analysis" "$STACK_DIR/pcap-evidence/artifacts"
chmod 0700 "$STACK_DIR/run"
touch "$STACK_DIR/run/ai-analysis.wake" "$STACK_DIR/run/pcap-analysis.wake" "$STACK_DIR/run/dashboard-refresh.wake"
chmod 0600 "$STACK_DIR/run/ai-analysis.wake" "$STACK_DIR/run/pcap-analysis.wake" "$STACK_DIR/run/dashboard-refresh.wake"

# n8n writes reports to ./soc-alerts inside the compose project. Obsidian uses
# the friendlier Documents path, so expose the same directory there with a
# symlink when it is safe to do so.
SOC_ALERTS_LINK="${HOME}/Documents/SOC Alerts"
if [[ -d "$SOC_ALERTS_LINK" && ! -L "$SOC_ALERTS_LINK" && -z "$(ls -A "$SOC_ALERTS_LINK")" ]]; then
  rmdir "$SOC_ALERTS_LINK"
fi
if [[ ! -e "$SOC_ALERTS_LINK" ]]; then
  ln -s "$STACK_DIR/soc-alerts" "$SOC_ALERTS_LINK"
fi

# Copy source and config into the runtime directory. Runtime data directories are
# created but not populated from Git.
cp "$REPO_DIR/n8n/docker-compose.yml" "$STACK_DIR/docker-compose.yml"
cp "$REPO_DIR/n8n/alert_store/alert_store.js" "$STACK_DIR/alert_store/alert_store.js"
cp "$REPO_DIR/n8n/alert_store/alert_store_proxy.js" "$STACK_DIR/alert_store/alert_store_proxy.js"
cp "$REPO_DIR/n8n/alert_store/package.json" "$STACK_DIR/alert_store/package.json"
cp "$REPO_DIR/n8n/alert_store/package-lock.json" "$STACK_DIR/alert_store/package-lock.json"
cp "$REPO_DIR/n8n/alert_store/review_alerts.js" "$STACK_DIR/alert_store/review_alerts.js"
cp "$REPO_DIR/n8n/alert_store/investigation_notes.js" "$STACK_DIR/alert_store/investigation_notes.js"
cp "$REPO_DIR/n8n/alert_store/lib/provider_scheduler.js" "$STACK_DIR/alert_store/lib/provider_scheduler.js"
cp "$REPO_DIR/n8n/alert_store/lib/durable_job_queue.js" "$STACK_DIR/alert_store/lib/durable_job_queue.js"
cp "$REPO_DIR/n8n/alert_store/lib/http_json_client.js" "$STACK_DIR/alert_store/lib/http_json_client.js"
cp "$REPO_DIR/n8n/alert_store/lib/http_runtime.js" "$STACK_DIR/alert_store/lib/http_runtime.js"
cp "$REPO_DIR/n8n/alert_store/lib/pipeline_metrics.js" "$STACK_DIR/alert_store/lib/pipeline_metrics.js"
cp "$REPO_DIR/n8n/alert_store/lib/group_identity.js" "$STACK_DIR/alert_store/lib/group_identity.js"
cp "$REPO_DIR/n8n/alert_store/lib/correlation_context.js" "$STACK_DIR/alert_store/lib/correlation_context.js"
# The repository carries a sanitized DR baseline. Production tuning may contain
# environment-specific rule names and addresses, so a repair install must not
# erase it. Runtime backups remain responsible for preserving the live policy.
if [[ ! -f "$STACK_DIR/alert_store/config/scoring_rules.json" ]]; then
  cp "$REPO_DIR/n8n/alert_store/config/scoring_rules.json" "$STACK_DIR/alert_store/config/scoring_rules.json"
fi
if [[ ! -f "$STACK_DIR/config/soc_analyst_system_prompt.md" && -f "$STACK_DIR/config/soc_analyst_system_prompt.txt" ]]; then
  cp "$STACK_DIR/config/soc_analyst_system_prompt.txt" "$STACK_DIR/config/soc_analyst_system_prompt.md"
elif [[ ! -f "$STACK_DIR/config/soc_analyst_system_prompt.md" ]]; then
  cp "$REPO_DIR/n8n/config/soc_analyst_system_prompt.md" "$STACK_DIR/config/soc_analyst_system_prompt.md"
fi
if [[ ! -f "$STACK_DIR/config/siem_engineer_system_prompt.md" ]]; then
  cp "$REPO_DIR/n8n/config/siem_engineer_system_prompt.md" "$STACK_DIR/config/siem_engineer_system_prompt.md"
fi
if [[ ! -f "$STACK_DIR/config/threat_hunter_system_prompt.md" ]]; then
  cp "$REPO_DIR/n8n/config/threat_hunter_system_prompt.md" "$STACK_DIR/config/threat_hunter_system_prompt.md"
fi
if [[ ! -f "$STACK_DIR/config/cyber_threat_intel_system_prompt.md" ]]; then
  cp "$REPO_DIR/n8n/config/cyber_threat_intel_system_prompt.md" "$STACK_DIR/config/cyber_threat_intel_system_prompt.md"
fi
if [[ ! -f "$STACK_DIR/config/incident_responder_system_prompt.md" ]]; then
  cp "$REPO_DIR/n8n/config/incident_responder_system_prompt.md" "$STACK_DIR/config/incident_responder_system_prompt.md"
fi
if [[ ! -f "$STACK_DIR/config/ai_model_settings.json" ]]; then
  cp "$REPO_DIR/n8n/config/ai_model_settings.json" "$STACK_DIR/config/ai_model_settings.json"
  chmod 0600 "$STACK_DIR/config/ai_model_settings.json"
fi
for memory_file in \
  soc-analyst-memory.md \
  incident-responder-memory.md \
  siem-engineer-memory.md \
  threat-hunter-memory.md \
  cyber-threat-intel-memory.md \
  shared-agent-memory.md
do
  if [[ ! -f "$STACK_DIR/soc-alerts/agent-memory/$memory_file" ]]; then
    cp "$REPO_DIR/n8n/agent-memory/$memory_file" "$STACK_DIR/soc-alerts/agent-memory/$memory_file"
  fi
done
cp "$REPO_DIR/n8n/bin/ensure-n8n-stack.zsh" "$STACK_DIR/bin/ensure-n8n-stack.zsh"
cp "$REPO_DIR/n8n/bin/monitor-n8n-stack.zsh" "$STACK_DIR/bin/monitor-n8n-stack.zsh"
cp "$REPO_DIR/n8n/bin/ensure-onion-sentinel-web.py" "$STACK_DIR/bin/ensure-onion-sentinel-web.py"
cp "$REPO_DIR/n8n/bin/send-telegram-notification.py" "$STACK_DIR/bin/send-telegram-notification.py"
cp "$REPO_DIR/n8n/bin/evaluate-operational-slos.py" "$STACK_DIR/bin/evaluate-operational-slos.py"
cp "$REPO_DIR/n8n/bin/disk_capacity.py" "$STACK_DIR/bin/disk_capacity.py"
cp "$REPO_DIR/n8n/bin/backup-onion-sentinel-runtime.py" "$STACK_DIR/bin/backup-onion-sentinel-runtime.py"
cp "$REPO_DIR/n8n/bin/report-production-soak.py" "$STACK_DIR/bin/report-production-soak.py"
cp "$REPO_DIR/n8n/bin/run-recovery-restore-drill.py" "$STACK_DIR/bin/run-recovery-restore-drill.py"
cp "$REPO_DIR/n8n/bin/run-alert-store-host.zsh" "$STACK_DIR/bin/run-alert-store-host.zsh"
cp "$REPO_DIR/n8n/bin/maintain-alert-store-sqlite.zsh" "$STACK_DIR/bin/maintain-alert-store-sqlite.zsh"
cp "$REPO_DIR/n8n/bin/build-ai-investigation-prompt.py" "$STACK_DIR/bin/build-ai-investigation-prompt.py"
cp "$REPO_DIR/n8n/bin/run-local-ai-analysis.py" "$STACK_DIR/bin/run-local-ai-analysis.py"
cp "$REPO_DIR/n8n/bin/bounded_http.py" "$STACK_DIR/bin/bounded_http.py"
cp "$REPO_DIR/n8n/bin/bounded_process.py" "$STACK_DIR/bin/bounded_process.py"
cp "$REPO_DIR/n8n/bin/auto-run-ai-analysis.py" "$STACK_DIR/bin/auto-run-ai-analysis.py"
cp "$REPO_DIR/n8n/bin/agent_memory.py" "$STACK_DIR/bin/agent_memory.py"
cp "$REPO_DIR/n8n/bin/manage-agent-memory.py" "$STACK_DIR/bin/manage-agent-memory.py"
cp "$REPO_DIR/n8n/bin/verify-agent-memory.py" "$STACK_DIR/bin/verify-agent-memory.py"
cp "$REPO_DIR/n8n/bin/backfill-ai-correlation-context.py" "$STACK_DIR/bin/backfill-ai-correlation-context.py"
cp "$REPO_DIR/n8n/bin/process-pcap-evidence.py" "$STACK_DIR/bin/process-pcap-evidence.py"
cp "$REPO_DIR/n8n/bin/onion-sentinel-pcap-intake.py" "$STACK_DIR/bin/onion-sentinel-pcap-intake.py"
cp "$REPO_DIR/n8n/bin/onion-sentinel-alert-intake.py" "$STACK_DIR/bin/onion-sentinel-alert-intake.py"
cp "$REPO_DIR/n8n/bin/configure-post-commit-env.py" "$STACK_DIR/bin/configure-post-commit-env.py"
cp "$REPO_DIR/n8n/bin/install-alert-intake-authorized-key.py" "$STACK_DIR/bin/install-alert-intake-authorized-key.py"
cp "$REPO_DIR/n8n/bin/pcap_lifecycle.py" "$STACK_DIR/bin/pcap_lifecycle.py"
cp "$REPO_DIR/n8n/bin/maintain-pcap-evidence.py" "$STACK_DIR/bin/maintain-pcap-evidence.py"
cp "$REPO_DIR/n8n/bin/refresh-soc-dashboard.py" "$STACK_DIR/bin/refresh-soc-dashboard.py"
cp "$REPO_DIR/n8n/bin/write-daily-soc-rollup.py" "$STACK_DIR/bin/write-daily-soc-rollup.py"
chmod +x "$STACK_DIR/bin/"*.zsh
chmod +x "$STACK_DIR/bin/"*.py
"$STACK_DIR/bin/verify-agent-memory.py" --initialize >/dev/null

# Onion Sentinel owns its builder, assets, API helpers, and web service. Never
# install these files under ~/.hermes or ~/report_portal; the Hermes LAN Portal
# may contain an external link to this service and nothing more.
mkdir -p "$DASHBOARD_RUNTIME_DIR/scripts" "$DASHBOARD_RUNTIME_DIR/assets"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/build_soc_alerts_dashboard.py" "$DASHBOARD_RUNTIME_DIR/scripts/build_soc_alerts_dashboard.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_metric_components.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_metric_components.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_pcap_components.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_pcap_components.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_timeline_components.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_timeline_components.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_system_health_components.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_system_health_components.py"
cp -R "$REPO_DIR/onion-sentinel-dashboard/assets/." "$DASHBOARD_RUNTIME_DIR/assets/"
cp "$REPO_DIR/onion-sentinel-dashboard/onion_sentinel_server.py" "$DASHBOARD_RUNTIME_DIR/onion_sentinel_server.py"
cp "$REPO_DIR/onion-sentinel-dashboard/http_runtime.py" "$DASHBOARD_RUNTIME_DIR/http_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/jsonl_log.py" "$DASHBOARD_RUNTIME_DIR/jsonl_log.py"
cp "$REPO_DIR/onion-sentinel-dashboard/report_portal.py" "$DASHBOARD_RUNTIME_DIR/report_portal.py"
cp "$REPO_DIR/onion-sentinel-dashboard/soc_alert_api.py" "$DASHBOARD_RUNTIME_DIR/soc_alert_api.py"
cp "$REPO_DIR/onion-sentinel-dashboard/artifact_cache.py" "$DASHBOARD_RUNTIME_DIR/artifact_cache.py"
cp "$REPO_DIR/onion-sentinel-dashboard/response_cache.py" "$DASHBOARD_RUNTIME_DIR/response_cache.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/atomic_io.py" "$DASHBOARD_RUNTIME_DIR/scripts/atomic_io.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_pcap_request_index.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_pcap_request_index.py"
chmod +x "$DASHBOARD_RUNTIME_DIR/onion_sentinel_server.py" "$DASHBOARD_RUNTIME_DIR/scripts/build_soc_alerts_dashboard.py"

# Remove the obsolete Onion Sentinel-to-Hermes publisher from this runtime. Do
# not touch any Hermes-owned files here; their owner performs the link migration.
rm -f "$STACK_DIR/bin/sync-soc-alerts-portal.py"

if [[ ! -f "$STACK_DIR/.env" ]]; then
  # Never overwrite an existing .env because it may contain the live Telegram
  # token. The example contains placeholders only.
  /usr/bin/python3 - "$HOME" "$REPO_DIR/n8n/.env.example" "$STACK_DIR/.env" <<'PY'
from pathlib import Path
import sys

home, source, destination = sys.argv[1:4]
Path(destination).write_text(Path(source).read_text().replace("__HOME__", home))
PY
  chmod 0600 "$STACK_DIR/.env"
  echo "Created $STACK_DIR/.env from example. Edit it before expecting Telegram notifications." >&2
fi

mkdir -p "$LAUNCHD_DIR"
for plist in \
  com.arron.n8n.ensure-stack.plist \
  com.arron.n8n.monitor-stack.plist \
  com.arron.soc.alert-store.plist \
  com.arron.soc.alert-store-maintenance.plist \
  com.arron.soc.pcap-analysis.plist \
  com.arron.soc.pcap-retention.plist \
  com.arron.soc.ai-analysis.plist \
  com.arron.soc.dashboard-refresh.plist \
  com.arron.soc.daily-rollup.plist \
  com.arron.onion-sentinel.web.plist \
  com.arron.onion-sentinel.web-guard.plist \
  com.arron.onion-sentinel.runtime-backup.plist
do
  /usr/bin/python3 - "$HOME" "$REPO_DIR/n8n/launchd/$plist" "$LAUNCHD_DIR/$plist" <<'PY'
from pathlib import Path
import sys

home, source, destination = sys.argv[1:4]
Path(destination).write_text(Path(source).read_text().replace("__HOME__", home))
PY
done

/opt/homebrew/bin/node -e '
const [major, minor] = process.versions.node.split(".").map(Number);
if (major < 20 || (major === 20 && minor < 17)) {
  console.error(`Onion Sentinel alert-store requires Node.js >=20.17.0; found ${process.versions.node}`);
  process.exit(1);
}
'
PATH="/opt/homebrew/bin:$PATH" /opt/homebrew/bin/npm --prefix "$STACK_DIR/alert_store" ci --omit=dev

/usr/local/bin/docker compose -f "$STACK_DIR/docker-compose.yml" --project-directory "$STACK_DIR" up -d
# Reload LaunchAgents so Docker/n8n are monitored after future reboots.
launchctl unload "$LAUNCHD_DIR/com.arron.n8n.ensure-stack.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.n8n.monitor-stack.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.soc.alert-store.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.soc.alert-store-maintenance.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.soc.pcap-analysis.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.soc.pcap-retention.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.soc.ai-analysis.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.soc.dashboard-refresh.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.soc.daily-rollup.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.onion-sentinel.web-guard.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.onion-sentinel.web.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.onion-sentinel.runtime-backup.plist" >/dev/null 2>&1 || true
launchctl load "$LAUNCHD_DIR/com.arron.n8n.ensure-stack.plist"
launchctl load "$LAUNCHD_DIR/com.arron.n8n.monitor-stack.plist"
launchctl load "$LAUNCHD_DIR/com.arron.soc.alert-store.plist"
launchctl load "$LAUNCHD_DIR/com.arron.soc.alert-store-maintenance.plist"
launchctl load "$LAUNCHD_DIR/com.arron.soc.pcap-analysis.plist"
launchctl load "$LAUNCHD_DIR/com.arron.soc.pcap-retention.plist"
launchctl load "$LAUNCHD_DIR/com.arron.soc.ai-analysis.plist"
launchctl load "$LAUNCHD_DIR/com.arron.soc.dashboard-refresh.plist"
launchctl load "$LAUNCHD_DIR/com.arron.soc.daily-rollup.plist"
launchctl load "$LAUNCHD_DIR/com.arron.onion-sentinel.web.plist"
launchctl load "$LAUNCHD_DIR/com.arron.onion-sentinel.web-guard.plist"
launchctl load "$LAUNCHD_DIR/com.arron.onion-sentinel.runtime-backup.plist"

cat <<MSG

Mac Studio n8n stack installed at:
  $STACK_DIR

Next manual steps:
1. Edit $STACK_DIR/.env with the Telegram token and chat id.
2. Run n8n/bin/sync-alert-intake-workflow.py --check, then import
   n8n/workflows/security-onion-configurable-scoring.workflow.json into n8n.
3. Create n8n variables for RELAY_WEBHOOK_TOKEN and, when PCAP is enabled, PCAP_BROKER_TOKEN.
4. Set runtime-only N8N_POST_COMMIT_TOKEN to the RELAY_WEBHOOK_TOKEN value.
5. Install a dedicated forced-command alert-intake public key using
   n8n/ssh/authorized_keys.alert-intake.example.
6. Activate the workflow and validate synthetic post-commit delivery before
   enabling relay alert_ingest.

MSG
