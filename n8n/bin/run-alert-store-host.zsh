#!/bin/zsh
set -euo pipefail

# Run alert-store on the Mac host so SQLite writes do not cross Docker
# Desktop's bind-mount virtualization layer.
STACK_DIR="${STACK_DIR:-$HOME/n8n-local}"
ENV_FILE="$STACK_DIR/.env"
ALERT_STORE_DIR="$STACK_DIR/alert_store"

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

if [[ -f "$ENV_FILE" ]]; then
  # Read literal KEY=VALUE pairs without evaluating the runtime .env as shell
  # code. API keys can legally contain shell metacharacters.
  while IFS= read -r -d $'\0' assignment; do
    export "$assignment"
  done < <(/usr/bin/python3 - "$ENV_FILE" <<'PY'
from pathlib import Path
import sys

for raw in Path(sys.argv[1]).read_text().splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    key = key.strip()
    if not key.replace("_", "").isalnum() or key[0].isdigit():
        continue
    sys.stdout.write(f"{key}={value.strip()}\0")
PY
)
fi

export ALERT_STORE_DB="${ALERT_STORE_DB:-$STACK_DIR/alert_store_data/alerts.sqlite3}"
export ALERT_STORE_BEACON_PATHS="${ALERT_STORE_BEACON_PATHS:-$STACK_DIR/alert_store_data/n8n-beacon.json,$HOME/SOC Alerts Web/n8n-beacon.json}"
export ALERT_STORE_BEACON_HISTORY_PATHS="${ALERT_STORE_BEACON_HISTORY_PATHS:-$STACK_DIR/alert_store_data/n8n-beacon-history.json,$HOME/SOC Alerts Web/n8n-beacon-history.json}"
export ALERT_STORE_HOST="${ALERT_STORE_HOST:-127.0.0.1}"
export ALERT_STORE_PORT="${ALERT_STORE_PORT:-8787}"
export SCORING_RULES_PATH="${SCORING_RULES_PATH:-$ALERT_STORE_DIR/config/scoring_rules.json}"
export PCAP_ARTIFACT_DIR="${PCAP_ARTIFACT_DIR:-$STACK_DIR/pcap-evidence/artifacts}"
export PCAP_REQUEST_DEFAULT_WINDOW_SECONDS="${PCAP_REQUEST_DEFAULT_WINDOW_SECONDS:-120}"
export PCAP_REQUEST_MAX_WINDOW_SECONDS="${PCAP_REQUEST_MAX_WINDOW_SECONDS:-300}"
export PCAP_CAPTURE_RETENTION_SECONDS="${PCAP_CAPTURE_RETENTION_SECONDS:-345600}"
export PCAP_PRIORITY_MAX_WAIT_SECONDS="${PCAP_PRIORITY_MAX_WAIT_SECONDS:-1200}"
export PCAP_TRANSFER_MAX_ATTEMPTS="${PCAP_TRANSFER_MAX_ATTEMPTS:-5}"
export PCAP_TRANSFER_MAX_RETRY_SECONDS="${PCAP_TRANSFER_MAX_RETRY_SECONDS:-1800}"
export PCAP_AUTO_REQUEST_LEVELS="${PCAP_AUTO_REQUEST_LEVELS:-critical,high,medium,low,informational}"
export ALERT_STORE_SQLITE_BUSY_TIMEOUT_MS="${ALERT_STORE_SQLITE_BUSY_TIMEOUT_MS:-30000}"
export ALERT_STORE_SQLITE_JOURNAL_MODE="${ALERT_STORE_SQLITE_JOURNAL_MODE:-DELETE}"
export ALERT_STORE_SQLITE_SYNCHRONOUS="${ALERT_STORE_SQLITE_SYNCHRONOUS:-FULL}"
export ALERT_STORE_SQLITE_TEMP_STORE="${ALERT_STORE_SQLITE_TEMP_STORE:-DEFAULT}"

cd "$ALERT_STORE_DIR"
exec node alert_store.js
