#!/bin/zsh
set -euo pipefail

# LaunchAgent health monitor for the Mac Studio stack. It sends Telegram only on
# failure transitions and recovery transitions.
STACK_DIR="$HOME/n8n-local"
LOG_DIR="$STACK_DIR/logs"
STATE_FILE="$LOG_DIR/monitor-n8n-stack-state.json"
DOCKER="/usr/local/bin/docker"
ENV_FILE="$STACK_DIR/.env"
SLO_EVALUATOR="$STACK_DIR/bin/evaluate-operational-slos.py"
WEB_GUARD="$STACK_DIR/bin/ensure-onion-sentinel-web.py"

mkdir -p "$LOG_DIR"

send_telegram() {
  local message="$1"
  # Parse .env as data so token-like values can never be executed as shell.
  [[ -f "$ENV_FILE" ]] || return 1
  eval "$(/usr/bin/python3 - "$ENV_FILE" <<'PY'
from pathlib import Path
import shlex
import sys

for raw in Path(sys.argv[1]).read_text().splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    key = key.strip()
    if not key.replace("_", "").isalnum() or key[0].isdigit():
        continue
    if key in {"TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"}:
        print(f"export {key}={shlex.quote(value.strip())}")
PY
)"
  [[ -n "${TELEGRAM_BOT_TOKEN:-}" ]] || return 1
  local chat_id="${TELEGRAM_CHAT_ID:-REPLACE_WITH_TELEGRAM_CHAT_ID}"
  /usr/bin/python3 - "$TELEGRAM_BOT_TOKEN" "$chat_id" "$message" <<'PY'
import json
import sys
import urllib.request

bot_token, chat_id, message = sys.argv[1:4]
payload = json.dumps({
    "chat_id": chat_id,
    "text": message,
    "disable_web_page_preview": True,
}).encode("utf-8")
req = urllib.request.Request(
    f"https://api.telegram.org/bot{bot_token}/sendMessage",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=10) as response:
    print(response.status)
PY
}

read_status() {
  # State file prevents repeated failure spam every five minutes.
  if [[ -f "$STATE_FILE" ]]; then
    /usr/bin/python3 - "$STATE_FILE" <<'PY'
import json
import sys

print(json.load(open(sys.argv[1])).get("status", "unknown"))
PY
  else
    echo unknown
  fi
}

write_status() {
  local health_status="$1"
  local detail="$2"
  # Write JSON so humans and scripts can inspect the last known state.
  /usr/bin/python3 - "$STATE_FILE" "$health_status" "$detail" <<'PY'
from datetime import datetime
import json
import sys

path, status, detail = sys.argv[1:4]
json.dump(
    {
        "status": status,
        "detail": detail,
        "updated_at": datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  "),
    },
    open(path, "w"),
    indent=2,
    sort_keys=True,
)
PY
}

check_stack() {
  # Check the layers in dependency order: Docker, containers, n8n HTTP, then
  # alert-store from inside the Docker network.
  "$DOCKER" info >/dev/null 2>&1 || { echo "Docker is not responding"; return 1; }
  "$DOCKER" inspect -f "{{.State.Status}}" n8n 2>/dev/null | grep -qx running || { echo "n8n container is not running"; return 1; }
  "$DOCKER" inspect -f "{{.State.Status}}" alert-store 2>/dev/null | grep -qx running || { echo "alert-store proxy container is not running"; return 1; }
  /usr/bin/curl -fsS --max-time 5 http://127.0.0.1:5678/healthz >/dev/null || { echo "n8n healthz failed"; return 1; }
  /usr/bin/curl -fsS --max-time 5 http://127.0.0.1:8787/health >/dev/null || { echo "host alert-store health failed"; return 1; }
  [[ -x "$WEB_GUARD" ]] || { echo "Onion Sentinel web identity guard is missing"; return 1; }
  /usr/bin/python3 "$WEB_GUARD" --check-only >/dev/null || { echo "Onion Sentinel web service identity failed"; return 1; }
  "$DOCKER" exec n8n node -e '(async()=>{const r=await fetch("http://alert-store:8787/health"); if(!r.ok) process.exit(1); const j=await r.json(); if(!j.ok) process.exit(1);})().catch(()=>process.exit(1))' || { echo "alert-store proxy health failed"; return 1; }
  [[ -x "$SLO_EVALUATOR" ]] || { echo "operational SLO evaluator is missing"; return 1; }
  /usr/bin/python3 "$SLO_EVALUATOR" --stack-dir "$STACK_DIR" || return 1
  echo "ok"
}

previous="$(read_status)"
if detail="$(check_stack 2>&1)"; then
  write_status ok "$detail"
  if [[ "$previous" == failed ]]; then
    # Recovery notification fires only when the previous state was failed.
    send_telegram "[RECOVERY] Mac Studio n8n stack recovered at $(date -u '+%Y-%m-%d  %H:%M:%SZ')" >/dev/null || true
  fi
  echo "health_status=ok detail=$detail"
else
  write_status failed "$detail"
  if [[ "$previous" != failed ]]; then
    # First failure notification only; repeated failures stay in logs/state.
    send_telegram "[FAILURE] Mac Studio n8n stack failed at $(date -u '+%Y-%m-%d  %H:%M:%SZ')"$'\n'"$detail" >/dev/null || true
  fi
  echo "health_status=failed detail=$detail"
  exit 1
fi
