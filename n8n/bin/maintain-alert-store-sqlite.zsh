#!/bin/zsh
set -euo pipefail

# Verify and back up the Onion Sentinel alert-store SQLite database.
#
# This script is designed for launchd on the Mac Studio. It creates runtime-only
# backups under $HOME/n8n-local/alert_store_backups and writes logs under
# $HOME/n8n-local/logs. If corruption is detected, it preserves the bad DB and
# writes a recovered candidate, but it does not swap files unless explicitly
# enabled with ALERT_STORE_AUTO_RECOVER=1.

STACK_DIR="${STACK_DIR:-$HOME/n8n-local}"
DB_PATH="${ALERT_STORE_DB_PATH:-$STACK_DIR/alert_store_data/alerts.sqlite3}"
BACKUP_DIR="${ALERT_STORE_BACKUP_DIR:-$STACK_DIR/alert_store_backups}"
LOG_DIR="${ALERT_STORE_MAINTENANCE_LOG_DIR:-$STACK_DIR/logs}"
KEEP_BACKUPS="${ALERT_STORE_BACKUP_KEEP:-48}"
AUTO_RECOVER="${ALERT_STORE_AUTO_RECOVER:-0}"
ENV_FILE="${ALERT_STORE_ENV_FILE:-$STACK_DIR/.env}"
STATE_FILE="$LOG_DIR/alert-store-sqlite-maintenance-state.json"
REFRESH_GROUPS_URL="${ALERT_STORE_REFRESH_GROUPS_URL:-http://127.0.0.1:8787/refresh-groups}"
REFRESH_GROUPS_TIMEOUT="${ALERT_STORE_REFRESH_GROUPS_TIMEOUT:-60}"
STAMP="$(date '+%Y%m%dT%H%M%S%z')"
LOG_FILE="$LOG_DIR/alert-store-sqlite-maintenance.log"

mkdir -p "$BACKUP_DIR" "$LOG_DIR"

log() {
  print -r -- "[$(date '+%Y-%m-%d  %H:%M:%S%z')] $*" | tee -a "$LOG_FILE"
}

send_telegram() {
  local message="$1"
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
    if key in {"TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"}:
        print(f"export {key}={shlex.quote(value.strip())}")
PY
)"
  [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]] || return 1
  /usr/bin/python3 - "$TELEGRAM_BOT_TOKEN" "$TELEGRAM_CHAT_ID" "$message" <<'PY'
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

mark_failed() {
  local detail="$1"
  local previous
  previous="$(read_status)"
  write_status failed "$detail"
  if [[ "$previous" != failed ]]; then
    send_telegram "[FAILURE] Onion Sentinel alert-store SQLite maintenance failed at $(date -u '+%Y-%m-%d  %H:%M:%SZ')
$detail" >/dev/null || true
  fi
}

mark_ok() {
  local detail="$1"
  local previous
  previous="$(read_status)"
  write_status ok "$detail"
  if [[ "$previous" == failed ]]; then
    send_telegram "[RECOVERY] Onion Sentinel alert-store SQLite maintenance recovered at $(date -u '+%Y-%m-%d  %H:%M:%SZ')
$detail" >/dev/null || true
  fi
}

fail() {
  local detail="$1"
  log "ERROR $detail"
  mark_failed "$detail"
  exit 1
}

require_sqlite() {
  if ! command -v sqlite3 >/dev/null 2>&1; then
    fail "sqlite3 is not installed or not in PATH"
  fi
}

quick_check() {
  local db="$1"
  sqlite3 "$db" 'PRAGMA quick_check;' 2>&1
}

verified_backup() {
  local backup_tmp="$BACKUP_DIR/alerts.sqlite3.$STAMP.backup.tmp"
  local backup="$BACKUP_DIR/alerts.sqlite3.$STAMP.backup"
  sqlite3 "$DB_PATH" ".backup '$backup_tmp'"
  local backup_check
  backup_check="$(quick_check "$backup_tmp")"
  if [[ "$backup_check" != "ok" ]]; then
    rm -f "$backup_tmp"
    fail "backup failed quick_check: $backup_check"
  fi
  mv "$backup_tmp" "$backup"
  log "backup_ok path=$backup"
}

summary_consistency_check() {
  /usr/bin/python3 - "$DB_PATH" <<'PY'
import json
import sqlite3
import sys

db_path = sys.argv[1]
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
bad_alert_filters = conn.execute(
    """
    SELECT COUNT(*) AS count
    FROM alerts
    WHERE COALESCE(NULLIF(filter_status, ''), 'accepted') NOT IN ('accepted', 'duplicate', 'escalated', 'suppressed', 'acknowledged', 'unknown')
    """
).fetchone()["count"]
bad_summary_filters = conn.execute(
    """
    SELECT COUNT(*) AS count
    FROM alert_group_summary
    WHERE COALESCE(NULLIF(filter_status, ''), 'accepted') NOT IN ('accepted', 'duplicate', 'escalated', 'suppressed', 'acknowledged', 'unknown')
    """
).fetchone()["count"]
orphan_summaries = conn.execute(
    """
    WITH alert_groups AS (
      SELECT COALESCE(
        NULLIF(suppression_key, ''),
        COALESCE(triage_level, 'unknown-level') || '|' ||
        COALESCE(rule_name, 'unknown-rule') || '|' ||
        COALESCE(source_ip, 'unknown-source') || '|' ||
        COALESCE(destination_ip, 'unknown-destination') || '|' ||
        COALESCE(filter_status, 'accepted')
      ) AS group_key
      FROM alerts
      GROUP BY group_key
    )
    SELECT COUNT(*) AS count
    FROM alert_group_summary AS s
    LEFT JOIN alert_groups AS a ON a.group_key = s.group_key
    WHERE a.group_key IS NULL
    """
).fetchone()["count"]
missing_summaries = conn.execute(
    """
    WITH alert_groups AS (
      SELECT COALESCE(
        NULLIF(suppression_key, ''),
        COALESCE(triage_level, 'unknown-level') || '|' ||
        COALESCE(rule_name, 'unknown-rule') || '|' ||
        COALESCE(source_ip, 'unknown-source') || '|' ||
        COALESCE(destination_ip, 'unknown-destination') || '|' ||
        COALESCE(filter_status, 'accepted')
      ) AS group_key
      FROM alerts
      GROUP BY group_key
    )
    SELECT COUNT(*) AS count
    FROM alert_groups AS a
    LEFT JOIN alert_group_summary AS s ON s.group_key = a.group_key
    WHERE s.group_key IS NULL
    """
).fetchone()["count"]
result = {
    "bad_alert_filters": bad_alert_filters,
    "bad_summary_filters": bad_summary_filters,
    "orphan_summaries": orphan_summaries,
    "missing_summaries": missing_summaries,
}
print(json.dumps(result, sort_keys=True))
sys.exit(0 if all(value == 0 for value in result.values()) else 2)
PY
}

refresh_group_summaries() {
  /usr/bin/curl -fsS --max-time "$REFRESH_GROUPS_TIMEOUT" -X POST "$REFRESH_GROUPS_URL"
}

recover_candidate() {
  local corrupt_copy="$BACKUP_DIR/alerts.sqlite3.$STAMP.corrupt"
  local sql_file="$BACKUP_DIR/alerts.sqlite3.$STAMP.recover.sql"
  local err_file="$BACKUP_DIR/alerts.sqlite3.$STAMP.recover.err"
  local recovered="$BACKUP_DIR/alerts.sqlite3.$STAMP.recovered"

  cp -p "$DB_PATH" "$corrupt_copy"
  sqlite3 "$DB_PATH" '.recover' > "$sql_file" 2> "$err_file" || true
  sqlite3 "$recovered" < "$sql_file"
  local recovered_check
  recovered_check="$(quick_check "$recovered")"
  if [[ "$recovered_check" != "ok" ]]; then
    log "corrupt_copy=$corrupt_copy recover_sql=$sql_file recover_err=$err_file"
    fail "recovered candidate failed quick_check: $recovered_check"
  fi
  log "recovered_candidate_ok path=$recovered corrupt_copy=$corrupt_copy recover_err=$err_file"

  if [[ "$AUTO_RECOVER" == "1" ]]; then
    log "AUTO_RECOVER enabled; stopping host alert-store, alert-store proxy, and report portal before DB swap"
    (cd "$STACK_DIR" && /usr/local/bin/docker compose stop alert-store >/dev/null)
    launchctl bootout "gui/$(id -u)/com.arron.soc.alert-store" >/dev/null 2>&1 || true
    launchctl bootout "gui/$(id -u)/com.arron.reportportal" >/dev/null 2>&1 || true
    mv "$DB_PATH" "$BACKUP_DIR/alerts.sqlite3.$STAMP.malformed-swapped-out"
    cp -p "$recovered" "$DB_PATH"
    rm -f "$DB_PATH-wal" "$DB_PATH-shm"
    launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.arron.soc.alert-store.plist" >/dev/null 2>&1 \
      || launchctl kickstart -k "gui/$(id -u)/com.arron.soc.alert-store" >/dev/null 2>&1 \
      || true
    (cd "$STACK_DIR" && /usr/local/bin/docker compose up -d alert-store >/dev/null)
    launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.arron.reportportal.plist" >/dev/null 2>&1 \
      || launchctl kickstart -k "gui/$(id -u)/com.arron.reportportal" >/dev/null 2>&1 \
      || true
    log "auto_recover_swap_complete"
    log "maintenance_complete recovered_db=$recovered"
    exit 0
  else
    log "AUTO_RECOVER disabled; leaving live DB unchanged"
    mark_failed "live DB failed quick_check; recovered candidate is available at $recovered"
    exit 2
  fi
}

prune_backups() {
  local keep="$KEEP_BACKUPS"
  if ! [[ "$keep" =~ '^[0-9]+$' ]] || (( keep < 1 )); then
    keep=48
  fi
  find "$BACKUP_DIR" -maxdepth 1 -type f -name 'alerts.sqlite3.*.backup' -print0 \
    | xargs -0 ls -t 2>/dev/null \
    | tail -n "+$((keep + 1))" \
    | while IFS= read -r old_backup; do
        rm -f "$old_backup"
        log "pruned_backup path=$old_backup"
      done
}

main() {
  require_sqlite
  if [[ ! -f "$DB_PATH" ]]; then
    fail "DB not found: $DB_PATH"
  fi

  log "maintenance_start db=$DB_PATH"
  local check
  check="$(quick_check "$DB_PATH")"
  if [[ "$check" != "ok" ]]; then
    log "ERROR live DB failed quick_check: $check"
    recover_candidate
  fi

  local summary_check
  if ! summary_check="$(summary_consistency_check 2>&1)"; then
    log "summary_consistency_stale detail=$summary_check"
    if refresh_result="$(refresh_group_summaries 2>&1)"; then
      log "summary_refresh_result=$refresh_result"
      summary_check="$(summary_consistency_check 2>&1)" || fail "summary consistency failed after refresh: $summary_check"
    else
      fail "summary refresh endpoint failed: $refresh_result"
    fi
  fi
  log "summary_consistency_ok detail=$summary_check"

  verified_backup
  prune_backups
  mark_ok "quick_check=ok summary_consistency=ok"
  log "maintenance_complete quick_check=ok"
}

main "$@"
