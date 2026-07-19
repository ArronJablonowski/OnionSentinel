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
SQLITE_BUSY_TIMEOUT_MS="${ALERT_STORE_SQLITE_BUSY_TIMEOUT_MS:-60000}"
BACKUP_ATTEMPTS="${ALERT_STORE_BACKUP_ATTEMPTS:-5}"
ENV_FILE="${ALERT_STORE_ENV_FILE:-$STACK_DIR/.env}"
TELEGRAM_SENDER="$STACK_DIR/bin/send-telegram-notification.py"
STATE_FILE="$LOG_DIR/alert-store-sqlite-maintenance-state.json"
REFRESH_GROUPS_URL="${ALERT_STORE_REFRESH_GROUPS_URL:-http://127.0.0.1:8787/refresh-groups}"
REFRESH_GROUPS_TIMEOUT="${ALERT_STORE_REFRESH_GROUPS_TIMEOUT:-60}"
STAMP="$(date '+%Y%m%dT%H%M%S%z')"
LOG_FILE="$LOG_DIR/alert-store-sqlite-maintenance.log"
WEB_MAINTENANCE_HOLD="$LOG_DIR/onion-sentinel-web-maintenance.hold"
RECOVERY_RUNTIME_STOPPED=0

[[ "$SQLITE_BUSY_TIMEOUT_MS" == <-> ]] || SQLITE_BUSY_TIMEOUT_MS=60000
[[ "$BACKUP_ATTEMPTS" == <-> ]] || BACKUP_ATTEMPTS=5
(( BACKUP_ATTEMPTS >= 1 )) || BACKUP_ATTEMPTS=5

mkdir -p "$BACKUP_DIR" "$LOG_DIR"
# Interrupted or lock-failed runs can leave an empty temporary target. Never
# touch a current run, but remove stale partials before evaluating retention.
find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.backup.tmp' -mmin +30 -delete 2>/dev/null || true

log() {
  print -r -- "[$(date '+%Y-%m-%d  %H:%M:%S%z')] $*" | tee -a "$LOG_FILE"
}

send_telegram() {
  local message="$1"
  [[ -x "$TELEGRAM_SENDER" ]] || return 1
  /usr/bin/python3 "$TELEGRAM_SENDER" --env-file "$ENV_FILE" --message "$message"
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
  sqlite3 -cmd ".timeout $SQLITE_BUSY_TIMEOUT_MS" "$db" 'PRAGMA quick_check;' 2>&1
}

verified_backup() {
  local backup_tmp="$BACKUP_DIR/alerts.sqlite3.$STAMP.backup.tmp"
  local backup="$BACKUP_DIR/alerts.sqlite3.$STAMP.backup"
  local attempt=1
  local backup_error=""
  rm -f "$backup_tmp"
  while (( attempt <= BACKUP_ATTEMPTS )); do
    if backup_error="$(sqlite3 -cmd ".timeout $SQLITE_BUSY_TIMEOUT_MS" "$DB_PATH" ".backup '$backup_tmp'" 2>&1)"; then
      break
    fi
    rm -f "$backup_tmp"
    log "backup_busy attempt=$attempt/$BACKUP_ATTEMPTS detail=${backup_error//$'\n'/ }"
    if (( attempt == BACKUP_ATTEMPTS )); then
      fail "backup remained unavailable after $BACKUP_ATTEMPTS attempts: $backup_error"
    fi
    sleep $((attempt * 2))
    (( attempt += 1 ))
  done
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
conn = sqlite3.connect(db_path, timeout=60)
conn.execute("PRAGMA busy_timeout = 60000")
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

restart_recovery_runtime() {
  local failed=0
  if (( RECOVERY_RUNTIME_STOPPED == 1 )); then
    launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.arron.soc.alert-store.plist" >/dev/null 2>&1 \
      || launchctl kickstart -k "gui/$(id -u)/com.arron.soc.alert-store" >/dev/null 2>&1 \
      || failed=1
    (cd "$STACK_DIR" && /usr/local/bin/docker compose up -d alert-store >/dev/null) || failed=1
    launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.arron.onion-sentinel.web.plist" >/dev/null 2>&1 \
      || launchctl kickstart -k "gui/$(id -u)/com.arron.onion-sentinel.web" >/dev/null 2>&1 \
      || failed=1
  fi
  RECOVERY_RUNTIME_STOPPED=0
  rm -f "$WEB_MAINTENANCE_HOLD" || failed=1
  return "$failed"
}

recovery_exit_cleanup() {
  local original_status=$?
  restart_recovery_runtime || true
  return "$original_status"
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
    log "AUTO_RECOVER enabled; stopping host alert-store, alert-store proxy, and Onion Sentinel web service before DB swap"
    print -r -- "database recovery started at $(date '+%Y-%m-%d  %H:%M:%S%z')" > "$WEB_MAINTENANCE_HOLD"
    chmod 0600 "$WEB_MAINTENANCE_HOLD"
    RECOVERY_RUNTIME_STOPPED=1
    trap 'recovery_exit_cleanup' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    (cd "$STACK_DIR" && /usr/local/bin/docker compose stop alert-store >/dev/null)
    launchctl bootout "gui/$(id -u)/com.arron.soc.alert-store" >/dev/null 2>&1 || true
    launchctl bootout "gui/$(id -u)/com.arron.onion-sentinel.web" >/dev/null 2>&1 || true
    mv "$DB_PATH" "$BACKUP_DIR/alerts.sqlite3.$STAMP.malformed-swapped-out"
    cp -p "$recovered" "$DB_PATH"
    rm -f "$DB_PATH-wal" "$DB_PATH-shm"
    if ! restart_recovery_runtime; then
      fail "database swap completed but one or more runtime services failed to restart"
    fi
    trap - EXIT INT TERM
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
