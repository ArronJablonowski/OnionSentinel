#!/bin/zsh
set -euo pipefail
umask 077

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
DEFAULT_KEEP_BACKUPS=10
KEEP_BACKUPS="${ALERT_STORE_BACKUP_KEEP:-$DEFAULT_KEEP_BACKUPS}"
AUTO_RECOVER="${ALERT_STORE_AUTO_RECOVER:-0}"
SQLITE_BUSY_TIMEOUT_MS="${ALERT_STORE_SQLITE_BUSY_TIMEOUT_MS:-60000}"
BACKUP_ATTEMPTS="${ALERT_STORE_BACKUP_ATTEMPTS:-5}"
ENV_FILE="${ALERT_STORE_ENV_FILE:-$STACK_DIR/.env}"
TELEGRAM_SENDER="$STACK_DIR/bin/send-telegram-notification.py"
SNAPSHOT_TOOL="$STACK_DIR/bin/recovery_snapshot.py"
STATE_FILE="$LOG_DIR/alert-store-sqlite-maintenance-state.json"
REFRESH_GROUPS_URL="${ALERT_STORE_REFRESH_GROUPS_URL:-http://127.0.0.1:8787/refresh-groups}"
REFRESH_GROUPS_TIMEOUT="${ALERT_STORE_REFRESH_GROUPS_TIMEOUT:-60}"
STAMP="$(date '+%Y%m%dT%H%M%S%z')"
LOG_FILE="$LOG_DIR/alert-store-sqlite-maintenance.log"
WEB_MAINTENANCE_HOLD="$LOG_DIR/onion-sentinel-web-maintenance.hold"
RECOVERY_RUNTIME_STOPPED=0
BACKUP_PLAINTEXT=""

[[ "$SQLITE_BUSY_TIMEOUT_MS" == <-> ]] || SQLITE_BUSY_TIMEOUT_MS=60000
[[ "$BACKUP_ATTEMPTS" == <-> ]] || BACKUP_ATTEMPTS=5
(( BACKUP_ATTEMPTS >= 1 )) || BACKUP_ATTEMPTS=5

mkdir -p "$LOG_DIR"

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

secure_regular_file() {
  local candidate="$1"
  if [[ -L "$candidate" || ! -f "$candidate" ]]; then
    fail "refusing to secure a non-regular backup artifact: $candidate"
  fi
  chmod -N "$candidate" || fail "could not remove backup artifact ACL: $candidate"
  chmod 0600 "$candidate" || fail "could not secure backup artifact: $candidate"
}

cleanup_backup_plaintext() {
  local original_status=$?
  if [[ -n "$BACKUP_PLAINTEXT" ]]; then
    rm -f "$BACKUP_PLAINTEXT"
    BACKUP_PLAINTEXT=""
  fi
  return "$original_status"
}

trap 'cleanup_backup_plaintext' EXIT
trap 'cleanup_backup_plaintext; exit 130' INT
trap 'cleanup_backup_plaintext; exit 143' TERM

prepare_backup_directory() {
  if [[ -L "$BACKUP_DIR" ]]; then
    fail "alert-store backup directory must not be a symbolic link: $BACKUP_DIR"
  fi
  mkdir -p "$BACKUP_DIR" || fail "could not create alert-store backup directory: $BACKUP_DIR"
  if [[ ! -d "$BACKUP_DIR" || -L "$BACKUP_DIR" ]]; then
    fail "alert-store backup path must be a real directory: $BACKUP_DIR"
  fi
  chmod -N "$BACKUP_DIR" || fail "could not remove alert-store backup directory ACL"
  chmod 0700 "$BACKUP_DIR" || fail "could not secure alert-store backup directory"
  # Retained recovery material predates this permission contract on some hosts.
  # Normalize only direct regular files and never follow a symlink out of the
  # owner-only directory.
  find -P "$BACKUP_DIR" -maxdepth 1 -type f -exec chmod -N {} + -exec chmod 0600 {} + \
    || fail "could not secure retained alert-store backup artifacts"
  # Interrupted or lock-failed runs can leave an empty temporary target. Never
  # touch a current run, but remove stale partials before evaluating retention.
  find -P "$BACKUP_DIR" -maxdepth 1 -type f -name '*.backup.tmp' -mmin +30 -delete 2>/dev/null || true
  find -P "$BACKUP_DIR" -maxdepth 1 -type f -name '.alerts.sqlite3.*.backup.*.tmp' -mmin +30 -delete 2>/dev/null || true
  find -P "$BACKUP_DIR" -maxdepth 1 -type f -name 'alerts.sqlite3.*.backup.enc' -mmin +30 -print0 \
    | while IFS= read -r -d '' encrypted; do
        [[ -f "${encrypted%.enc}.json" && ! -L "${encrypted%.enc}.json" ]] \
          || rm -f "$encrypted"
      done
  find -P "$BACKUP_DIR" -maxdepth 1 -type f -name 'alerts.sqlite3.*.backup.json' -mmin +30 -print0 \
    | while IFS= read -r -d '' metadata; do
        [[ -f "${metadata%.json}.enc" && ! -L "${metadata%.json}.enc" ]] \
          || rm -f "$metadata"
      done
}

require_sqlite() {
  if ! command -v sqlite3 >/dev/null 2>&1; then
    fail "sqlite3 is not installed or not in PATH"
  fi
}

require_snapshot_tool() {
  if [[ -L "$SNAPSHOT_TOOL" || ! -f "$SNAPSHOT_TOOL" ]]; then
    fail "authenticated recovery snapshot tool is unavailable"
  fi
  local admitted
  admitted="$(find -P "$SNAPSHOT_TOOL" -prune -type f -user "$(id -un)" ! -perm -022 -print)"
  if [[ "$admitted" != "$SNAPSHOT_TOOL" ]]; then
    fail "authenticated recovery snapshot tool is not trusted"
  fi
}

quick_check() {
  local db="$1"
  sqlite3 -cmd ".timeout $SQLITE_BUSY_TIMEOUT_MS" "$db" 'PRAGMA quick_check;' 2>&1
}

verified_backup() {
  local backup_tmp="$BACKUP_DIR/alerts.sqlite3.$STAMP.backup.tmp"
  local backup="$BACKUP_DIR/alerts.sqlite3.$STAMP.backup.enc"
  local metadata="$BACKUP_DIR/alerts.sqlite3.$STAMP.backup.json"
  local attempt=1
  local backup_error=""
  rm -f "$backup_tmp"
  BACKUP_PLAINTEXT="$backup_tmp"
  while (( attempt <= BACKUP_ATTEMPTS )); do
    if backup_error="$(sqlite3 -cmd ".timeout $SQLITE_BUSY_TIMEOUT_MS" "$DB_PATH" ".backup '$backup_tmp'" 2>&1)"; then
      secure_regular_file "$backup_tmp"
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
    BACKUP_PLAINTEXT=""
    fail "backup failed quick_check: $backup_check"
  fi
  local snapshot_error
  if ! snapshot_error="$("$SNAPSHOT_TOOL" create \
      --source "$backup_tmp" --artifact "$backup" --metadata "$metadata" 2>&1)"; then
    fail "authenticated backup publication failed: $snapshot_error"
  fi
  rm -f "$backup_tmp"
  BACKUP_PLAINTEXT=""
  secure_regular_file "$backup"
  secure_regular_file "$metadata"
  log "backup_ok path=$backup"
}

encrypt_retained_plaintext_backups() {
  find -P "$BACKUP_DIR" -maxdepth 1 -type f -name 'alerts.sqlite3.*.backup' -print0 \
    | while IFS= read -r -d '' plaintext; do
        local encrypted="${plaintext}.enc"
        local metadata="${plaintext}.json"
        local check
        local check_failed=0
        if ! check="$(quick_check "$plaintext")"; then
          check_failed=1
        elif [[ "$check" != "ok" ]]; then
          check_failed=1
        fi
        local snapshot_error
        if ! snapshot_error="$("$SNAPSHOT_TOOL" create \
            --source "$plaintext" --artifact "$encrypted" --metadata "$metadata" 2>&1)"; then
          fail "retained backup encryption failed: $snapshot_error"
        fi
        rm -f "$plaintext"
        secure_regular_file "$encrypted"
        secure_regular_file "$metadata"
        log "retained_backup_encrypted path=$encrypted"
        (( check_failed == 0 )) || fail "retained backup failed quick_check"
      done
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
  secure_regular_file "$corrupt_copy"
  sqlite3 "$DB_PATH" '.recover' > "$sql_file" 2> "$err_file" || true
  sqlite3 "$recovered" < "$sql_file"
  secure_regular_file "$sql_file"
  secure_regular_file "$err_file"
  secure_regular_file "$recovered"
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
    secure_regular_file "$BACKUP_DIR/alerts.sqlite3.$STAMP.malformed-swapped-out"
    cp -p "$recovered" "$DB_PATH"
    secure_regular_file "$DB_PATH"
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
    keep="$DEFAULT_KEEP_BACKUPS"
  fi
  find "$BACKUP_DIR" -maxdepth 1 -type f -name 'alerts.sqlite3.*.backup.json' -print0 \
    | xargs -0 ls -t 2>/dev/null \
    | tail -n "+$((keep + 1))" \
    | while IFS= read -r old_metadata; do
        local encrypted="${old_metadata%.json}.enc"
        rm -f "$old_metadata" "$encrypted"
        log "pruned_backup path=$encrypted"
      done
}

main() {
  prepare_backup_directory
  require_sqlite
  require_snapshot_tool
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

  encrypt_retained_plaintext_backups
  verified_backup
  prune_backups
  mark_ok "quick_check=ok summary_consistency=ok"
  log "maintenance_complete quick_check=ok"
}

main "$@"
