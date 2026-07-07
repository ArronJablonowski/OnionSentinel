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
STAMP="$(date '+%Y%m%dT%H%M%S%z')"
LOG_FILE="$LOG_DIR/alert-store-sqlite-maintenance.log"

mkdir -p "$BACKUP_DIR" "$LOG_DIR"

log() {
  print -r -- "[$(date '+%Y-%m-%d  %H:%M:%S%z')] $*" | tee -a "$LOG_FILE"
}

require_sqlite() {
  if ! command -v sqlite3 >/dev/null 2>&1; then
    log "ERROR sqlite3 is not installed or not in PATH"
    exit 1
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
    log "ERROR backup failed quick_check: $backup_check"
    rm -f "$backup_tmp"
    exit 1
  fi
  mv "$backup_tmp" "$backup"
  log "backup_ok path=$backup"
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
    log "ERROR recovered candidate failed quick_check: $recovered_check"
    log "corrupt_copy=$corrupt_copy recover_sql=$sql_file recover_err=$err_file"
    exit 2
  fi
  log "recovered_candidate_ok path=$recovered corrupt_copy=$corrupt_copy recover_err=$err_file"

  if [[ "$AUTO_RECOVER" == "1" ]]; then
    log "AUTO_RECOVER enabled; stopping alert-store and swapping recovered DB"
    (cd "$STACK_DIR" && /usr/local/bin/docker compose stop alert-store >/dev/null)
    mv "$DB_PATH" "$BACKUP_DIR/alerts.sqlite3.$STAMP.malformed-swapped-out"
    cp -p "$recovered" "$DB_PATH"
    rm -f "$DB_PATH-wal" "$DB_PATH-shm"
    (cd "$STACK_DIR" && /usr/local/bin/docker compose up -d alert-store >/dev/null)
    log "auto_recover_swap_complete"
  else
    log "AUTO_RECOVER disabled; leaving live DB unchanged"
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
    log "ERROR DB not found: $DB_PATH"
    exit 1
  fi

  log "maintenance_start db=$DB_PATH"
  local check
  check="$(quick_check "$DB_PATH")"
  if [[ "$check" != "ok" ]]; then
    log "ERROR live DB failed quick_check: $check"
    recover_candidate
  fi

  verified_backup
  prune_backups
  log "maintenance_complete quick_check=ok"
}

main "$@"
