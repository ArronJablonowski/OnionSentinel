#!/bin/zsh
set -euo pipefail
umask 077

# LaunchAgent runs this at login and every few minutes. Its job is idempotent:
# wait for Docker Desktop, then make sure the compose stack is up.
STACK_DIR="$HOME/n8n-local"
LOG_DIR="$STACK_DIR/logs"
DOCKER="/usr/local/bin/docker"
LOG_FILE="$LOG_DIR/ensure-n8n-stack-$(date -u +%Y%m%d-%H%M%SZ).log"
MAX_LOG_BYTES=10485760

mkdir -p "$LOG_DIR"

finalize_log() {
  local original_status=$?
  local size
  local temporary
  trap - EXIT
  set +e
  if [[ -f "$LOG_FILE" && ! -L "$LOG_FILE" ]]; then
    size="$(/usr/bin/stat -f '%z' "$LOG_FILE" 2>/dev/null)"
    if [[ "$size" == <-> && "$size" -gt "$MAX_LOG_BYTES" ]]; then
      temporary="$LOG_FILE.$$.tmp"
      if /usr/bin/tail -c "$MAX_LOG_BYTES" "$LOG_FILE" >"$temporary" \
        && /bin/chmod 0600 "$temporary"; then
        /bin/mv -f "$temporary" "$LOG_FILE"
      else
        /bin/rm -f "$temporary"
      fi
    fi
  fi
  /usr/bin/find "$LOG_DIR" -name 'ensure-n8n-stack-*.log' -type f -mtime +30 -delete
  exit "$original_status"
}

trap finalize_log EXIT

{
  echo "started_at=$(date -u '+%Y-%m-%d  %H:%M:%SZ')"
  echo "stack_dir=$STACK_DIR"

  # Docker Desktop often starts after launchd jobs. Wait up to five minutes
  # rather than failing immediately during Mac reboot/login.
  for attempt in {1..60}; do
    if "$DOCKER" info >/dev/null 2>&1; then
      echo "docker_ready_attempt=$attempt"
      break
    fi
    if [[ "$attempt" -eq 60 ]]; then
      echo "docker_not_ready_after_seconds=300"
      exit 1
    fi
    sleep 5
  done

  cd "$STACK_DIR"
  # compose up -d is safe to repeat; it starts missing containers and leaves
  # healthy running containers alone.
  "$DOCKER" compose up -d
  "$DOCKER" compose ps
  echo "finished_at=$(date -u '+%Y-%m-%d  %H:%M:%SZ')"
} >>"$LOG_FILE" 2>&1
