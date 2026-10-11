# Sourced by install-macstudio-stack.zsh; retain the caller shell and traps.
start_ai_deployment_guard() {
  mkdir -p "$STACK_DIR/run"
  AI_DEPLOYMENT_GUARD_DIR="$(/usr/bin/mktemp -d "$STACK_DIR/run/.deployment-ai-guard.XXXXXX")"
  chmod 0700 "$AI_DEPLOYMENT_GUARD_DIR"
  /usr/bin/python3 - \
    "$STACK_DIR/run/ai-analysis-ollama-worker.lock" \
    "$STACK_DIR/run/ai-analysis-cli-worker.lock" \
    "$AI_DEPLOYMENT_GUARD_DIR/status" <<'PY' &
import fcntl
from pathlib import Path
import signal
import sys
import time

lock_paths = [Path(value) for value in sys.argv[1:3]]
status_path = Path(sys.argv[3])
handles = []


def raise_exit():
    raise SystemExit(0)


try:
    for lock_path in lock_paths:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = lock_path.open("a+")
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            status_path.write_text("busy\n", encoding="utf-8")
            raise SystemExit(3)
        handles.append(handle)
    status_path.write_text("ready\n", encoding="utf-8")
    signal.signal(signal.SIGTERM, lambda *_: raise_exit())
    signal.signal(signal.SIGINT, lambda *_: raise_exit())
    while True:
        time.sleep(60)
finally:
    for handle in reversed(handles):
        fcntl.flock(handle, fcntl.LOCK_UN)
        handle.close()
PY
  AI_DEPLOYMENT_GUARD_PID=$!
  local guard_status=""
  for attempt in {1..50}; do
    if [[ -f "$AI_DEPLOYMENT_GUARD_DIR/status" ]]; then
      guard_status="$(<"$AI_DEPLOYMENT_GUARD_DIR/status")"
      break
    fi
    if ! kill -0 "$AI_DEPLOYMENT_GUARD_PID" >/dev/null 2>&1; then
      break
    fi
    /bin/sleep 0.1
  done
  if [[ "$guard_status" != "ready" ]]; then
    kill -TERM "$AI_DEPLOYMENT_GUARD_PID" >/dev/null 2>&1 || true
    wait "$AI_DEPLOYMENT_GUARD_PID" >/dev/null 2>&1 || true
    /bin/rm -f "$AI_DEPLOYMENT_GUARD_DIR/status"
    /bin/rmdir "$AI_DEPLOYMENT_GUARD_DIR" >/dev/null 2>&1 || true
    AI_DEPLOYMENT_GUARD_PID=""
    AI_DEPLOYMENT_GUARD_DIR=""
    echo "Refusing install: an Onion Sentinel AI investigation is active; retry after it completes." >&2
    return 1
  fi
}

release_ai_deployment_guard() {
  if [[ -n "$AI_DEPLOYMENT_GUARD_PID" ]]; then
    kill -TERM "$AI_DEPLOYMENT_GUARD_PID" >/dev/null 2>&1 || true
    wait "$AI_DEPLOYMENT_GUARD_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$AI_DEPLOYMENT_GUARD_DIR" ]]; then
    /bin/rm -f "$AI_DEPLOYMENT_GUARD_DIR/status"
    /bin/rmdir "$AI_DEPLOYMENT_GUARD_DIR" >/dev/null 2>&1 || true
  fi
  AI_DEPLOYMENT_GUARD_PID=""
  AI_DEPLOYMENT_GUARD_DIR=""
}

wait_for_harness_maintenance_readiness() {
  local report_path="$STACK_DIR/logs/harness-maintenance-deploy-preflight.json"
  local exit_code=2
  local attempt
  for attempt in {1..30}; do
    if /usr/bin/python3 \
      "$STACK_DIR/bin/maintain-investigation-harness.py" \
      --stack-dir "$STACK_DIR" \
      --report "$report_path" >/dev/null
    then
      exit_code=0
    else
      exit_code=$?
    fi
    # Exit 1 means the bounded dry run found additional maintenance work. The
    # databases and query contract are ready, so RunAtLoad may safely apply it.
    if (( exit_code == 0 || exit_code == 1 )); then
      return 0
    fi
    if (( attempt < 30 )); then
      /bin/sleep 1
    fi
  done
  echo "Harness maintenance did not become database-ready (last exit $exit_code)." >&2
  return 1
}

