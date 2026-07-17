#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCHEMA="$ROOT_DIR/n8n/postgres/alert-store-queue-schema.sql"
IMAGE="${POSTGRES_TEST_IMAGE:-postgres@sha256:e53683f43dd931aeacaef349422caf1f6259389ca5eab0c11763fcb8d38f26af}"
DOCKER="${DOCKER_BIN:-}"
if [[ -z "$DOCKER" ]]; then
  for candidate in /usr/local/bin/docker /opt/homebrew/bin/docker "$(command -v docker 2>/dev/null || true)"; do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
      DOCKER="$candidate"
      break
    fi
  done
fi
[[ -n "$DOCKER" && -x "$DOCKER" ]] || { echo "docker not found" >&2; exit 2; }
[[ -f "$SCHEMA" ]] || { echo "queue schema missing: $SCHEMA" >&2; exit 2; }

CONTAINER="onion-sentinel-queue-schema-$$"
cleanup() {
  "$DOCKER" rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# This qualification database has no network and no mounted live data. Its
# placeholder credential exists only for the disposable container lifetime.
"$DOCKER" run -d --rm --network none \
  --name "$CONTAINER" \
  -e POSTGRES_DB=queue_test \
  -e POSTGRES_USER=queue_test \
  -e POSTGRES_PASSWORD=disposable-schema-test \
  "$IMAGE" >/dev/null

ready_streak=0
for _ in {1..60}; do
  # A new PostgreSQL data directory briefly accepts connections during its
  # bootstrap server, then restarts into the final server. Require consecutive
  # SQL probes so the qualification cannot race that intentional restart.
  if "$DOCKER" exec "$CONTAINER" psql -Atqc "SELECT 1" -U queue_test -d queue_test \
      2>/dev/null | grep -qx '1'; then
    ready_streak=$((ready_streak + 1))
    if [[ "$ready_streak" -ge 2 ]]; then
      break
    fi
  else
    ready_streak=0
  fi
  sleep 1
done
[[ "$ready_streak" -ge 2 ]] || { echo "disposable PostgreSQL did not become ready" >&2; exit 1; }

"$DOCKER" exec -i "$CONTAINER" psql -v ON_ERROR_STOP=1 -U queue_test -d queue_test < "$SCHEMA" >/dev/null

job_id="$("$DOCKER" exec "$CONTAINER" psql -At -U queue_test -d queue_test -c \
  "SELECT onion_sentinel_queue.enqueue_durable_job('ai_analysis','synthetic-group','{\"source\":\"schema-test\"}'::jsonb,40,8);")"
[[ "$job_id" == <-> ]] || { echo "enqueue did not return a job id" >&2; exit 1; }

claimed="$("$DOCKER" exec "$CONTAINER" psql -At -U queue_test -d queue_test -c \
  "SELECT status FROM onion_sentinel_queue.claim_durable_job('ai_analysis',300);")"
[[ "$claimed" == "processing" ]] || { echo "claim did not atomically transition to processing" >&2; exit 1; }

# Enqueue during processing must retain the active lease and latch one rerun.
"$DOCKER" exec "$CONTAINER" psql -At -U queue_test -d queue_test -c \
  "SELECT onion_sentinel_queue.enqueue_durable_job('ai_analysis','synthetic-group','{\"source\":\"new-evidence\"}'::jsonb,50,8);" >/dev/null
latched="$("$DOCKER" exec "$CONTAINER" psql -At -U queue_test -d queue_test -c \
  "SELECT status || ':' || rerun_requested::text FROM onion_sentinel_queue.durable_jobs WHERE id=$job_id;")"
[[ "$latched" == "processing:true" ]] || { echo "active-job rerun was not latched" >&2; exit 1; }

completed="$("$DOCKER" exec "$CONTAINER" psql -At -U queue_test -d queue_test -c \
  "SELECT onion_sentinel_queue.complete_durable_job($job_id);")"
[[ "$completed" == "pending" ]] || { echo "completion did not preserve the coalesced rerun" >&2; exit 1; }

echo "PostgreSQL durable queue schema qualification passed"
