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
AI_DEPLOYMENT_GUARD_PID=""
AI_DEPLOYMENT_GUARD_DIR=""
ALERT_STORE_STAGE_DIR=""

# Every deployed runtime must carry the exact code release that produced its
# reports and reanalysis ledger. A commit-less disaster recovery is allowed
# only through the explicit, auditable escape hatch below.
RUNTIME_RELEASE_ID="${ONION_SENTINEL_RELEASE_ID:-}"
if [[ -z "$RUNTIME_RELEASE_ID" ]]; then
  if [[ "${ALLOW_UNVERSIONED_RECOVERY:-0}" != "1" ]]; then
    echo "Refusing install: set ONION_SENTINEL_RELEASE_ID to the exact tested release." >&2
    echo "For commit-less disaster recovery only, set ALLOW_UNVERSIONED_RECOVERY=1." >&2
    exit 2
  fi
  RUNTIME_RELEASE_ID="unversioned"
  echo "WARNING: installing an unversioned disaster-recovery runtime; redeploy an exact release as soon as possible." >&2
fi
/usr/bin/python3 "$REPO_DIR/n8n/bin/set-runtime-release-id.py" \
  --release-id "$RUNTIME_RELEASE_ID" \
  --validate-only

cleanup_alert_store_stage() {
  if [[ -n "$ALERT_STORE_STAGE_DIR" ]]; then
    case "$ALERT_STORE_STAGE_DIR" in
      "$STACK_DIR"/run/.alert-store-stage.*)
        /bin/rm -rf -- "$ALERT_STORE_STAGE_DIR"
        ;;
      *)
        echo "Refusing unsafe alert-store stage cleanup path." >&2
        return 1
        ;;
    esac
  fi
  ALERT_STORE_STAGE_DIR=""
}

prepare_alert_store_stage() {
  mkdir -p "$STACK_DIR/run"
  chmod 0700 "$STACK_DIR/run"
  ALERT_STORE_STAGE_DIR="$(
    /usr/bin/mktemp -d "$STACK_DIR/run/.alert-store-stage.XXXXXX"
  )"
  chmod 0700 "$ALERT_STORE_STAGE_DIR"
  local tree
  for tree in lib routes services repositories jobs composition; do
    local source="$REPO_DIR/n8n/alert_store/$tree"
    [[ -d "$source" ]] || continue
    if [[ -n "$(find "$source" ! -type d ! -type f -print -quit)" ]]; then
      echo "Refusing alert-store $tree tree with a non-regular entry." >&2
      return 1
    fi
    cp -R "$source" "$ALERT_STORE_STAGE_DIR/$tree"
  done
  for tree in lib routes services composition; do
    if [[ ! -d "$ALERT_STORE_STAGE_DIR/$tree" ]]; then
      echo "Refusing incomplete staged alert-store module tree: $tree" >&2
      return 1
    fi
  done
  local source_file
  while IFS= read -r source_file; do
    /opt/homebrew/bin/node --check "$source_file" >/dev/null
  done < <(find "$ALERT_STORE_STAGE_DIR" -type f -name '*.js' -print | sort)
  /opt/homebrew/bin/node -e '
    for (const modulePath of process.argv.slice(1)) require(modulePath);
  ' \
    "$ALERT_STORE_STAGE_DIR/lib/route_registry.js" \
    "$ALERT_STORE_STAGE_DIR/lib/http_dispatch.js" \
    "$ALERT_STORE_STAGE_DIR/lib/scoring_policy.js" \
    "$ALERT_STORE_STAGE_DIR/lib/indicator_extraction.js" \
    "$ALERT_STORE_STAGE_DIR/lib/analyst_review_policy.js" \
    "$ALERT_STORE_STAGE_DIR/lib/enrichment_policy.js" \
    "$ALERT_STORE_STAGE_DIR/lib/controlled_job_identity.js" \
    "$ALERT_STORE_STAGE_DIR/lib/controlled_retirement_identity.js" \
    "$ALERT_STORE_STAGE_DIR/lib/controlled_retirement_projections.js" \
    "$ALERT_STORE_STAGE_DIR/lib/manual_dispatch_identity.js" \
    "$ALERT_STORE_STAGE_DIR/lib/controlled_evaluation_schema.js" \
    "$ALERT_STORE_STAGE_DIR/lib/pcap_policy.js" \
    "$ALERT_STORE_STAGE_DIR/lib/request_authorization.js" \
    "$ALERT_STORE_STAGE_DIR/lib/project_serialization.js" \
    "$ALERT_STORE_STAGE_DIR/lib/runtime_configuration.js" \
    "$ALERT_STORE_STAGE_DIR/lib/scoring_rules_runtime.js" \
    "$ALERT_STORE_STAGE_DIR/lib/alert_value_normalization.js" \
    "$ALERT_STORE_STAGE_DIR/repositories/health_repository.js" \
    "$ALERT_STORE_STAGE_DIR/repositories/ai_correlation_repository.js" \
    "$ALERT_STORE_STAGE_DIR/repositories/ai_review_repository.js" \
    "$ALERT_STORE_STAGE_DIR/repositories/pcap_request_repository.js" \
    "$ALERT_STORE_STAGE_DIR/repositories/pcap_transfer_repository.js" \
    "$ALERT_STORE_STAGE_DIR/routes/inventory_routes.js" \
    "$ALERT_STORE_STAGE_DIR/services/ai_analysis_acceptance.js" \
    "$ALERT_STORE_STAGE_DIR/services/controlled_job_transition.js" \
    "$ALERT_STORE_STAGE_DIR/services/controlled_result_admission.js" \
    "$ALERT_STORE_STAGE_DIR/services/alert_store_schema_foundation.js" \
    "$ALERT_STORE_STAGE_DIR/services/incident_analysis_schema.js" \
    "$ALERT_STORE_STAGE_DIR/services/ai_review_schema.js" \
    "$ALERT_STORE_STAGE_DIR/services/notification_enrichment_schema.js" \
    "$ALERT_STORE_STAGE_DIR/services/pcap_schema.js" \
    "$ALERT_STORE_STAGE_DIR/services/startup_persistence_orchestrator.js" \
    "$ALERT_STORE_STAGE_DIR/services/authorized_campaign_persistence.js" \
    "$ALERT_STORE_STAGE_DIR/services/analyst_review_projection.js" \
    "$ALERT_STORE_STAGE_DIR/services/analyst_decision_persistence.js" \
    "$ALERT_STORE_STAGE_DIR/services/alert_ingest_orchestrator.js" \
    "$ALERT_STORE_STAGE_DIR/services/post_commit_payload.js" \
    "$ALERT_STORE_STAGE_DIR/services/alert_persistence.js" \
    "$ALERT_STORE_STAGE_DIR/services/suppression_persistence.js" \
    "$ALERT_STORE_STAGE_DIR/services/rescore_persistence.js" \
    "$ALERT_STORE_STAGE_DIR/services/automatic_response_routing.js" \
    "$ALERT_STORE_STAGE_DIR/services/manual_analysis_dispatch.js" \
    "$ALERT_STORE_STAGE_DIR/services/durable_background_drains.js" \
    "$ALERT_STORE_STAGE_DIR/services/service_runtime_lifecycle.js" \
    "$ALERT_STORE_STAGE_DIR/services/http_request_boundary.js" \
    "$ALERT_STORE_STAGE_DIR/services/disk_write_admission.js" \
    "$ALERT_STORE_STAGE_DIR/services/worker_wake_signaling.js" \
    "$ALERT_STORE_STAGE_DIR/services/beacon_persistence.js" \
    "$ALERT_STORE_STAGE_DIR/services/postgres_auxiliary_store_runtime.js" \
    "$ALERT_STORE_STAGE_DIR/services/sqlite_runtime.js" \
    "$ALERT_STORE_STAGE_DIR/services/durable_job_recovery.js" \
    "$ALERT_STORE_STAGE_DIR/services/durable_job_transition_executor.js" \
    "$ALERT_STORE_STAGE_DIR/services/controlled_retirement_completed_member.js" \
    "$ALERT_STORE_STAGE_DIR/services/controlled_retirement_target_member.js" \
    "$ALERT_STORE_STAGE_DIR/services/controlled_retirement_census.js" \
    "$ALERT_STORE_STAGE_DIR/services/controlled_retirement_replay.js" \
    "$ALERT_STORE_STAGE_DIR/services/controlled_retirement_command.js" \
    "$ALERT_STORE_STAGE_DIR/services/alert_group_alias_resolution.js" \
    "$ALERT_STORE_STAGE_DIR/services/incident_durable_job_persistence.js" \
    "$ALERT_STORE_STAGE_DIR/services/incident_reanalysis_frozen_dispatch.js" \
    "$ALERT_STORE_STAGE_DIR/services/incident_reanalysis_request.js" \
    "$ALERT_STORE_STAGE_DIR/services/incident_reanalysis_job_ownership.js" \
    "$ALERT_STORE_STAGE_DIR/services/incident_reanalysis_attempt_lifecycle.js" \
    "$ALERT_STORE_STAGE_DIR/services/incident_reanalysis_recovery.js" \
    "$ALERT_STORE_STAGE_DIR/services/incident_reanalysis_run_persistence.js" \
    "$ALERT_STORE_STAGE_DIR/services/incident_analysis_completion.js" \
    "$ALERT_STORE_STAGE_DIR/services/incident_reanalysis_binding.js" \
    "$ALERT_STORE_STAGE_DIR/routes/health_routes.js" \
    "$ALERT_STORE_STAGE_DIR/routes/analyst_state_routes.js" \
    "$ALERT_STORE_STAGE_DIR/routes/durable_job_routes.js" \
    "$ALERT_STORE_STAGE_DIR/routes/analysis_request_routes.js" \
    "$ALERT_STORE_STAGE_DIR/routes/analysis_result_routes.js" \
    "$ALERT_STORE_STAGE_DIR/routes/pcap_routes.js" \
    "$ALERT_STORE_STAGE_DIR/routes/enrichment_routes.js" \
    "$ALERT_STORE_STAGE_DIR/routes/maintenance_routes.js" \
    "$ALERT_STORE_STAGE_DIR/routes/alert_ingest_routes.js" \
    "$ALERT_STORE_STAGE_DIR/services/inventory_service.js" \
    "$ALERT_STORE_STAGE_DIR/services/health_service.js" \
    "$ALERT_STORE_STAGE_DIR/services/analyst_state_service.js" \
    "$ALERT_STORE_STAGE_DIR/services/durable_job_service.js" \
    "$ALERT_STORE_STAGE_DIR/services/analysis_request_service.js" \
    "$ALERT_STORE_STAGE_DIR/services/analysis_result_service.js" \
    "$ALERT_STORE_STAGE_DIR/services/pcap_analysis_completion.js" \
    "$ALERT_STORE_STAGE_DIR/services/pcap_service.js" \
    "$ALERT_STORE_STAGE_DIR/services/enrichment_service.js" \
    "$ALERT_STORE_STAGE_DIR/services/alert_ingest_service.js" \
    "$ALERT_STORE_STAGE_DIR/services/notification_service.js" \
    "$ALERT_STORE_STAGE_DIR/services/alert_group_service.js" \
    "$ALERT_STORE_STAGE_DIR/services/enrichment_provider_client.js" \
    "$ALERT_STORE_STAGE_DIR/services/enrichment_orchestrator.js" \
    "$ALERT_STORE_STAGE_DIR/composition/application_composition.js" \
    "$ALERT_STORE_STAGE_DIR/composition/application_graph_runtime.js" \
    "$ALERT_STORE_STAGE_DIR/composition/application_runtime_ports.js" \
    "$ALERT_STORE_STAGE_DIR/composition/controlled_incident_composition.js" \
    "$ALERT_STORE_STAGE_DIR/composition/evidence_processing_composition.js" \
    "$ALERT_STORE_STAGE_DIR/composition/http_application_runtime.js" \
    "$ALERT_STORE_STAGE_DIR/composition/mutable_runtime_owners.js" \
    "$ALERT_STORE_STAGE_DIR/composition/runtime_foundation_composition.js" \
    "$ALERT_STORE_STAGE_DIR/composition/startup_persistence_compatibility.js" \
    "$ALERT_STORE_STAGE_DIR/composition/route_composition.js"
}

validate_production_python_sources() {
  PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -B - \
    "$REPO_DIR/n8n/bin" \
    "$REPO_DIR/onion-sentinel-dashboard" <<'PY'
import importlib.util
from pathlib import Path
import sys

bin_dir = Path(sys.argv[1])
dashboard_dir = Path(sys.argv[2])
sys.path.insert(0, str(bin_dir))

import agent_memory
import bounded_process
import harness_maintenance_cli
import pcap_evidence_query


def load_file(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("production Python validation could not create a loader")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


load_file(
    "_onion_sentinel_software_inventory_collector",
    bin_dir / "collect-software-inventory.py",
)
load_file(
    "_onion_sentinel_harness_maintenance",
    bin_dir / "maintain-investigation-harness.py",
)
load_file(
    "_onion_sentinel_operational_slos",
    bin_dir / "evaluate-operational-slos.py",
)

sys.path.insert(0, str(dashboard_dir))
import onion_sentinel_server

result = bounded_process.run_bounded_command(
    ["/usr/bin/true"],
    timeout_seconds=5,
    max_stdout_bytes=100,
    max_stderr_bytes=100,
)
if result.returncode != 0:
    raise RuntimeError("production Python bounded-process smoke failed")
PY
}

trap cleanup_alert_store_stage EXIT
prepare_alert_store_stage
validate_production_python_sources
if [[ "${ONION_SENTINEL_VALIDATE_ONLY:-0}" == "1" ]]; then
  echo "Mac Studio installer preflight validation passed."
  exit 0
elif [[ "${ONION_SENTINEL_VALIDATE_ONLY:-0}" != "0" ]]; then
  echo "ONION_SENTINEL_VALIDATE_ONLY must be 0 or 1." >&2
  exit 2
fi

# Take the same advisory locks used by both AI scheduler lanes before touching
# launchd or runtime files. A nonblocking failure means an investigation is in
# flight, so leave every service running and ask the operator to retry. Holding
# both locks across the install also closes the check/unload race: WatchPath or
# timer activity cannot start a new inference while code is being replaced.
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

if ! start_ai_deployment_guard; then
  exit 3
fi

# These jobs execute files replaced below. Stop only those code consumers
# before the first runtime copy; unrelated monitoring, PCAP, dashboard, backup,
# and Docker services stay up until their normal final reload phase.
critical_launch_agents_down() {
  local plist
  local label
  for plist in \
    com.arron.soc.alert-store.plist \
    com.arron.soc.ai-analysis.plist \
    com.arron.soc.ai-analysis-cli.plist \
    com.arron.soc.dhcp-asset-discovery.plist \
    com.arron.soc.endpoint-software-inventory.plist \
    com.arron.soc.software-inventory.plist \
    com.arron.soc.ac-hunter.plist
  do
    launchctl unload "$LAUNCHD_DIR/$plist" >/dev/null 2>&1 || true
  done
  for label in \
    com.arron.soc.alert-store \
    com.arron.soc.ai-analysis \
    com.arron.soc.ai-analysis-cli \
    com.arron.soc.dhcp-asset-discovery \
    com.arron.soc.endpoint-software-inventory \
    com.arron.soc.software-inventory \
    com.arron.soc.ac-hunter
  do
    launchctl bootout "gui/$(id -u)/$label" >/dev/null 2>&1 || true
  done
  # A worker can be inside a model subprocess when launchd is unloaded. On
  # macOS that subprocess may be reparented to PID 1 and continue consuming a
  # prompt even though its Python owner and durable lease are gone. Stop only
  # the two exact AI runtime entry points and Codex subprocesses carrying the
  # runner-owned isolated-workspace marker. Durable leases recover interrupted
  # work; allowing old code to finish after a wire-contract cutover would
  # produce an incorrectly attributed analysis.
  local runtime_ai_pids
  local runtime_codex_pids
  runtime_ai_pids="$(
    /bin/ps -axo pid=,command= \
      | /usr/bin/awk \
        -v scheduler="$STACK_DIR/bin/auto-run-ai-analysis.py" \
        -v runner="$STACK_DIR/bin/run-local-ai-analysis.py" \
        '$2 ~ /[Pp]ython/ && (index($0, scheduler) || index($0, runner)) {print $1}'
  )"
  if [[ -n "$runtime_ai_pids" ]]; then
    for pid in ${(f)runtime_ai_pids}; do
      kill -TERM "$pid" >/dev/null 2>&1 || true
    done
  fi
  runtime_codex_pids="$(
    /bin/ps -axo pid=,command= \
      | /usr/bin/awk '
        $2 ~ /(^|\/)codex$/ \
        && index($0, "/onion-sentinel-codex-") \
        && index($0, "codex exec") \
        && index($0, "--ignore-user-config") \
        && index($0, "--ignore-rules") {print $1}'
  )"
  if [[ -n "$runtime_codex_pids" ]]; then
    for pid in ${(f)runtime_codex_pids}; do
      kill -TERM "$pid" >/dev/null 2>&1 || true
    done
  fi
  if [[ -n "$runtime_ai_pids" || -n "$runtime_codex_pids" ]]; then
    for attempt in {1..10}; do
      runtime_ai_pids="$(
        /bin/ps -axo pid=,command= \
          | /usr/bin/awk \
            -v scheduler="$STACK_DIR/bin/auto-run-ai-analysis.py" \
            -v runner="$STACK_DIR/bin/run-local-ai-analysis.py" \
            '$2 ~ /[Pp]ython/ && (index($0, scheduler) || index($0, runner)) {print $1}'
      )"
      runtime_codex_pids="$(
        /bin/ps -axo pid=,command= \
          | /usr/bin/awk '
            $2 ~ /(^|\/)codex$/ \
            && index($0, "/onion-sentinel-codex-") \
            && index($0, "codex exec") \
            && index($0, "--ignore-user-config") \
            && index($0, "--ignore-rules") {print $1}'
      )"
      [[ -z "$runtime_ai_pids" && -z "$runtime_codex_pids" ]] && break
      /bin/sleep 1
    done
  fi
}

critical_launch_agents_are_down() {
  local label
  for label in \
    com.arron.soc.alert-store \
    com.arron.soc.ai-analysis \
    com.arron.soc.ai-analysis-cli \
    com.arron.soc.dhcp-asset-discovery \
    com.arron.soc.endpoint-software-inventory \
    com.arron.soc.software-inventory \
    com.arron.soc.ac-hunter
  do
    if launchctl print "gui/$(id -u)/$label" >/dev/null 2>&1; then
      return 1
    fi
  done
  if /bin/ps -axo pid=,command= \
    | /usr/bin/awk \
      -v scheduler="$STACK_DIR/bin/auto-run-ai-analysis.py" \
      -v runner="$STACK_DIR/bin/run-local-ai-analysis.py" \
      '$2 ~ /[Pp]ython/ && (index($0, scheduler) || index($0, runner)) {found=1} END {exit !found}'
  then
    return 1
  fi
  if /bin/ps -axo pid=,command= \
    | /usr/bin/awk '
      $2 ~ /(^|\/)codex$/ \
      && index($0, "/onion-sentinel-codex-") \
      && index($0, "codex exec") \
      && index($0, "--ignore-user-config") \
      && index($0, "--ignore-rules") {found=1} END {exit !found}'
  then
    return 1
  fi
  return 0
}

keep_critical_agents_down_on_failure() {
  local exit_code=$?
  if (( exit_code != 0 )); then
    critical_launch_agents_down
    echo "Install failed; alert-store and both AI LaunchAgents remain stopped." >&2
    echo "The DHCP asset-discovery LaunchAgent also remains stopped." >&2
    echo "The software-inventory LaunchAgent also remains stopped." >&2
  fi
  release_ai_deployment_guard
  cleanup_alert_store_stage
  return $exit_code
}

trap keep_critical_agents_down_on_failure EXIT
critical_launch_agents_down
for attempt in {1..20}; do
  critical_launch_agents_are_down && break
  /bin/sleep 1
done
if ! critical_launch_agents_are_down; then
  echo "Refusing install: could not stop alert-store and both AI LaunchAgents." >&2
  exit 1
fi

mkdir -p "$STACK_DIR/alert_store/config" "$STACK_DIR/alert_store/lib" "$STACK_DIR/postgres" "$STACK_DIR/bin" "$STACK_DIR/cache" "$STACK_DIR/config" "$STACK_DIR/config/maxmind" "$STACK_DIR/logs" "$STACK_DIR/run" "$STACK_DIR/python" "$STACK_DIR/alert_store_data" "$STACK_DIR/alert_store_postgres_data" "$STACK_DIR/n8n_data" "$STACK_DIR/soc-alerts" "$STACK_DIR/soc-alerts/agent-memory" "$STACK_DIR/soc-alerts/pcap-analysis" "$STACK_DIR/pcap-evidence/artifacts" "$STACK_DIR/asset-discovery" "$STACK_DIR/software-inventory"
chmod 0700 "$STACK_DIR/cache"
chmod 0700 "$STACK_DIR/run"
chmod 0700 "$STACK_DIR/asset-discovery"
chmod 0700 "$STACK_DIR/software-inventory"
chmod 0750 "$STACK_DIR/config/maxmind"
touch "$STACK_DIR/run/ai-analysis-ollama.wake" "$STACK_DIR/run/ai-analysis-cli.wake" "$STACK_DIR/run/pcap-analysis.wake"
chmod 0600 "$STACK_DIR/run/ai-analysis-ollama.wake" "$STACK_DIR/run/ai-analysis-cli.wake" "$STACK_DIR/run/pcap-analysis.wake"

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
for tree in lib routes services repositories jobs composition; do
  if [[ -d "$ALERT_STORE_STAGE_DIR/$tree" ]]; then
    mkdir -p "$STACK_DIR/alert_store/$tree"
    /usr/bin/rsync -a --delete \
      "$ALERT_STORE_STAGE_DIR/$tree/" \
      "$STACK_DIR/alert_store/$tree/"
  fi
done
cp "$REPO_DIR/n8n/alert_store/alert_store.js" "$STACK_DIR/alert_store/alert_store.js"
cp "$REPO_DIR/n8n/alert_store/alert_store_proxy.js" "$STACK_DIR/alert_store/alert_store_proxy.js"
cp "$REPO_DIR/n8n/alert_store/package.json" "$STACK_DIR/alert_store/package.json"
cp "$REPO_DIR/n8n/alert_store/package-lock.json" "$STACK_DIR/alert_store/package-lock.json"
cp "$REPO_DIR/n8n/alert_store/verify_install_script_policy.js" "$STACK_DIR/alert_store/verify_install_script_policy.js"
cp "$REPO_DIR/n8n/alert_store/review_alerts.js" "$STACK_DIR/alert_store/review_alerts.js"
cp "$REPO_DIR/n8n/alert_store/investigation_notes.js" "$STACK_DIR/alert_store/investigation_notes.js"
cp "$REPO_DIR/n8n/alert_store/lib/provider_scheduler.js" "$STACK_DIR/alert_store/lib/provider_scheduler.js"
cp "$REPO_DIR/n8n/alert_store/lib/durable_job_queue.js" "$STACK_DIR/alert_store/lib/durable_job_queue.js"
cp "$REPO_DIR/n8n/alert_store/lib/postgres_shadow_outbox.js" "$STACK_DIR/alert_store/lib/postgres_shadow_outbox.js"
cp "$REPO_DIR/n8n/alert_store/lib/postgres_shadow_projector.js" "$STACK_DIR/alert_store/lib/postgres_shadow_projector.js"
cp "$REPO_DIR/n8n/alert_store/lib/postgres_asset_store.js" "$STACK_DIR/alert_store/lib/postgres_asset_store.js"
cp "$REPO_DIR/n8n/alert_store/lib/postgres_asset_normalization.js" "$STACK_DIR/alert_store/lib/postgres_asset_normalization.js"
cp "$REPO_DIR/n8n/alert_store/lib/postgres_asset_dhcp_repository.js" "$STACK_DIR/alert_store/lib/postgres_asset_dhcp_repository.js"
cp "$REPO_DIR/n8n/alert_store/lib/postgres_asset_health_projection.js" "$STACK_DIR/alert_store/lib/postgres_asset_health_projection.js"
cp "$REPO_DIR/n8n/alert_store/lib/postgres_asset_inventory_repository.js" "$STACK_DIR/alert_store/lib/postgres_asset_inventory_repository.js"
cp "$REPO_DIR/n8n/alert_store/lib/postgres_asset_read_projection.js" "$STACK_DIR/alert_store/lib/postgres_asset_read_projection.js"
cp "$REPO_DIR/n8n/alert_store/lib/postgres_asset_schema.js" "$STACK_DIR/alert_store/lib/postgres_asset_schema.js"
cp "$REPO_DIR/n8n/alert_store/lib/postgres_software_store.js" "$STACK_DIR/alert_store/lib/postgres_software_store.js"
cp "$REPO_DIR/n8n/alert_store/lib/postgres_ac_hunter_store.js" "$STACK_DIR/alert_store/lib/postgres_ac_hunter_store.js"
cp "$REPO_DIR/n8n/alert_store/lib/security_logger.js" "$STACK_DIR/alert_store/lib/security_logger.js"
cp "$REPO_DIR/n8n/alert_store/lib/http_json_client.js" "$STACK_DIR/alert_store/lib/http_json_client.js"
cp "$REPO_DIR/n8n/alert_store/lib/http_runtime.js" "$STACK_DIR/alert_store/lib/http_runtime.js"
cp "$REPO_DIR/n8n/alert_store/lib/pipeline_metrics.js" "$STACK_DIR/alert_store/lib/pipeline_metrics.js"
cp "$REPO_DIR/n8n/alert_store/lib/group_identity.js" "$STACK_DIR/alert_store/lib/group_identity.js"
cp "$REPO_DIR/n8n/alert_store/lib/correlation_context.js" "$STACK_DIR/alert_store/lib/correlation_context.js"
cp "$REPO_DIR/n8n/alert_store/lib/enrichment_cache.js" "$STACK_DIR/alert_store/lib/enrichment_cache.js"
cp "$REPO_DIR/n8n/alert_store/lib/soc_analysis_policy.js" "$STACK_DIR/alert_store/lib/soc_analysis_policy.js"
cp "$REPO_DIR/n8n/alert_store/lib/authorized_activity_policy.js" "$STACK_DIR/alert_store/lib/authorized_activity_policy.js"
cp "$REPO_DIR/n8n/postgres/alert-store-queue-schema.sql" "$STACK_DIR/postgres/alert-store-queue-schema.sql"
cp "$REPO_DIR/n8n/postgres/asset-inventory-schema.sql" "$STACK_DIR/postgres/asset-inventory-schema.sql"
cp "$REPO_DIR/n8n/postgres/software-inventory-schema.sql" "$STACK_DIR/postgres/software-inventory-schema.sql"
cp "$REPO_DIR/n8n/postgres/ac-hunter-schema.sql" "$STACK_DIR/postgres/ac-hunter-schema.sql"
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
# The bounded adjudicator contract is code-owned safety policy. Unlike the
# role prompts, it is not operator-tunable because relaxing its closed choices
# could accidentally turn shadow review into an automation authority.
install -m 0600 \
  "$REPO_DIR/n8n/config/disagreement_adjudicator_system_prompt.md" \
  "$STACK_DIR/config/disagreement_adjudicator_system_prompt.md"
# Reviewer prompts are operator-editable runtime policy, just like the primary
# prompts. Seed missing files during recovery. Existing files are considered
# for the byte-exact, reviewed baseline upgrades below.
for reviewer_prompt in \
  soc_analyst_second_opinion_prompt.md \
  incident_responder_second_opinion_prompt.md \
  siem_engineer_second_opinion_prompt.md \
  cyber_threat_intel_second_opinion_prompt.md \
  threat_hunter_second_opinion_prompt.md
do
  if [[ ! -f "$STACK_DIR/config/$reviewer_prompt" ]]; then
    cp "$REPO_DIR/n8n/config/$reviewer_prompt" "$STACK_DIR/config/$reviewer_prompt"
  fi
done
# Upgrade each reviewer only when its live file still matches an exact
# previously shipped baseline. Any operator edit changes the digest, so the
# helper preserves that file and reports the decision instead of silently
# overwriting it. Reviewer prompts with multiple shipped baselines retain each
# exact predecessor digest so an unmodified runtime can advance safely.
/usr/bin/python3 "$REPO_DIR/n8n/bin/upgrade-runtime-policy.py" \
  --source "$REPO_DIR/n8n/config/cyber_threat_intel_second_opinion_prompt.md" \
  --destination "$STACK_DIR/config/cyber_threat_intel_second_opinion_prompt.md" \
  --accepted-prior-sha256 "2c0a5093fc6c79d6bb7f40a278a265e2edba91d69e7fa763508f16eaf5f69e44"
/usr/bin/python3 "$REPO_DIR/n8n/bin/upgrade-runtime-policy.py" \
  --source "$REPO_DIR/n8n/config/incident_responder_second_opinion_prompt.md" \
  --destination "$STACK_DIR/config/incident_responder_second_opinion_prompt.md" \
  --accepted-prior-sha256 "c13d5fcd90644db6fcd745fdc5c6ce978ccdd62a3f3e115dfce0aec634f77421" \
  --accepted-prior-sha256 "71400cd9a6826be6b23a2cfa3cdacbada21ff6ef16d0093dac49c13dcf63d646" \
  --accepted-prior-sha256 "eb0ee3c7a4109088036e2447d1693733dea86944b62437ac75140ddf9f688c1f" \
  --accepted-prior-sha256 "3b84b2972bbe7a447e5a981ac63669b538e944c91d0f089715cdcd04414b156e"
/usr/bin/python3 "$REPO_DIR/n8n/bin/upgrade-runtime-policy.py" \
  --source "$REPO_DIR/n8n/config/siem_engineer_second_opinion_prompt.md" \
  --destination "$STACK_DIR/config/siem_engineer_second_opinion_prompt.md" \
  --accepted-prior-sha256 "d2d60b55dd3050d99f42cc62653376c9ed6b1a5e3ad47bd3ea9b2a2f884d0dac"
/usr/bin/python3 "$REPO_DIR/n8n/bin/upgrade-runtime-policy.py" \
  --source "$REPO_DIR/n8n/config/soc_analyst_second_opinion_prompt.md" \
  --destination "$STACK_DIR/config/soc_analyst_second_opinion_prompt.md" \
  --accepted-prior-sha256 "db79fa2ac912b7227e4889626d853eca28a950966b93acd822582b0468dcc5ff" \
  --accepted-prior-sha256 "b979deea89cc1914b81c363563ed245f854660db799e773a52842da6ca2f22e5" \
  --accepted-prior-sha256 "42e45f57ab6a802eaa8e383b7eba82780c2ade58d99e06ef041912fa01ce2af9"
/usr/bin/python3 "$REPO_DIR/n8n/bin/upgrade-runtime-policy.py" \
  --source "$REPO_DIR/n8n/config/threat_hunter_second_opinion_prompt.md" \
  --destination "$STACK_DIR/config/threat_hunter_second_opinion_prompt.md" \
  --accepted-prior-sha256 "15af4c64dfa8fcd5388286250212c24224aeb06716efb7da1e29bd6dd6469017"
if [[ ! -f "$STACK_DIR/config/ai_model_settings.json" ]]; then
  cp "$REPO_DIR/n8n/config/ai_model_settings.json" "$STACK_DIR/config/ai_model_settings.json"
  chmod 0600 "$STACK_DIR/config/ai_model_settings.json"
fi
# The former repository template assigned the Incident Responder reviewer to
# gemma4 and left gpt-5.6-sol disabled at medium effort. Upgrade that complete,
# byte-exact template only. Any settings change, including an operator-selected
# Sol route or effort, changes the digest and is therefore preserved.
/usr/bin/python3 "$REPO_DIR/n8n/bin/upgrade-runtime-policy.py" \
  --source "$REPO_DIR/n8n/config/ai_model_settings.json" \
  --destination "$STACK_DIR/config/ai_model_settings.json" \
  --accepted-prior-sha256 "bafb138cf8d2c216bf9fe37ea92d5b822b9444a108e9ca5de51a09f587983118" \
  --accepted-prior-sha256 "fd9f93123b22c0664d147fdcd012d1c016329566ffaea97cb4bfa7c5d7daaf2b"
# The investigation harness policy is operator-owned runtime policy. Seed the
# checked-in, disabled-by-default baseline only on first install and preserve
# all later operator changes. Refuse a symlink so chmod/copy cannot be redirected
# outside the runtime config directory.
if [[ -L "$STACK_DIR/config/investigation_harness_policy.schema.json" ]] \
  || [[ -e "$STACK_DIR/config/investigation_harness_policy.schema.json" \
    && ! -f "$STACK_DIR/config/investigation_harness_policy.schema.json" ]]; then
  echo "Refusing install: investigation harness policy schema must be a regular file." >&2
  exit 1
fi
cp "$REPO_DIR/n8n/config/investigation_harness_policy.schema.json" \
  "$STACK_DIR/config/investigation_harness_policy.schema.json"
chmod 0644 "$STACK_DIR/config/investigation_harness_policy.schema.json"
if [[ -L "$STACK_DIR/config/investigation_harness_policy.json" ]] \
  || [[ -e "$STACK_DIR/config/investigation_harness_policy.json" \
    && ! -f "$STACK_DIR/config/investigation_harness_policy.json" ]]; then
  echo "Refusing install: investigation harness policy must be a regular file." >&2
  exit 1
fi
if [[ ! -f "$STACK_DIR/config/investigation_harness_policy.json" ]]; then
  cp "$REPO_DIR/n8n/config/investigation_harness_policy.json" \
    "$STACK_DIR/config/investigation_harness_policy.json"
fi
chmod 0600 "$STACK_DIR/config/investigation_harness_policy.json"
cp "$REPO_DIR/n8n/config/detection_playbooks.json" "$STACK_DIR/config/detection_playbooks.json"
for investigation_skill_file in \
  investigation_skills.schema.json \
  investigation_skills.json
do
  if [[ -L "$STACK_DIR/config/$investigation_skill_file" ]] \
    || [[ -e "$STACK_DIR/config/$investigation_skill_file" \
      && ! -f "$STACK_DIR/config/$investigation_skill_file" ]]; then
    echo "Refusing install: $investigation_skill_file must be a regular file." >&2
    exit 1
  fi
done
cp "$REPO_DIR/n8n/config/investigation_skills.schema.json" \
  "$STACK_DIR/config/investigation_skills.schema.json"
cp "$REPO_DIR/n8n/config/investigation_skills.json" \
  "$STACK_DIR/config/investigation_skills.json"
chmod 0644 \
  "$STACK_DIR/config/investigation_skills.schema.json" \
  "$STACK_DIR/config/investigation_skills.json"
if [[ -L "$STACK_DIR/config/authorized_activity_campaigns.json" ]] \
  || [[ -e "$STACK_DIR/config/authorized_activity_campaigns.json" \
    && ! -f "$STACK_DIR/config/authorized_activity_campaigns.json" ]]; then
  echo "Refusing install: authorized activity campaign policy must be a regular file." >&2
  exit 1
fi
if [[ ! -f "$STACK_DIR/config/authorized_activity_campaigns.json" ]]; then
  cp "$REPO_DIR/n8n/config/authorized_activity_campaigns.json" \
    "$STACK_DIR/config/authorized_activity_campaigns.json"
fi
chmod 0600 "$STACK_DIR/config/authorized_activity_campaigns.json"
if [[ ! -f "$STACK_DIR/config/asset_inventory.json" ]]; then
  cp "$REPO_DIR/n8n/config/asset_inventory.example.json" "$STACK_DIR/config/asset_inventory.json"
  chmod 0600 "$STACK_DIR/config/asset_inventory.json"
fi
# Seed the incident-evidence transport with enough time for four sequential
# bounded pivots plus both controls. During upgrades, add the key only when it
# is absent; an operator's existing timeout (including a deliberately lower
# value) is never overwritten.
/usr/bin/python3 - "$HOME" "$REPO_DIR/n8n/config/incident-evidence.example.json" "$STACK_DIR/config/incident-evidence.json" <<'PY'
import json
import os
from pathlib import Path
import sys
import tempfile

home, source_name, destination_name = sys.argv[1:4]
source = Path(source_name)
destination = Path(destination_name)
if not destination.exists():
    destination.write_text(source.read_text().replace("__HOME__", home))
    os.chmod(destination, 0o600)
else:
    try:
        config = json.loads(destination.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"WARNING: leaving invalid incident-evidence config unchanged: {exc}",
            file=sys.stderr,
        )
        raise SystemExit(0)
    if not isinstance(config, dict):
        print(
            "WARNING: leaving non-object incident-evidence config unchanged",
            file=sys.stderr,
        )
        raise SystemExit(0)
    if "timeout_seconds" not in config:
        config["timeout_seconds"] = 420
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            delete=False,
        ) as handle:
            json.dump(config, handle, indent=2)
            handle.write("\n")
            temporary = Path(handle.name)
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
PY
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
cp "$REPO_DIR/n8n/bin/check-onion-sentinel-readiness.py" "$STACK_DIR/bin/check-onion-sentinel-readiness.py"
cp "$REPO_DIR/n8n/bin/send-telegram-notification.py" "$STACK_DIR/bin/send-telegram-notification.py"
cp "$REPO_DIR/n8n/bin/operational_slo_primitives.py" "$STACK_DIR/bin/operational_slo_primitives.py"
cp "$REPO_DIR/n8n/bin/operational_slo_queue_policy.py" "$STACK_DIR/bin/operational_slo_queue_policy.py"
cp "$REPO_DIR/n8n/bin/operational_slo_resilience_policy.py" "$STACK_DIR/bin/operational_slo_resilience_policy.py"
cp "$REPO_DIR/n8n/bin/operational_slo_policy.py" "$STACK_DIR/bin/operational_slo_policy.py"
cp "$REPO_DIR/n8n/bin/operational_slo_state.py" "$STACK_DIR/bin/operational_slo_state.py"
cp "$REPO_DIR/n8n/bin/evaluate-operational-slos.py" "$STACK_DIR/bin/evaluate-operational-slos.py"
cp "$REPO_DIR/n8n/bin/disk_capacity.py" "$STACK_DIR/bin/disk_capacity.py"
cp "$REPO_DIR/n8n/bin/backup-onion-sentinel-runtime.py" "$STACK_DIR/bin/backup-onion-sentinel-runtime.py"
cp "$REPO_DIR/n8n/bin/harness_maintenance_contract.py" "$STACK_DIR/bin/harness_maintenance_contract.py"
cp "$REPO_DIR/n8n/bin/harness_maintenance_integrity.py" "$STACK_DIR/bin/harness_maintenance_integrity.py"
cp "$REPO_DIR/n8n/bin/harness_maintenance_recovery.py" "$STACK_DIR/bin/harness_maintenance_recovery.py"
cp "$REPO_DIR/n8n/bin/harness_maintenance_retention.py" "$STACK_DIR/bin/harness_maintenance_retention.py"
cp "$REPO_DIR/n8n/bin/harness_maintenance_reporting.py" "$STACK_DIR/bin/harness_maintenance_reporting.py"
cp "$REPO_DIR/n8n/bin/harness_maintenance_cli.py" "$STACK_DIR/bin/harness_maintenance_cli.py"
cp "$REPO_DIR/n8n/bin/maintain-investigation-harness.py" "$STACK_DIR/bin/maintain-investigation-harness.py"
cp "$REPO_DIR/n8n/bin/report-production-soak.py" "$STACK_DIR/bin/report-production-soak.py"
cp "$REPO_DIR/n8n/bin/report-harness-observability.py" "$STACK_DIR/bin/report-harness-observability.py"
cp "$REPO_DIR/n8n/bin/run-recovery-restore-drill.py" "$STACK_DIR/bin/run-recovery-restore-drill.py"
cp "$REPO_DIR/n8n/bin/run-alert-store-host.zsh" "$STACK_DIR/bin/run-alert-store-host.zsh"
cp "$REPO_DIR/n8n/bin/maintain-alert-store-sqlite.zsh" "$STACK_DIR/bin/maintain-alert-store-sqlite.zsh"
cp "$REPO_DIR/n8n/bin/detection_validation_rule_contract.py" "$STACK_DIR/bin/detection_validation_rule_contract.py"
cp "$REPO_DIR/n8n/bin/detection_validation_rule_parser.py" "$STACK_DIR/bin/detection_validation_rule_parser.py"
cp "$REPO_DIR/n8n/bin/detection_validation_rule_context.py" "$STACK_DIR/bin/detection_validation_rule_context.py"
cp "$REPO_DIR/n8n/bin/detection_validation_rule_icmp.py" "$STACK_DIR/bin/detection_validation_rule_icmp.py"
cp "$REPO_DIR/n8n/bin/detection_validation_rule.py" "$STACK_DIR/bin/detection_validation_rule.py"
cp "$REPO_DIR/n8n/bin/detection_validation_packet_network.py" "$STACK_DIR/bin/detection_validation_packet_network.py"
cp "$REPO_DIR/n8n/bin/detection_validation_packet_markers.py" "$STACK_DIR/bin/detection_validation_packet_markers.py"
cp "$REPO_DIR/n8n/bin/detection_validation_packet_content.py" "$STACK_DIR/bin/detection_validation_packet_content.py"
cp "$REPO_DIR/n8n/bin/detection_validation_packet_buffers.py" "$STACK_DIR/bin/detection_validation_packet_buffers.py"
cp "$REPO_DIR/n8n/bin/detection_validation_packet.py" "$STACK_DIR/bin/detection_validation_packet.py"
cp "$REPO_DIR/n8n/bin/detection_validation_features_state.py" "$STACK_DIR/bin/detection_validation_features_state.py"
cp "$REPO_DIR/n8n/bin/detection_validation_features_markers.py" "$STACK_DIR/bin/detection_validation_features_markers.py"
cp "$REPO_DIR/n8n/bin/detection_validation_features_observation.py" "$STACK_DIR/bin/detection_validation_features_observation.py"
cp "$REPO_DIR/n8n/bin/detection_validation_features_projection.py" "$STACK_DIR/bin/detection_validation_features_projection.py"
cp "$REPO_DIR/n8n/bin/detection_validation_features_workflow.py" "$STACK_DIR/bin/detection_validation_features_workflow.py"
cp "$REPO_DIR/n8n/bin/detection_validation_features.py" "$STACK_DIR/bin/detection_validation_features.py"
cp "$REPO_DIR/n8n/bin/detection_validation_policy_registry.py" "$STACK_DIR/bin/detection_validation_policy_registry.py"
cp "$REPO_DIR/n8n/bin/detection_validation_policy_resolution.py" "$STACK_DIR/bin/detection_validation_policy_resolution.py"
cp "$REPO_DIR/n8n/bin/detection_validation_policy_predicates.py" "$STACK_DIR/bin/detection_validation_policy_predicates.py"
cp "$REPO_DIR/n8n/bin/detection_validation_policy_stun.py" "$STACK_DIR/bin/detection_validation_policy_stun.py"
cp "$REPO_DIR/n8n/bin/detection_validation_policy.py" "$STACK_DIR/bin/detection_validation_policy.py"
cp "$REPO_DIR/n8n/bin/detection_validation_result_predicates.py" "$STACK_DIR/bin/detection_validation_result_predicates.py"
cp "$REPO_DIR/n8n/bin/detection_validation_result_content.py" "$STACK_DIR/bin/detection_validation_result_content.py"
cp "$REPO_DIR/n8n/bin/detection_validation_result_decision.py" "$STACK_DIR/bin/detection_validation_result_decision.py"
cp "$REPO_DIR/n8n/bin/detection_validation_result_projection.py" "$STACK_DIR/bin/detection_validation_result_projection.py"
cp "$REPO_DIR/n8n/bin/detection_validation_result_workflow.py" "$STACK_DIR/bin/detection_validation_result_workflow.py"
cp "$REPO_DIR/n8n/bin/detection_validation_result.py" "$STACK_DIR/bin/detection_validation_result.py"
cp "$REPO_DIR/n8n/bin/detection_validation.py" "$STACK_DIR/bin/detection_validation.py"
cp "$REPO_DIR/n8n/bin/investigation_skills.py" "$STACK_DIR/bin/investigation_skills.py"
cp "$REPO_DIR/n8n/bin/asset_inventory.py" "$STACK_DIR/bin/asset_inventory.py"
cp "$REPO_DIR/n8n/bin/dhcp_asset_contract.py" "$STACK_DIR/bin/dhcp_asset_contract.py"
cp "$REPO_DIR/n8n/bin/dhcp_asset_state.py" "$STACK_DIR/bin/dhcp_asset_state.py"
cp "$REPO_DIR/n8n/bin/dhcp_asset_adapters.py" "$STACK_DIR/bin/dhcp_asset_adapters.py"
cp "$REPO_DIR/n8n/bin/dhcp_asset_workflow.py" "$STACK_DIR/bin/dhcp_asset_workflow.py"
cp "$REPO_DIR/n8n/bin/collect-dhcp-asset-discovery.py" "$STACK_DIR/bin/collect-dhcp-asset-discovery.py"
cp "$REPO_DIR/n8n/bin/collect-endpoint-software-inventory.py" "$STACK_DIR/bin/collect-endpoint-software-inventory.py"
cp "$REPO_DIR/n8n/bin/software_inventory_contract.py" "$STACK_DIR/bin/software_inventory_contract.py"
cp "$REPO_DIR/n8n/bin/software_inventory_record_normalization.py" "$STACK_DIR/bin/software_inventory_record_normalization.py"
cp "$REPO_DIR/n8n/bin/software_inventory_state_validation.py" "$STACK_DIR/bin/software_inventory_state_validation.py"
cp "$REPO_DIR/n8n/bin/software_inventory_normalization.py" "$STACK_DIR/bin/software_inventory_normalization.py"
cp "$REPO_DIR/n8n/bin/software_inventory_transport.py" "$STACK_DIR/bin/software_inventory_transport.py"
cp "$REPO_DIR/n8n/bin/software_inventory_validation.py" "$STACK_DIR/bin/software_inventory_validation.py"
cp "$REPO_DIR/n8n/bin/software_inventory_workflow.py" "$STACK_DIR/bin/software_inventory_workflow.py"
cp "$REPO_DIR/n8n/bin/collect-software-inventory.py" "$STACK_DIR/bin/collect-software-inventory.py"
cp "$REPO_DIR/n8n/bin/collect-ac-hunter.py" "$STACK_DIR/bin/collect-ac-hunter.py"
cp "$REPO_DIR/n8n/bin/migrate-software-inventory-to-postgres.py" "$STACK_DIR/bin/migrate-software-inventory-to-postgres.py"
cp "$REPO_DIR/n8n/bin/query-security-onion.py" "$STACK_DIR/bin/query-security-onion.py"
cp "$REPO_DIR/n8n/bin/promote-dhcp-asset.py" "$STACK_DIR/bin/promote-dhcp-asset.py"
cp "$REPO_DIR/n8n/bin/migrate-assets-to-postgres.py" "$STACK_DIR/bin/migrate-assets-to-postgres.py"
cp "$REPO_DIR/n8n/bin/incident_evidence_validation.py" "$STACK_DIR/bin/incident_evidence_validation.py"
cp "$REPO_DIR/n8n/bin/incident_evidence_primitives.py" "$STACK_DIR/bin/incident_evidence_primitives.py"
cp "$REPO_DIR/n8n/bin/incident_evidence_search_contract.py" "$STACK_DIR/bin/incident_evidence_search_contract.py"
cp "$REPO_DIR/n8n/bin/incident_evidence_osquery_contract.py" "$STACK_DIR/bin/incident_evidence_osquery_contract.py"
cp "$REPO_DIR/n8n/bin/incident_evidence_control_contract.py" "$STACK_DIR/bin/incident_evidence_control_contract.py"
cp "$REPO_DIR/n8n/bin/incident_evidence_artifact_contract.py" "$STACK_DIR/bin/incident_evidence_artifact_contract.py"
cp "$REPO_DIR/n8n/bin/incident_evidence_contract.py" "$STACK_DIR/bin/incident_evidence_contract.py"
cp "$REPO_DIR/n8n/bin/prompt_incident_evidence_projection.py" "$STACK_DIR/bin/prompt_incident_evidence_projection.py"
cp "$REPO_DIR/n8n/bin/prompt_incident_grounding.py" "$STACK_DIR/bin/prompt_incident_grounding.py"
cp "$REPO_DIR/n8n/bin/prompt_alert_group.py" "$STACK_DIR/bin/prompt_alert_group.py"
cp "$REPO_DIR/n8n/bin/prompt_alert_projection.py" "$STACK_DIR/bin/prompt_alert_projection.py"
cp "$REPO_DIR/n8n/bin/prompt_alert_queries.py" "$STACK_DIR/bin/prompt_alert_queries.py"
cp "$REPO_DIR/n8n/bin/prompt_alert_store.py" "$STACK_DIR/bin/prompt_alert_store.py"
cp "$REPO_DIR/n8n/bin/prompt_authorization_context.py" "$STACK_DIR/bin/prompt_authorization_context.py"
cp "$REPO_DIR/n8n/bin/prompt_builder_cli.py" "$STACK_DIR/bin/prompt_builder_cli.py"
cp "$REPO_DIR/n8n/bin/prompt_builder_compatibility.py" "$STACK_DIR/bin/prompt_builder_compatibility.py"
cp "$REPO_DIR/n8n/bin/prompt_builder_io.py" "$STACK_DIR/bin/prompt_builder_io.py"
cp "$REPO_DIR/n8n/bin/prompt_builder_policy.py" "$STACK_DIR/bin/prompt_builder_policy.py"
cp "$REPO_DIR/n8n/bin/prompt_correlation_context.py" "$STACK_DIR/bin/prompt_correlation_context.py"
cp "$REPO_DIR/n8n/bin/prompt_correlation_facts.py" "$STACK_DIR/bin/prompt_correlation_facts.py"
cp "$REPO_DIR/n8n/bin/prompt_detection_context.py" "$STACK_DIR/bin/prompt_detection_context.py"
cp "$REPO_DIR/n8n/bin/prompt_detection_facade.py" "$STACK_DIR/bin/prompt_detection_facade.py"
cp "$REPO_DIR/n8n/bin/prompt_evidence_admission.py" "$STACK_DIR/bin/prompt_evidence_admission.py"
cp "$REPO_DIR/n8n/bin/prompt_evidence_facade.py" "$STACK_DIR/bin/prompt_evidence_facade.py"
cp "$REPO_DIR/n8n/bin/prompt_evidence_snapshot.py" "$STACK_DIR/bin/prompt_evidence_snapshot.py"
cp "$REPO_DIR/n8n/bin/prompt_investigation_query_context.py" "$STACK_DIR/bin/prompt_investigation_query_context.py"
cp "$REPO_DIR/n8n/bin/prompt_package_compactor.py" "$STACK_DIR/bin/prompt_package_compactor.py"
cp "$REPO_DIR/n8n/bin/prompt_package_orchestrator.py" "$STACK_DIR/bin/prompt_package_orchestrator.py"
cp "$REPO_DIR/n8n/bin/prompt_package_view_model.py" "$STACK_DIR/bin/prompt_package_view_model.py"
cp "$REPO_DIR/n8n/bin/prompt_pcap_evidence.py" "$STACK_DIR/bin/prompt_pcap_evidence.py"
cp "$REPO_DIR/n8n/bin/prompt_prior_analysis.py" "$STACK_DIR/bin/prompt_prior_analysis.py"
cp "$REPO_DIR/n8n/bin/prompt_public_enrichment.py" "$STACK_DIR/bin/prompt_public_enrichment.py"
cp "$REPO_DIR/n8n/bin/prompt_response_contract.py" "$STACK_DIR/bin/prompt_response_contract.py"
cp "$REPO_DIR/n8n/bin/prompt_role_task.py" "$STACK_DIR/bin/prompt_role_task.py"
cp "$REPO_DIR/n8n/bin/collect-incident-evidence.py" "$STACK_DIR/bin/collect-incident-evidence.py"
cp "$REPO_DIR/n8n/bin/install-investigation-query-runtime.py" "$STACK_DIR/bin/install-investigation-query-runtime.py"
# The Security Onion forced command and these three Mac files are one exact
# wire protocol.  Missing configuration means v1, and every v1 install restores
# the checksum-pinned repository compatibility bundle so local drift cannot
# silently change the protocol.  V2 is copied only after an operator explicitly
# selects its exact ID in incident-evidence.json.
/usr/bin/python3 "$STACK_DIR/bin/install-investigation-query-runtime.py" \
  --repo-root "$REPO_DIR" \
  --runtime-bin "$STACK_DIR/bin" \
  --config "$STACK_DIR/config/incident-evidence.json"
cp "$REPO_DIR/n8n/bin/live_osquery_contract_schema.py" "$STACK_DIR/bin/live_osquery_contract_schema.py"
cp "$REPO_DIR/n8n/bin/live_osquery_contract_query.py" "$STACK_DIR/bin/live_osquery_contract_query.py"
cp "$REPO_DIR/n8n/bin/live_osquery_contract_request.py" "$STACK_DIR/bin/live_osquery_contract_request.py"
cp "$REPO_DIR/n8n/bin/live_osquery_contract_result.py" "$STACK_DIR/bin/live_osquery_contract_result.py"
cp "$REPO_DIR/n8n/bin/live_osquery_contract.py" "$STACK_DIR/bin/live_osquery_contract.py"
cp "$REPO_DIR/n8n/bin/live_osquery_client_primitives.py" "$STACK_DIR/bin/live_osquery_client_primitives.py"
cp "$REPO_DIR/n8n/bin/live_osquery_client_config.py" "$STACK_DIR/bin/live_osquery_client_config.py"
cp "$REPO_DIR/n8n/bin/live_osquery_client_policy.py" "$STACK_DIR/bin/live_osquery_client_policy.py"
cp "$REPO_DIR/n8n/bin/live_osquery_client_transport.py" "$STACK_DIR/bin/live_osquery_client_transport.py"
cp "$REPO_DIR/n8n/bin/live_osquery_client_custody.py" "$STACK_DIR/bin/live_osquery_client_custody.py"
cp "$REPO_DIR/n8n/bin/live_osquery_client.py" "$STACK_DIR/bin/live_osquery_client.py"
cp "$REPO_DIR/n8n/bin/collect-live-osquery.py" "$STACK_DIR/bin/collect-live-osquery.py"
cp "$REPO_DIR/n8n/bin/ac_hunter_contract.py" "$STACK_DIR/bin/ac_hunter_contract.py"
cp "$REPO_DIR/n8n/bin/onion_sentinel_harness.py" "$STACK_DIR/bin/onion_sentinel_harness.py"
cp "$REPO_DIR/n8n/bin/harness_contract_job.py" "$STACK_DIR/bin/harness_contract_job.py"
cp "$REPO_DIR/n8n/bin/harness_contract_ledger.py" "$STACK_DIR/bin/harness_contract_ledger.py"
cp "$REPO_DIR/n8n/bin/harness_contract_metadata.py" "$STACK_DIR/bin/harness_contract_metadata.py"
cp "$REPO_DIR/n8n/bin/harness_contract_skill_attestation.py" "$STACK_DIR/bin/harness_contract_skill_attestation.py"
cp "$REPO_DIR/n8n/bin/harness_contracts.py" "$STACK_DIR/bin/harness_contracts.py"
cp "$REPO_DIR/n8n/bin/harness_memory.py" "$STACK_DIR/bin/harness_memory.py"
cp "$REPO_DIR/n8n/bin/harness_policy_primitives.py" "$STACK_DIR/bin/harness_policy_primitives.py"
cp "$REPO_DIR/n8n/bin/harness_policy_capabilities.py" "$STACK_DIR/bin/harness_policy_capabilities.py"
cp "$REPO_DIR/n8n/bin/harness_policy_document.py" "$STACK_DIR/bin/harness_policy_document.py"
cp "$REPO_DIR/n8n/bin/harness_policy.py" "$STACK_DIR/bin/harness_policy.py"
cp "$REPO_DIR/n8n/bin/harness_query_observation.py" "$STACK_DIR/bin/harness_query_observation.py"
cp "$REPO_DIR/n8n/bin/harness_query_binding_envelope.py" "$STACK_DIR/bin/harness_query_binding_envelope.py"
cp "$REPO_DIR/n8n/bin/harness_query_binding_validation.py" "$STACK_DIR/bin/harness_query_binding_validation.py"
cp "$REPO_DIR/n8n/bin/harness_query_binding.py" "$STACK_DIR/bin/harness_query_binding.py"
cp "$REPO_DIR/n8n/bin/harness_query_contract.py" "$STACK_DIR/bin/harness_query_contract.py"
cp "$REPO_DIR/n8n/bin/harness_run_completion.py" "$STACK_DIR/bin/harness_run_completion.py"
cp "$REPO_DIR/n8n/bin/harness_run_model_execution.py" "$STACK_DIR/bin/harness_run_model_execution.py"
cp "$REPO_DIR/n8n/bin/harness_run_query_execution.py" "$STACK_DIR/bin/harness_run_query_execution.py"
cp "$REPO_DIR/n8n/bin/harness_run_execution.py" "$STACK_DIR/bin/harness_run_execution.py"
cp "$REPO_DIR/n8n/bin/harness_run_model_preflight.py" "$STACK_DIR/bin/harness_run_model_preflight.py"
cp "$REPO_DIR/n8n/bin/harness_run_foundation.py" "$STACK_DIR/bin/harness_run_foundation.py"
cp "$REPO_DIR/n8n/bin/harness_store_foundation.py" "$STACK_DIR/bin/harness_store_foundation.py"
cp "$REPO_DIR/n8n/bin/harness_store_schema.py" "$STACK_DIR/bin/harness_store_schema.py"
cp "$REPO_DIR/n8n/bin/harness_store_hypothesis_persistence.py" "$STACK_DIR/bin/harness_store_hypothesis_persistence.py"
cp "$REPO_DIR/n8n/bin/harness_store_decision_persistence.py" "$STACK_DIR/bin/harness_store_decision_persistence.py"
cp "$REPO_DIR/n8n/bin/harness_store_decision_repository.py" "$STACK_DIR/bin/harness_store_decision_repository.py"
cp "$REPO_DIR/n8n/bin/harness_store_execution_repository.py" "$STACK_DIR/bin/harness_store_execution_repository.py"
cp "$REPO_DIR/n8n/bin/harness_store_run_repository.py" "$STACK_DIR/bin/harness_store_run_repository.py"
cp "$REPO_DIR/n8n/bin/harness_store_trace_repository.py" "$STACK_DIR/bin/harness_store_trace_repository.py"
cp "$REPO_DIR/n8n/bin/harness_store_trace_verification.py" "$STACK_DIR/bin/harness_store_trace_verification.py"
cp "$REPO_DIR/n8n/bin/security_jsonl_log.py" "$STACK_DIR/bin/security_jsonl_log.py"
cp "$REPO_DIR/operations/evaluate-harness-traces.py" "$STACK_DIR/bin/evaluate-harness-traces.py"
cp "$REPO_DIR/operations/trace_evaluation_skills.py" "$STACK_DIR/bin/trace_evaluation_skills.py"
cp "$REPO_DIR/operations/trace_evaluation_storage.py" "$STACK_DIR/bin/trace_evaluation_storage.py"
cp "$REPO_DIR/operations/trace_evaluation_integrity.py" "$STACK_DIR/bin/trace_evaluation_integrity.py"
cp "$REPO_DIR/operations/trace_evaluation_reviewer.py" "$STACK_DIR/bin/trace_evaluation_reviewer.py"
cp "$REPO_DIR/operations/trace_evaluation_model_contract.py" "$STACK_DIR/bin/trace_evaluation_model_contract.py"
cp "$REPO_DIR/operations/trace_evaluation_model_completion.py" "$STACK_DIR/bin/trace_evaluation_model_completion.py"
cp "$REPO_DIR/operations/trace_evaluation_model_routes.py" "$STACK_DIR/bin/trace_evaluation_model_routes.py"
cp "$REPO_DIR/operations/trace_evaluation_run.py" "$STACK_DIR/bin/trace_evaluation_run.py"
cp "$REPO_DIR/operations/trace_evaluation_output.py" "$STACK_DIR/bin/trace_evaluation_output.py"
cp "$REPO_DIR/operations/trace_evaluation_summary.py" "$STACK_DIR/bin/trace_evaluation_summary.py"
cp "$REPO_DIR/operations/trace_evaluation_events.py" "$STACK_DIR/bin/trace_evaluation_events.py"
cp "$REPO_DIR/operations/trace_evaluation_contract.py" "$STACK_DIR/bin/trace_evaluation_contract.py"
cp "$REPO_DIR/operations/trace_evaluation_api.py" "$STACK_DIR/bin/trace_evaluation_api.py"
cp "$REPO_DIR/n8n/bin/controlled_evaluation_isolation.py" "$STACK_DIR/bin/controlled_evaluation_isolation.py"
/usr/bin/python3 "$REPO_DIR/n8n/bin/install-ai-runtime-package.py" \
  --source "$REPO_DIR/n8n/onion_sentinel" \
  --destination "$STACK_DIR/onion_sentinel"
cp "$REPO_DIR/n8n/bin/install-ai-runtime-package.py" "$STACK_DIR/bin/install-ai-runtime-package.py"
cp "$REPO_DIR/n8n/bin/local_ai_pipeline_adapters.py" "$STACK_DIR/bin/local_ai_pipeline_adapters.py"
cp "$REPO_DIR/n8n/bin/local_ai_compatibility_facade.py" "$STACK_DIR/bin/local_ai_compatibility_facade.py"
cp "$REPO_DIR/n8n/bin/local_ai_compatibility_modules.py" "$STACK_DIR/bin/local_ai_compatibility_modules.py"
cp "$REPO_DIR/n8n/bin/local_ai_conclusion_compat.py" "$STACK_DIR/bin/local_ai_conclusion_compat.py"
cp "$REPO_DIR/n8n/bin/local_ai_conclusion_review_dependency_compat.py" "$STACK_DIR/bin/local_ai_conclusion_review_dependency_compat.py"
cp "$REPO_DIR/n8n/bin/local_ai_dependency_compat.py" "$STACK_DIR/bin/local_ai_dependency_compat.py"
cp "$REPO_DIR/n8n/bin/local_ai_evidence_compat.py" "$STACK_DIR/bin/local_ai_evidence_compat.py"
cp "$REPO_DIR/n8n/bin/local_ai_evaluation_routing_compat.py" "$STACK_DIR/bin/local_ai_evaluation_routing_compat.py"
cp "$REPO_DIR/n8n/bin/local_ai_investigation_compat.py" "$STACK_DIR/bin/local_ai_investigation_compat.py"
cp "$REPO_DIR/n8n/bin/local_ai_provider_compat.py" "$STACK_DIR/bin/local_ai_provider_compat.py"
cp "$REPO_DIR/n8n/bin/local_ai_query_dependency_compat.py" "$STACK_DIR/bin/local_ai_query_dependency_compat.py"
cp "$REPO_DIR/n8n/bin/local_ai_review_compat.py" "$STACK_DIR/bin/local_ai_review_compat.py"
cp "$REPO_DIR/n8n/bin/local_ai_runtime_compat.py" "$STACK_DIR/bin/local_ai_runtime_compat.py"
cp "$REPO_DIR/n8n/bin/local_ai_runtime_contract.py" "$STACK_DIR/bin/local_ai_runtime_contract.py"
cp "$REPO_DIR/n8n/bin/local_ai_analysis_contract.py" "$STACK_DIR/bin/local_ai_analysis_contract.py"
cp "$REPO_DIR/n8n/bin/run-local-ai-analysis.py" "$STACK_DIR/bin/run-local-ai-analysis.py"
cp "$REPO_DIR/n8n/bin/export-adjudicated-analysis-replays.py" "$STACK_DIR/bin/export-adjudicated-analysis-replays.py"
cp "$REPO_DIR/n8n/bin/bounded_http.py" "$STACK_DIR/bin/bounded_http.py"
cp "$REPO_DIR/n8n/bin/bounded_process.py" "$STACK_DIR/bin/bounded_process.py"
cp "$REPO_DIR/n8n/bin/bounded_process_policy.py" "$STACK_DIR/bin/bounded_process_policy.py"
cp "$REPO_DIR/n8n/bin/bounded_process_observation.py" "$STACK_DIR/bin/bounded_process_observation.py"
cp "$REPO_DIR/n8n/bin/bounded_process_io.py" "$STACK_DIR/bin/bounded_process_io.py"
cp "$REPO_DIR/n8n/bin/bounded_process_termination.py" "$STACK_DIR/bin/bounded_process_termination.py"
cp "$REPO_DIR/n8n/bin/bounded_process_runtime.py" "$STACK_DIR/bin/bounded_process_runtime.py"
cp "$REPO_DIR/n8n/bin/auto-run-ai-analysis.py" "$STACK_DIR/bin/auto-run-ai-analysis.py"
cp "$REPO_DIR/n8n/bin/scheduler_application.py" "$STACK_DIR/bin/scheduler_application.py"
cp "$REPO_DIR/n8n/bin/scheduler_composition.py" "$STACK_DIR/bin/scheduler_composition.py"
cp "$REPO_DIR/n8n/bin/scheduler_configuration.py" "$STACK_DIR/bin/scheduler_configuration.py"
cp "$REPO_DIR/n8n/bin/scheduler_controlled_compat.py" "$STACK_DIR/bin/scheduler_controlled_compat.py"
cp "$REPO_DIR/n8n/bin/scheduler_claim.py" "$STACK_DIR/bin/scheduler_claim.py"
cp "$REPO_DIR/n8n/bin/scheduler_claim_snapshot.py" "$STACK_DIR/bin/scheduler_claim_snapshot.py"
cp "$REPO_DIR/n8n/bin/scheduler_cli.py" "$STACK_DIR/bin/scheduler_cli.py"
cp "$REPO_DIR/n8n/bin/scheduler_ai_settings.py" "$STACK_DIR/bin/scheduler_ai_settings.py"
cp "$REPO_DIR/n8n/bin/scheduler_artifact_repository.py" "$STACK_DIR/bin/scheduler_artifact_repository.py"
cp "$REPO_DIR/n8n/bin/scheduler_legacy_reconciliation.py" "$STACK_DIR/bin/scheduler_legacy_reconciliation.py"
cp "$REPO_DIR/n8n/bin/scheduler_prompt_builder.py" "$STACK_DIR/bin/scheduler_prompt_builder.py"
cp "$REPO_DIR/n8n/bin/scheduler_runner_invocation.py" "$STACK_DIR/bin/scheduler_runner_invocation.py"
cp "$REPO_DIR/n8n/bin/scheduler_javascript_compat.py" "$STACK_DIR/bin/scheduler_javascript_compat.py"
cp "$REPO_DIR/n8n/bin/scheduler_controlled_canonical.py" "$STACK_DIR/bin/scheduler_controlled_canonical.py"
cp "$REPO_DIR/n8n/bin/scheduler_controlled_acceptance.py" "$STACK_DIR/bin/scheduler_controlled_acceptance.py"
cp "$REPO_DIR/n8n/bin/scheduler_controlled_artifacts.py" "$STACK_DIR/bin/scheduler_controlled_artifacts.py"
cp "$REPO_DIR/n8n/bin/scheduler_controlled_recovery.py" "$STACK_DIR/bin/scheduler_controlled_recovery.py"
cp "$REPO_DIR/n8n/bin/scheduler_controlled_result_client.py" "$STACK_DIR/bin/scheduler_controlled_result_client.py"
cp "$REPO_DIR/n8n/bin/scheduler_controlled_release.py" "$STACK_DIR/bin/scheduler_controlled_release.py"
cp "$REPO_DIR/n8n/bin/scheduler_controlled_claim_contract.py" "$STACK_DIR/bin/scheduler_controlled_claim_contract.py"
cp "$REPO_DIR/n8n/bin/scheduler_controlled_payload.py" "$STACK_DIR/bin/scheduler_controlled_payload.py"
cp "$REPO_DIR/n8n/bin/scheduler_controlled_runtime.py" "$STACK_DIR/bin/scheduler_controlled_runtime.py"
cp "$REPO_DIR/n8n/bin/scheduler_controlled_terminal_proof.py" "$STACK_DIR/bin/scheduler_controlled_terminal_proof.py"
cp "$REPO_DIR/n8n/bin/scheduler_drain.py" "$STACK_DIR/bin/scheduler_drain.py"
cp "$REPO_DIR/n8n/bin/scheduler_execution.py" "$STACK_DIR/bin/scheduler_execution.py"
cp "$REPO_DIR/n8n/bin/scheduler_facade.py" "$STACK_DIR/bin/scheduler_facade.py"
cp "$REPO_DIR/n8n/bin/scheduler_indexed_selection.py" "$STACK_DIR/bin/scheduler_indexed_selection.py"
cp "$REPO_DIR/n8n/bin/scheduler_indexed_state.py" "$STACK_DIR/bin/scheduler_indexed_state.py"
cp "$REPO_DIR/n8n/bin/scheduler_job_reporting.py" "$STACK_DIR/bin/scheduler_job_reporting.py"
cp "$REPO_DIR/n8n/bin/scheduler_job_compat.py" "$STACK_DIR/bin/scheduler_job_compat.py"
cp "$REPO_DIR/n8n/bin/scheduler_legacy_selection.py" "$STACK_DIR/bin/scheduler_legacy_selection.py"
cp "$REPO_DIR/n8n/bin/scheduler_outcome.py" "$STACK_DIR/bin/scheduler_outcome.py"
cp "$REPO_DIR/n8n/bin/scheduler_runtime_compat.py" "$STACK_DIR/bin/scheduler_runtime_compat.py"
cp "$REPO_DIR/n8n/bin/scheduler_settlement.py" "$STACK_DIR/bin/scheduler_settlement.py"
cp "$REPO_DIR/n8n/bin/scheduler_selection_compat.py" "$STACK_DIR/bin/scheduler_selection_compat.py"
cp "$REPO_DIR/n8n/bin/scheduler_startup.py" "$STACK_DIR/bin/scheduler_startup.py"
cp "$REPO_DIR/n8n/bin/scheduler_terminal_recovery.py" "$STACK_DIR/bin/scheduler_terminal_recovery.py"
cp "$REPO_DIR/n8n/bin/scheduler_worker.py" "$STACK_DIR/bin/scheduler_worker.py"
cp "$REPO_DIR/n8n/bin/agent_memory.py" "$STACK_DIR/bin/agent_memory.py"
cp "$REPO_DIR/n8n/bin/agent_memory_validation.py" "$STACK_DIR/bin/agent_memory_validation.py"
cp "$REPO_DIR/n8n/bin/agent_memory_journal.py" "$STACK_DIR/bin/agent_memory_journal.py"
cp "$REPO_DIR/n8n/bin/agent_memory_promotion.py" "$STACK_DIR/bin/agent_memory_promotion.py"
cp "$REPO_DIR/n8n/bin/manage-agent-memory.py" "$STACK_DIR/bin/manage-agent-memory.py"
cp "$REPO_DIR/n8n/bin/verify-agent-memory.py" "$STACK_DIR/bin/verify-agent-memory.py"
cp "$REPO_DIR/n8n/bin/set-runtime-release-id.py" "$STACK_DIR/bin/set-runtime-release-id.py"
cp "$REPO_DIR/n8n/bin/upgrade-runtime-policy.py" "$STACK_DIR/bin/upgrade-runtime-policy.py"
cp "$REPO_DIR/n8n/bin/backfill-ai-correlation-context.py" "$STACK_DIR/bin/backfill-ai-correlation-context.py"
cp "$REPO_DIR/n8n/bin/pcap_processor_contract.py" "$STACK_DIR/bin/pcap_processor_contract.py"
cp "$REPO_DIR/n8n/bin/pcap_processor_storage_requests.py" "$STACK_DIR/bin/pcap_processor_storage_requests.py"
cp "$REPO_DIR/n8n/bin/pcap_processor_storage_scope.py" "$STACK_DIR/bin/pcap_processor_storage_scope.py"
cp "$REPO_DIR/n8n/bin/pcap_processor_storage_artifacts.py" "$STACK_DIR/bin/pcap_processor_storage_artifacts.py"
cp "$REPO_DIR/n8n/bin/pcap_processor_storage_records.py" "$STACK_DIR/bin/pcap_processor_storage_records.py"
cp "$REPO_DIR/n8n/bin/pcap_processor_storage.py" "$STACK_DIR/bin/pcap_processor_storage.py"
cp "$REPO_DIR/n8n/bin/pcap_processor_zeek.py" "$STACK_DIR/bin/pcap_processor_zeek.py"
cp "$REPO_DIR/n8n/bin/pcap_processor_tshark_contract.py" "$STACK_DIR/bin/pcap_processor_tshark_contract.py"
cp "$REPO_DIR/n8n/bin/pcap_processor_tshark_state.py" "$STACK_DIR/bin/pcap_processor_tshark_state.py"
cp "$REPO_DIR/n8n/bin/pcap_processor_tshark_parser.py" "$STACK_DIR/bin/pcap_processor_tshark_parser.py"
cp "$REPO_DIR/n8n/bin/pcap_processor_tshark_projection.py" "$STACK_DIR/bin/pcap_processor_tshark_projection.py"
cp "$REPO_DIR/n8n/bin/pcap_processor_tshark_workflow.py" "$STACK_DIR/bin/pcap_processor_tshark_workflow.py"
cp "$REPO_DIR/n8n/bin/pcap_processor_tshark.py" "$STACK_DIR/bin/pcap_processor_tshark.py"
cp "$REPO_DIR/n8n/bin/pcap_processor_workflow.py" "$STACK_DIR/bin/pcap_processor_workflow.py"
cp "$REPO_DIR/n8n/bin/process-pcap-evidence.py" "$STACK_DIR/bin/process-pcap-evidence.py"
cp "$REPO_DIR/n8n/bin/pcap_analysis_core.py" "$STACK_DIR/bin/pcap_analysis_core.py"
cp "$REPO_DIR/n8n/bin/pcap_evidence_query_policy.py" "$STACK_DIR/bin/pcap_evidence_query_policy.py"
cp "$REPO_DIR/n8n/bin/pcap_evidence_query_validation.py" "$STACK_DIR/bin/pcap_evidence_query_validation.py"
cp "$REPO_DIR/n8n/bin/pcap_evidence_query_matching.py" "$STACK_DIR/bin/pcap_evidence_query_matching.py"
cp "$REPO_DIR/n8n/bin/pcap_evidence_query_selection.py" "$STACK_DIR/bin/pcap_evidence_query_selection.py"
cp "$REPO_DIR/n8n/bin/pcap_evidence_query_projection.py" "$STACK_DIR/bin/pcap_evidence_query_projection.py"
cp "$REPO_DIR/n8n/bin/pcap_evidence_query_response.py" "$STACK_DIR/bin/pcap_evidence_query_response.py"
cp "$REPO_DIR/n8n/bin/pcap_evidence_query.py" "$STACK_DIR/bin/pcap_evidence_query.py"
cp "$REPO_DIR/n8n/bin/pcap_tool_runtime.py" "$STACK_DIR/bin/pcap_tool_runtime.py"
cp "$REPO_DIR/n8n/bin/onion-sentinel-pcap-intake.py" "$STACK_DIR/bin/onion-sentinel-pcap-intake.py"
cp "$REPO_DIR/n8n/bin/onion-sentinel-alert-intake.py" "$STACK_DIR/bin/onion-sentinel-alert-intake.py"
cp "$REPO_DIR/n8n/bin/configure-post-commit-env.py" "$STACK_DIR/bin/configure-post-commit-env.py"
cp "$REPO_DIR/n8n/bin/configure-postgres-shadow-env.py" "$STACK_DIR/bin/configure-postgres-shadow-env.py"
cp "$REPO_DIR/operations/reconcile-postgres-shadow.js" "$STACK_DIR/bin/reconcile-postgres-shadow.js"
cp "$REPO_DIR/n8n/bin/install-alert-intake-authorized-key.py" "$STACK_DIR/bin/install-alert-intake-authorized-key.py"
cp "$REPO_DIR/n8n/bin/pcap_lifecycle.py" "$STACK_DIR/bin/pcap_lifecycle.py"
cp "$REPO_DIR/n8n/bin/maintain-pcap-evidence.py" "$STACK_DIR/bin/maintain-pcap-evidence.py"
cp "$REPO_DIR/n8n/bin/refresh-soc-dashboard.py" "$STACK_DIR/bin/refresh-soc-dashboard.py"
cp "$REPO_DIR/n8n/bin/write-daily-soc-rollup.py" "$STACK_DIR/bin/write-daily-soc-rollup.py"
cp "$REPO_DIR/n8n/bin/daily_soc_rollup_data.py" "$STACK_DIR/bin/daily_soc_rollup_data.py"
cp "$REPO_DIR/n8n/bin/daily_soc_rollup_markdown.py" "$STACK_DIR/bin/daily_soc_rollup_markdown.py"
chmod +x "$STACK_DIR/bin/"*.zsh
chmod +x "$STACK_DIR/bin/"*.py
chmod 0755 "$STACK_DIR/bin/reconcile-postgres-shadow.js"
"$STACK_DIR/bin/verify-agent-memory.py" --initialize >/dev/null

if [[ ! -f "$STACK_DIR/config/live-osquery.json" ]]; then
  cp "$REPO_DIR/n8n/config/live-osquery.example.json" "$STACK_DIR/config/live-osquery.json"
  chmod 0600 "$STACK_DIR/config/live-osquery.json"
fi

# GeoIP is an offline, optional enrichment. Keep its Python reader isolated
# from macOS system packages, and leave PCAP parsing operational if package
# installation is temporarily unavailable during disaster recovery.
if ! PYTHONPATH="$STACK_DIR/python" /usr/bin/python3 -c 'import maxminddb' >/dev/null 2>&1; then
  if ! /usr/bin/python3 -m pip install \
    --disable-pip-version-check \
    --no-input \
    --target "$STACK_DIR/python" \
    'maxminddb>=2.6,<3'; then
    echo "WARNING: optional MaxMind reader installation failed; PCAP parsing will continue without GeoIP until maxminddb is installed." >&2
  fi
fi

# Onion Sentinel owns its builder, assets, API helpers, and web service. Never
# install these files under ~/.hermes or ~/report_portal; the Hermes LAN Portal
# may contain an external link to this service and nothing more.
mkdir -p "$DASHBOARD_RUNTIME_DIR/scripts" "$DASHBOARD_RUNTIME_DIR/assets"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/build_soc_alerts_dashboard.py" "$DASHBOARD_RUNTIME_DIR/scripts/build_soc_alerts_dashboard.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_builder_contract.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_builder_contract.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_builder_settings.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_builder_settings.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_builder_report_core.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_builder_report_core.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_builder_reports.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_builder_reports.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_builder_executive.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_builder_executive.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_builder_siem.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_builder_siem.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_builder_pages.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_builder_pages.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_builder_publication.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_builder_publication.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_builder_runtime.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_builder_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_time_format.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_time_format.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_executive_metrics.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_executive_metrics.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_metric_components.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_metric_components.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_pcap_components.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_pcap_components.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_timeline_components.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_timeline_components.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_system_health_components.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_system_health_components.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_reactive_tables.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_reactive_tables.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_static_composition.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_static_composition.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_publication.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_publication.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_soc_shell_content.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_soc_shell_content.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_logs_page.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_logs_page.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_asset_inventory_page.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_asset_inventory_page.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_ac_hunter_page.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_ac_hunter_page.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_incident_response_page.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_incident_response_page.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_analyst_adjudication_modal.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_analyst_adjudication_modal.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_alert_detail_markdown.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_alert_detail_markdown.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_alert_detail_layout.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_alert_detail_layout.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_alert_detail_values.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_alert_detail_values.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_alert_detail_evidence.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_alert_detail_evidence.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_alert_detail_ai.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_alert_detail_ai.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_alert_detail_enrichment.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_alert_detail_enrichment.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_alert_detail_sections.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_alert_detail_sections.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_alert_detail_composer.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_alert_detail_composer.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_alert_repository.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_alert_repository.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_alert_report_model.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_alert_report_model.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_alert_report_factory.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_alert_report_factory.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_report_repository.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_report_repository.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_ai_artifact_repository.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_ai_artifact_repository.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_alert_ai_workflow.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_alert_ai_workflow.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_alert_pcap_workflow.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_alert_pcap_workflow.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_model_routing.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_model_routing.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_ai_settings.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_ai_settings.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_investigation_skills.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_investigation_skills.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_model_presentation.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_model_presentation.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_flow_page.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_flow_page.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_cyber_threat_intel_page.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_cyber_threat_intel_page.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_threat_hunter_page.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_threat_hunter_page.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_siem_engineering_assets.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_siem_engineering_assets.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_siem_engineering_page.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_siem_engineering_page.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_reports_assets.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_reports_assets.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_reports_page.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_reports_page.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_executive_home_assets.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_executive_home_assets.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_executive_home_page.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_executive_home_page.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_settings_assets.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_settings_assets.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_settings_agent_card.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_settings_agent_card.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_settings_page.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_settings_page.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_settings_client_shell.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_settings_client_shell.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_settings_client_model.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_settings_client_model.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_settings_client_actions.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_settings_client_actions.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_software_inventory_page.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_software_inventory_page.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_shell_components.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_shell_components.py"
cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_shell_page.py" "$DASHBOARD_RUNTIME_DIR/scripts/dashboard_shell_page.py"
cp -R "$REPO_DIR/onion-sentinel-dashboard/assets/." "$DASHBOARD_RUNTIME_DIR/assets/"
cp "$REPO_DIR/onion-sentinel-dashboard/onion_sentinel_release.py" "$DASHBOARD_RUNTIME_DIR/onion_sentinel_release.py"
cp "$REPO_DIR/onion-sentinel-dashboard/onion_sentinel_application.py" "$DASHBOARD_RUNTIME_DIR/onion_sentinel_application.py"
cp "$REPO_DIR/onion-sentinel-dashboard/onion_sentinel_request_routes.py" "$DASHBOARD_RUNTIME_DIR/onion_sentinel_request_routes.py"
cp "$REPO_DIR/onion-sentinel-dashboard/onion_sentinel_server.py" "$DASHBOARD_RUNTIME_DIR/onion_sentinel_server.py"
cp "$REPO_DIR/onion-sentinel-dashboard/application_log_contract.py" "$DASHBOARD_RUNTIME_DIR/application_log_contract.py"
cp "$REPO_DIR/onion-sentinel-dashboard/application_log_filesystem.py" "$DASHBOARD_RUNTIME_DIR/application_log_filesystem.py"
cp "$REPO_DIR/onion-sentinel-dashboard/application_log_catalog.py" "$DASHBOARD_RUNTIME_DIR/application_log_catalog.py"
cp "$REPO_DIR/onion-sentinel-dashboard/application_log_content.py" "$DASHBOARD_RUNTIME_DIR/application_log_content.py"
cp "$REPO_DIR/onion-sentinel-dashboard/application_logs.py" "$DASHBOARD_RUNTIME_DIR/application_logs.py"
cp "$REPO_DIR/onion-sentinel-dashboard/http_runtime.py" "$DASHBOARD_RUNTIME_DIR/http_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/jsonl_log.py" "$DASHBOARD_RUNTIME_DIR/jsonl_log.py"
cp "$REPO_DIR/n8n/bin/security_jsonl_log.py" "$DASHBOARD_RUNTIME_DIR/security_jsonl_log.py"
cp "$REPO_DIR/onion-sentinel-dashboard/report_portal.py" "$DASHBOARD_RUNTIME_DIR/report_portal.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_runtime_config.py" "$DASHBOARD_RUNTIME_DIR/portal_runtime_config.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_runtime_standard_dependencies.py" "$DASHBOARD_RUNTIME_DIR/portal_runtime_standard_dependencies.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_runtime_settings_dependencies.py" "$DASHBOARD_RUNTIME_DIR/portal_runtime_settings_dependencies.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_runtime_admin_dependencies.py" "$DASHBOARD_RUNTIME_DIR/portal_runtime_admin_dependencies.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_runtime_soc_dependencies.py" "$DASHBOARD_RUNTIME_DIR/portal_runtime_soc_dependencies.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_runtime_constants.py" "$DASHBOARD_RUNTIME_DIR/portal_runtime_constants.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_compat_bindings.py" "$DASHBOARD_RUNTIME_DIR/portal_compat_bindings.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_admin_dashboard.py" "$DASHBOARD_RUNTIME_DIR/portal_admin_dashboard.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_admin_dashboard_assets.py" "$DASHBOARD_RUNTIME_DIR/portal_admin_dashboard_assets.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_admin_versions.py" "$DASHBOARD_RUNTIME_DIR/portal_admin_versions.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_admin_availability.py" "$DASHBOARD_RUNTIME_DIR/portal_admin_availability.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_admin_action_state.py" "$DASHBOARD_RUNTIME_DIR/portal_admin_action_state.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_admin_session_store.py" "$DASHBOARD_RUNTIME_DIR/portal_admin_session_store.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_access_runtime.py" "$DASHBOARD_RUNTIME_DIR/portal_access_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_admin_action_runner.py" "$DASHBOARD_RUNTIME_DIR/portal_admin_action_runner.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_admin_runtime.py" "$DASHBOARD_RUNTIME_DIR/portal_admin_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_admin_service_probes.py" "$DASHBOARD_RUNTIME_DIR/portal_admin_service_probes.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_admin_services.py" "$DASHBOARD_RUNTIME_DIR/portal_admin_services.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_disk_inventory.py" "$DASHBOARD_RUNTIME_DIR/portal_disk_inventory.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_hermes_backup_health.py" "$DASHBOARD_RUNTIME_DIR/portal_hermes_backup_health.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_update_health.py" "$DASHBOARD_RUNTIME_DIR/portal_update_health.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_operational_runtime.py" "$DASHBOARD_RUNTIME_DIR/portal_operational_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_dashboard_runtime.py" "$DASHBOARD_RUNTIME_DIR/portal_dashboard_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_foundation_runtime.py" "$DASHBOARD_RUNTIME_DIR/portal_foundation_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_write_runtime.py" "$DASHBOARD_RUNTIME_DIR/portal_write_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_delivery_runtime.py" "$DASHBOARD_RUNTIME_DIR/portal_delivery_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_llm_activity.py" "$DASHBOARD_RUNTIME_DIR/portal_llm_activity.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_llm_active_store.py" "$DASHBOARD_RUNTIME_DIR/portal_llm_active_store.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_llm_history.py" "$DASHBOARD_RUNTIME_DIR/portal_llm_history.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_llm_history_store.py" "$DASHBOARD_RUNTIME_DIR/portal_llm_history_store.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_llm_history_api.py" "$DASHBOARD_RUNTIME_DIR/portal_llm_history_api.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_llm_runtime.py" "$DASHBOARD_RUNTIME_DIR/portal_llm_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_alert_status_write.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_alert_status_write.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_alert_status_store.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_alert_status_store.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_alert_status_service.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_alert_status_service.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_status_runtime.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_status_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_core_runtime.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_core_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_detail_runtime.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_detail_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_pcap_runtime.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_pcap_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_query_runtime.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_query_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_record_runtime.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_record_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_incident_action_runtime.py" "$DASHBOARD_RUNTIME_DIR/portal_incident_action_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_incident_read_runtime.py" "$DASHBOARD_RUNTIME_DIR/portal_incident_read_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_adjudication_policy.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_adjudication_policy.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_adjudication_history.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_adjudication_history.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_pcap_request_policy.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_pcap_request_policy.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_pcap_request_store.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_pcap_request_store.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_pcap_request_service.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_pcap_request_service.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_action_service.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_action_service.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_cron_failures.py" "$DASHBOARD_RUNTIME_DIR/portal_cron_failures.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_n8n_container_status.py" "$DASHBOARD_RUNTIME_DIR/portal_n8n_container_status.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_pcap_health.py" "$DASHBOARD_RUNTIME_DIR/portal_pcap_health.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_beacon_history.py" "$DASHBOARD_RUNTIME_DIR/portal_beacon_history.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_home_dashboard.py" "$DASHBOARD_RUNTIME_DIR/portal_home_dashboard.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_home_dashboard_assets.py" "$DASHBOARD_RUNTIME_DIR/portal_home_dashboard_assets.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_dhcp_discovery.py" "$DASHBOARD_RUNTIME_DIR/portal_dhcp_discovery.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_review_metadata.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_review_metadata.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_evidence_metadata.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_evidence_metadata.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_incident_metadata.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_incident_metadata.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_alert_presenter.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_alert_presenter.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_ai_status.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_ai_status.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_pcap_status.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_pcap_status.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_pcap_artifacts.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_pcap_artifacts.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_pcap_renderer.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_pcap_renderer.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_enrichment_status.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_enrichment_status.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_ai_artifact_context.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_ai_artifact_context.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_ai_artifacts.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_ai_artifacts.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_group_query.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_group_query.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_group_enrichment.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_group_enrichment.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_metrics.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_metrics.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_live_revisions.py" "$DASHBOARD_RUNTIME_DIR/portal_live_revisions.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_read_dispatch.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_read_dispatch.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_sse_stream.py" "$DASHBOARD_RUNTIME_DIR/portal_sse_stream.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_write_request.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_write_request.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_software_inventory_service.py" "$DASHBOARD_RUNTIME_DIR/portal_software_inventory_service.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_asset_inventory_service.py" "$DASHBOARD_RUNTIME_DIR/portal_asset_inventory_service.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_asset_runtime.py" "$DASHBOARD_RUNTIME_DIR/portal_asset_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_asset_dhcp_overlay.py" "$DASHBOARD_RUNTIME_DIR/portal_asset_dhcp_overlay.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_asset_repository.py" "$DASHBOARD_RUNTIME_DIR/portal_asset_repository.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_asset_store_client.py" "$DASHBOARD_RUNTIME_DIR/portal_asset_store_client.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_asset_mutation_service.py" "$DASHBOARD_RUNTIME_DIR/portal_asset_mutation_service.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_asset_write_request.py" "$DASHBOARD_RUNTIME_DIR/portal_asset_write_request.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_cti_program_service.py" "$DASHBOARD_RUNTIME_DIR/portal_cti_program_service.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_settings_write.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_settings_write.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_admin_service_write.py" "$DASHBOARD_RUNTIME_DIR/portal_admin_service_write.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_resource_library_write.py" "$DASHBOARD_RUNTIME_DIR/portal_resource_library_write.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_resource_library_store.py" "$DASHBOARD_RUNTIME_DIR/portal_resource_library_store.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_status_write.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_status_write.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_admin_form_service.py" "$DASHBOARD_RUNTIME_DIR/portal_admin_form_service.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_admin_read_service.py" "$DASHBOARD_RUNTIME_DIR/portal_admin_read_service.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_health_read_service.py" "$DASHBOARD_RUNTIME_DIR/portal_health_read_service.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_http_handler.py" "$DASHBOARD_RUNTIME_DIR/portal_http_handler.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_http_read_adapter.py" "$DASHBOARD_RUNTIME_DIR/portal_http_read_adapter.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_general_read_service.py" "$DASHBOARD_RUNTIME_DIR/portal_general_read_service.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_post_intake.py" "$DASHBOARD_RUNTIME_DIR/portal_post_intake.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_json_write_service.py" "$DASHBOARD_RUNTIME_DIR/portal_json_write_service.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_llm_runtime_state.py" "$DASHBOARD_RUNTIME_DIR/portal_llm_runtime_state.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_resource_action_read.py" "$DASHBOARD_RUNTIME_DIR/portal_resource_action_read.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_catalog_read_service.py" "$DASHBOARD_RUNTIME_DIR/portal_catalog_read_service.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_catalog_runtime.py" "$DASHBOARD_RUNTIME_DIR/portal_catalog_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_catalog_delivery.py" "$DASHBOARD_RUNTIME_DIR/portal_catalog_delivery.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_ai_model_policy.py" "$DASHBOARD_RUNTIME_DIR/portal_ai_model_policy.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_cli_provider_readiness.py" "$DASHBOARD_RUNTIME_DIR/portal_cli_provider_readiness.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_ollama_catalog.py" "$DASHBOARD_RUNTIME_DIR/portal_ollama_catalog.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_ai_settings_normalizer.py" "$DASHBOARD_RUNTIME_DIR/portal_ai_settings_normalizer.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_ai_settings_store.py" "$DASHBOARD_RUNTIME_DIR/portal_ai_settings_store.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_settings_runtime.py" "$DASHBOARD_RUNTIME_DIR/portal_settings_runtime.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_agent_content_store.py" "$DASHBOARD_RUNTIME_DIR/portal_agent_content_store.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_catalog_routes.py" "$DASHBOARD_RUNTIME_DIR/portal_catalog_routes.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_report_catalog.py" "$DASHBOARD_RUNTIME_DIR/portal_report_catalog.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_metric_detail_renderer.py" "$DASHBOARD_RUNTIME_DIR/portal_metric_detail_renderer.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_incident_actions.py" "$DASHBOARD_RUNTIME_DIR/portal_incident_actions.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_incident_list_service.py" "$DASHBOARD_RUNTIME_DIR/portal_incident_list_service.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_incident_read_service.py" "$DASHBOARD_RUNTIME_DIR/portal_incident_read_service.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_incident_read_model.py" "$DASHBOARD_RUNTIME_DIR/portal_incident_read_model.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_incident_reanalysis.py" "$DASHBOARD_RUNTIME_DIR/portal_incident_reanalysis.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_incident_repository.py" "$DASHBOARD_RUNTIME_DIR/portal_incident_repository.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_incident_review_model.py" "$DASHBOARD_RUNTIME_DIR/portal_incident_review_model.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_incident_report_renderer.py" "$DASHBOARD_RUNTIME_DIR/portal_incident_report_renderer.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_investigation_audit_renderer.py" "$DASHBOARD_RUNTIME_DIR/portal_investigation_audit_renderer.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_review_panel_renderer.py" "$DASHBOARD_RUNTIME_DIR/portal_review_panel_renderer.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_json_body.py" "$DASHBOARD_RUNTIME_DIR/portal_json_body.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_request_routes.py" "$DASHBOARD_RUNTIME_DIR/portal_request_routes.py"
cp "$REPO_DIR/onion-sentinel-dashboard/portal_soc_write_dispatch.py" "$DASHBOARD_RUNTIME_DIR/portal_soc_write_dispatch.py"
cp "$REPO_DIR/onion-sentinel-dashboard/ac_hunter_config.py" "$DASHBOARD_RUNTIME_DIR/ac_hunter_config.py"
cp "$REPO_DIR/onion-sentinel-dashboard/ac_hunter_transport.py" "$DASHBOARD_RUNTIME_DIR/ac_hunter_transport.py"
cp "$REPO_DIR/onion-sentinel-dashboard/ac_hunter_finding_normalization.py" "$DASHBOARD_RUNTIME_DIR/ac_hunter_finding_normalization.py"
cp "$REPO_DIR/onion-sentinel-dashboard/ac_hunter_normalization.py" "$DASHBOARD_RUNTIME_DIR/ac_hunter_normalization.py"
cp "$REPO_DIR/onion-sentinel-dashboard/ac_hunter_scoring_policy.py" "$DASHBOARD_RUNTIME_DIR/ac_hunter_scoring_policy.py"
cp "$REPO_DIR/onion-sentinel-dashboard/ac_hunter_scoring.py" "$DASHBOARD_RUNTIME_DIR/ac_hunter_scoring.py"
cp "$REPO_DIR/onion-sentinel-dashboard/ac_hunter_collection_findings.py" "$DASHBOARD_RUNTIME_DIR/ac_hunter_collection_findings.py"
cp "$REPO_DIR/onion-sentinel-dashboard/ac_hunter_collection_hosts.py" "$DASHBOARD_RUNTIME_DIR/ac_hunter_collection_hosts.py"
cp "$REPO_DIR/onion-sentinel-dashboard/ac_hunter_collection_projection.py" "$DASHBOARD_RUNTIME_DIR/ac_hunter_collection_projection.py"
cp "$REPO_DIR/onion-sentinel-dashboard/ac_hunter_collection.py" "$DASHBOARD_RUNTIME_DIR/ac_hunter_collection.py"
cp "$REPO_DIR/onion-sentinel-dashboard/ac_hunter_service.py" "$DASHBOARD_RUNTIME_DIR/ac_hunter_service.py"
cp "$REPO_DIR/onion-sentinel-dashboard/ac_hunter_review.py" "$DASHBOARD_RUNTIME_DIR/ac_hunter_review.py"
cp "$REPO_DIR/onion-sentinel-dashboard/cti_program.py" "$DASHBOARD_RUNTIME_DIR/cti_program.py"
cp "$REPO_DIR/onion-sentinel-dashboard/cti_program_contract.py" "$DASHBOARD_RUNTIME_DIR/cti_program_contract.py"
cp "$REPO_DIR/onion-sentinel-dashboard/cti_program_validation.py" "$DASHBOARD_RUNTIME_DIR/cti_program_validation.py"
cp "$REPO_DIR/onion-sentinel-dashboard/cti_program_store.py" "$DASHBOARD_RUNTIME_DIR/cti_program_store.py"
cp "$REPO_DIR/n8n/bin/asset_inventory.py" "$DASHBOARD_RUNTIME_DIR/asset_inventory.py"
cp "$REPO_DIR/onion-sentinel-dashboard/software_inventory.py" "$DASHBOARD_RUNTIME_DIR/software_inventory.py"
cp "$REPO_DIR/onion-sentinel-dashboard/software_inventory_asset_labels.py" "$DASHBOARD_RUNTIME_DIR/software_inventory_asset_labels.py"
cp "$REPO_DIR/onion-sentinel-dashboard/software_inventory_os_correlation.py" "$DASHBOARD_RUNTIME_DIR/software_inventory_os_correlation.py"
cp "$REPO_DIR/onion-sentinel-dashboard/software_inventory_assets.py" "$DASHBOARD_RUNTIME_DIR/software_inventory_assets.py"
cp "$REPO_DIR/onion-sentinel-dashboard/software_inventory_query.py" "$DASHBOARD_RUNTIME_DIR/software_inventory_query.py"
cp "$REPO_DIR/onion-sentinel-dashboard/software_inventory_response_selection.py" "$DASHBOARD_RUNTIME_DIR/software_inventory_response_selection.py"
cp "$REPO_DIR/onion-sentinel-dashboard/software_inventory_response_projection.py" "$DASHBOARD_RUNTIME_DIR/software_inventory_response_projection.py"
cp "$REPO_DIR/onion-sentinel-dashboard/software_inventory_response.py" "$DASHBOARD_RUNTIME_DIR/software_inventory_response.py"
cp "$REPO_DIR/onion-sentinel-dashboard/software_inventory_state_io.py" "$DASHBOARD_RUNTIME_DIR/software_inventory_state_io.py"
cp "$REPO_DIR/onion-sentinel-dashboard/software_inventory_state.py" "$DASHBOARD_RUNTIME_DIR/software_inventory_state.py"
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
if [[ ! -f "$STACK_DIR/config/dhcp-asset-discovery.json" ]]; then
  /usr/bin/python3 - "$HOME" "$REPO_DIR/n8n/config/dhcp-asset-discovery.example.json" "$STACK_DIR/config/dhcp-asset-discovery.json" <<'PY'
from pathlib import Path
import sys

home, source, destination = sys.argv[1:4]
Path(destination).write_text(
    Path(source).read_text(encoding="utf-8").replace("__HOME__", home),
    encoding="utf-8",
)
PY
  chmod 0600 "$STACK_DIR/config/dhcp-asset-discovery.json"
  echo "Created disabled $STACK_DIR/config/dhcp-asset-discovery.json example." >&2
fi
if [[ ! -f "$STACK_DIR/config/software-inventory.json" ]]; then
  /usr/bin/python3 - "$HOME" "$REPO_DIR/n8n/config/software-inventory.example.json" "$STACK_DIR/config/software-inventory.json" <<'PY'
from pathlib import Path
import sys

home, source, destination = sys.argv[1:4]
Path(destination).write_text(
    Path(source).read_text(encoding="utf-8").replace("__HOME__", home),
    encoding="utf-8",
)
PY
  chmod 0600 "$STACK_DIR/config/software-inventory.json"
  echo "Created disabled $STACK_DIR/config/software-inventory.json example." >&2
fi
# AC Hunter configuration, credentials, and normalized cache are separate trust
# objects. Seed only the disabled non-secret configuration. Never create,
# replace, parse, or print the dedicated service-account credential file.
if [[ -L "$STACK_DIR/config/ac-hunter.json" ]] \
  || [[ -e "$STACK_DIR/config/ac-hunter.json" \
    && ! -f "$STACK_DIR/config/ac-hunter.json" ]]; then
  echo "Refusing install: AC Hunter client config must be a regular file." >&2
  exit 1
fi
if [[ ! -f "$STACK_DIR/config/ac-hunter.json" ]]; then
  /usr/bin/python3 - "$HOME" "$REPO_DIR/n8n/config/ac-hunter.example.json" "$STACK_DIR/config/ac-hunter.json" <<'PY'
from pathlib import Path
import os
import sys

home, source, destination = sys.argv[1:4]
payload = Path(source).read_text(encoding="utf-8").replace("__HOME__", home)
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(destination, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
    handle.write(payload)
PY
  echo "Created disabled $STACK_DIR/config/ac-hunter.json example." >&2
fi
chmod 0600 "$STACK_DIR/config/ac-hunter.json"

AC_HUNTER_CREDENTIALS="$STACK_DIR/config/ac-hunter-credentials.json"
if [[ -L "$AC_HUNTER_CREDENTIALS" ]] \
  || [[ -e "$AC_HUNTER_CREDENTIALS" && ! -f "$AC_HUNTER_CREDENTIALS" ]]; then
  echo "Refusing install: AC Hunter credentials must be a regular file." >&2
  exit 1
fi
if [[ -f "$AC_HUNTER_CREDENTIALS" ]]; then
  chmod 0600 "$AC_HUNTER_CREDENTIALS"
fi

AC_HUNTER_CACHE="$STACK_DIR/cache/ac-hunter-deep-review.json"
if [[ -L "$AC_HUNTER_CACHE" ]] \
  || [[ -e "$AC_HUNTER_CACHE" && ! -f "$AC_HUNTER_CACHE" ]]; then
  echo "Refusing install: AC Hunter cache must be a regular file." >&2
  exit 1
fi
if [[ -f "$AC_HUNTER_CACHE" ]]; then
  chmod 0600 "$AC_HUNTER_CACHE"
fi
# DHCP discovery and software inventory intentionally inherit the established
# read-only incident-evidence SSH lane. Preserve each collector's scheduling
# and paging choices while synchronizing only the four SSH identity fields.
/usr/bin/python3 - \
  "$STACK_DIR/config/dhcp-asset-discovery.json" \
  "$STACK_DIR/config/software-inventory.json" \
  "$STACK_DIR/config/incident-evidence.json" <<'PY'
import json
import os
from pathlib import Path
import sys
import tempfile

*destination_names, incident_name = sys.argv[1:]
incident = json.loads(Path(incident_name).read_text(encoding="utf-8"))
transport_fields = ("host", "ssh_user", "ssh_key", "known_hosts")
if isinstance(incident, dict) and all(
    isinstance(incident.get(field), str) and incident[field]
    for field in transport_fields
):
    for destination_name in destination_names:
        destination = Path(destination_name)
        config = json.loads(destination.read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            continue
        updated = False
        for field in transport_fields:
            if config.get(field) != incident[field]:
                config[field] = incident[field]
                updated = True
        if not updated:
            continue
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            delete=False,
        ) as handle:
            json.dump(config, handle, indent=2)
            handle.write("\n")
            temporary = Path(handle.name)
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
PY
# Persist the already validated release marker while preserving every
# operator-owned secret and comment in the live .env.
/usr/bin/python3 "$STACK_DIR/bin/set-runtime-release-id.py" \
  --env-file "$STACK_DIR/.env" \
  --release-id "$RUNTIME_RELEASE_ID"

mkdir -p "$LAUNCHD_DIR"
for plist in \
  com.arron.n8n.ensure-stack.plist \
  com.arron.n8n.monitor-stack.plist \
  com.arron.soc.alert-store.plist \
  com.arron.soc.alert-store-maintenance.plist \
  com.arron.soc.pcap-analysis.plist \
  com.arron.soc.pcap-retention.plist \
  com.arron.soc.ai-analysis.plist \
  com.arron.soc.ai-analysis-cli.plist \
  com.arron.soc.dashboard-refresh.plist \
  com.arron.soc.daily-rollup.plist \
  com.arron.soc.dhcp-asset-discovery.plist \
  com.arron.soc.endpoint-software-inventory.plist \
  com.arron.soc.software-inventory.plist \
  com.arron.soc.ac-hunter.plist \
  com.arron.onion-sentinel.web.plist \
  com.arron.onion-sentinel.web-guard.plist \
  com.arron.onion-sentinel.harness-maintenance.plist \
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
/opt/homebrew/bin/node -e '
const version = process.argv[1];
const major = Number(String(version).split(".")[0]);
if (!Number.isInteger(major) || major < 11) {
  console.error(`Onion Sentinel locked install policy requires npm >=11; found ${version}`);
  process.exit(1);
}
' "$(/opt/homebrew/bin/npm --version)"
(
  cd "$STACK_DIR/alert_store"
  PATH="/opt/homebrew/bin:$PATH" /opt/homebrew/bin/npm ci --omit=dev
  PATH="/opt/homebrew/bin:$PATH" /opt/homebrew/bin/npm run check:install-scripts
)

/usr/local/bin/docker compose -f "$STACK_DIR/docker-compose.yml" --project-directory "$STACK_DIR" up -d
# Reload LaunchAgents so Docker/n8n are monitored after future reboots.
launchctl unload "$LAUNCHD_DIR/com.arron.n8n.ensure-stack.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.n8n.monitor-stack.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.soc.alert-store-maintenance.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.soc.pcap-analysis.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.soc.pcap-retention.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.soc.dashboard-refresh.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.soc.daily-rollup.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.soc.dhcp-asset-discovery.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.soc.endpoint-software-inventory.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.soc.software-inventory.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.soc.ac-hunter.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.onion-sentinel.web-guard.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.onion-sentinel.web.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.onion-sentinel.harness-maintenance.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.onion-sentinel.runtime-backup.plist" >/dev/null 2>&1 || true
launchctl load "$LAUNCHD_DIR/com.arron.n8n.ensure-stack.plist"
launchctl load "$LAUNCHD_DIR/com.arron.n8n.monitor-stack.plist"
launchctl load "$LAUNCHD_DIR/com.arron.soc.alert-store.plist"
# Cut an existing last-good Software Inventory snapshot over before the
# scheduled collector is loaded. This avoids a race where the dashboard starts
# against an empty database while the first relay collection is still running.
if [[ -s "$STACK_DIR/software-inventory/software-inventory.json" ]]; then
  alert_store_ready=false
  for _attempt in {1..30}; do
    if /usr/bin/curl --fail --silent --max-time 2 \
      "http://127.0.0.1:8787/health" >/dev/null; then
      alert_store_ready=true
      break
    fi
    sleep 1
  done
  if [[ "$alert_store_ready" != "true" ]]; then
    echo "Alert store did not become ready for Software Inventory migration." >&2
    exit 1
  fi
  software_snapshot_complete="$(/usr/bin/python3 - \
    "$STACK_DIR/software-inventory/software-inventory.json" <<'PY'
import json
from pathlib import Path
import sys

try:
    value = json.loads(Path(sys.argv[1]).read_text())
except (OSError, ValueError, TypeError):
    value = {}
print("true" if value.get("records") and value.get("collection", {}).get("complete") is True else "false")
PY
)"
  if [[ "$software_snapshot_complete" == "true" ]]; then
    /usr/bin/python3 \
      "$STACK_DIR/bin/migrate-software-inventory-to-postgres.py"
  elif /usr/bin/python3 - <<'PY'
import json
import urllib.request

limit = 1024 * 1024
with urllib.request.urlopen(
    "http://127.0.0.1:8787/software-inventory?limit=1",
    timeout=5,
) as response:
    raw = response.read(limit + 1)
if len(raw) > limit:
    raise SystemExit("Software Inventory preflight response exceeded its bound")
value = json.loads(raw)
if not (
    value.get("ok") is True
    and value.get("storage_backend") == "postgresql"
    and value.get("collection", {}).get("complete") is True
    and int(value.get("summary", {}).get("records") or 0) > 0
):
    raise SystemExit("existing PostgreSQL Software Inventory is incomplete")
PY
  then
    echo "Preserving the existing complete PostgreSQL Software Inventory; the latest local collection is incomplete."
  else
    echo "Refusing install: neither the local nor PostgreSQL Software Inventory is complete." >&2
    exit 1
  fi
fi
launchctl load "$LAUNCHD_DIR/com.arron.soc.alert-store-maintenance.plist"
launchctl load "$LAUNCHD_DIR/com.arron.soc.pcap-analysis.plist"
launchctl load "$LAUNCHD_DIR/com.arron.soc.pcap-retention.plist"
launchctl load "$LAUNCHD_DIR/com.arron.soc.ai-analysis.plist"
launchctl load "$LAUNCHD_DIR/com.arron.soc.ai-analysis-cli.plist"
launchctl load "$LAUNCHD_DIR/com.arron.soc.dashboard-refresh.plist"
launchctl load "$LAUNCHD_DIR/com.arron.soc.daily-rollup.plist"
launchctl load "$LAUNCHD_DIR/com.arron.soc.dhcp-asset-discovery.plist"
launchctl load "$LAUNCHD_DIR/com.arron.soc.endpoint-software-inventory.plist"
launchctl load "$LAUNCHD_DIR/com.arron.soc.software-inventory.plist"
launchctl load "$LAUNCHD_DIR/com.arron.soc.ac-hunter.plist"
launchctl load "$LAUNCHD_DIR/com.arron.onion-sentinel.web.plist"
launchctl load "$LAUNCHD_DIR/com.arron.onion-sentinel.web-guard.plist"
launchctl load "$LAUNCHD_DIR/com.arron.onion-sentinel.harness-maintenance.plist"
launchctl load "$LAUNCHD_DIR/com.arron.onion-sentinel.runtime-backup.plist"

# Signal the dashboard only after the tested builder and refresh worker are in
# place and the refresh LaunchAgent is loaded. Signaling at install start can
# race the source copy and publish a stale page for the next five-minute cycle.
touch "$STACK_DIR/run/dashboard-refresh.wake"
chmod 0600 "$STACK_DIR/run/dashboard-refresh.wake"

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
7. The PostgreSQL-backed AC Hunter collector is scheduled hourly at minute 35.
   Follow docs/ac-hunter-deep-review.md for its dedicated key, host pin,
   owner-only service credential, Relay trust, and validation procedure.

MSG
