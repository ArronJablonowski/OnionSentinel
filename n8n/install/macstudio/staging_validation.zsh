# Sourced by install-macstudio-stack.zsh; retain the caller shell and traps.
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
import evaluation_artifact_contract
import evaluation_artifact_retention
import evaluation_artifact_seal
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
    "_onion_sentinel_evaluation_artifact_maintenance",
    bin_dir / "maintain-evaluation-artifacts.py",
)
load_file(
    "_onion_sentinel_evaluation_artifact_seal",
    bin_dir / "seal-evaluation-artifacts.py",
)
load_file(
    "_onion_sentinel_operational_slos",
    bin_dir / "evaluate-operational-slos.py",
)
load_file(
    "_onion_sentinel_sqlite_backup_recovery_gate",
    bin_dir / "sqlite_backup_recovery_gate.py",
)

sys.path.insert(0, str(dashboard_dir))
import portal_access_policy
import portal_access_enforcement
import portal_access_observer
import portal_access_observer_runtime
import portal_admin_audit_chain
import portal_admin_audit_store
import portal_session_principal
import portal_human_session_store
import portal_human_session_runtime
import portal_human_identity_store
import portal_human_identity_management
import portal_human_identity_cli
import portal_admin_recovery
import portal_admin_recovery_cli
import onion_sentinel_access_adapter
import onion_sentinel_auth_pages
import onion_sentinel_server
load_file(
    "_onion_sentinel_admin_recovery",
    dashboard_dir / "recover-admin-access.py",
)
load_file(
    "_onion_sentinel_human_identity_management",
    dashboard_dir / "manage-human-identities.py",
)

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
