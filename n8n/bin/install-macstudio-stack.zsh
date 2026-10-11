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

installer_usage() {
  print -r -- "Usage: n8n/bin/install-macstudio-stack.zsh [--validate-only]"
  print -r -- ""
  print -r -- "Options:"
  print -r -- "  --validate-only  Validate staged production sources and exit before deployment."
  print -r -- "  -h, --help       Show this help and exit."
}

parse_installer_arguments() {
  local validate_only_requested=0
  local help_requested=0
  local argument
  for argument in "$@"; do
    case "$argument" in
      --validate-only)
        validate_only_requested=1
        ;;
      -h|--help)
        help_requested=1
        ;;
      *)
        print -r -- "Unknown installer argument: $argument" >&2
        installer_usage >&2
        return 2
        ;;
    esac
  done
  if (( help_requested )); then
    installer_usage
    exit 0
  fi
  if [[ "${ONION_SENTINEL_VALIDATE_ONLY:-0}" != "0" \
    && "${ONION_SENTINEL_VALIDATE_ONLY:-0}" != "1" ]]; then
    print -r -- "ONION_SENTINEL_VALIDATE_ONLY must be 0 or 1." >&2
    return 2
  fi
  if (( validate_only_requested )); then
    ONION_SENTINEL_VALIDATE_ONLY=1
  fi
}

parse_installer_arguments "$@"

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

# Source-only qualification is not proof that the host has approved credential
# lifecycle records. Check the deployed inventory before stopping services or
# replacing any runtime code; startup must never be the first discovery point.
if [[ "${ONION_SENTINEL_VALIDATE_ONLY:-0}" != "1" ]] && ! /usr/bin/env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/python3 "$REPO_DIR/operations/validate-credential-governance.py" \
  --deployed-runtime \
  --catalog "$REPO_DIR/operations/security/credential-governance.json" \
  --inventory "$STACK_DIR/config/service-identity-inventory.json" >/dev/null
then
  echo "Refusing install before service changes: credential lifecycle inventory is missing or invalid." >&2
  exit 78
fi

source "$REPO_DIR/n8n/install/macstudio/staging_validation.zsh" "$@"
trap cleanup_alert_store_stage EXIT
prepare_alert_store_stage
validate_production_python_sources
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 \
  "$REPO_DIR/operations/validate-credential-governance.py" \
  --catalog "$REPO_DIR/operations/security/credential-governance.json" >/dev/null
if [[ "${ONION_SENTINEL_VALIDATE_ONLY:-0}" == "1" ]]; then
  echo "Mac Studio installer preflight validation passed."
  exit 0
fi

# Take the same advisory locks used by both AI scheduler lanes before touching
# launchd or runtime files. A nonblocking failure means an investigation is in
# flight, so leave every service running and ask the operator to retry. Holding
# both locks across the install also closes the check/unload race: WatchPath or
# timer activity cannot start a new inference while code is being replaced.
source "$REPO_DIR/n8n/install/macstudio/investigation_guard.zsh" "$@"
if ! start_ai_deployment_guard; then
  exit 3
fi

# These jobs execute files replaced below. Stop only those code consumers
# before the first runtime copy; unrelated monitoring, PCAP, dashboard, backup,
# and Docker services stay up until their normal final reload phase.
source "$REPO_DIR/n8n/install/macstudio/service_quiescence.zsh" "$@"
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

mkdir -p "$STACK_DIR/alert_store/config" "$STACK_DIR/alert_store/lib" "$STACK_DIR/postgres" "$STACK_DIR/bin" "$STACK_DIR/cache" "$STACK_DIR/config" "$STACK_DIR/config/maxmind" "$STACK_DIR/admin-state" "$STACK_DIR/logs" "$STACK_DIR/run" "$STACK_DIR/python" "$STACK_DIR/alert_store_data" "$STACK_DIR/alert_store_postgres_data" "$STACK_DIR/n8n_data" "$STACK_DIR/soc-alerts" "$STACK_DIR/soc-alerts/agent-memory" "$STACK_DIR/soc-alerts/pcap-analysis" "$STACK_DIR/pcap-evidence/artifacts" "$STACK_DIR/asset-discovery" "$STACK_DIR/software-inventory"
chmod 0700 "$STACK_DIR/cache"
chmod 0700 "$STACK_DIR/config"
chmod 0700 "$STACK_DIR/admin-state"
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
cp "$REPO_DIR/n8n/bin/sqlite_online_backup.py" "$STACK_DIR/bin/sqlite_online_backup.py"
cp "$REPO_DIR/n8n/bin/sqlite_backup_recovery_gate.py" "$STACK_DIR/bin/sqlite_backup_recovery_gate.py"
source "$REPO_DIR/n8n/install/macstudio/runtime_payload.zsh" "$@"
source "$REPO_DIR/n8n/install/macstudio/dashboard_payload.zsh" "$@"
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
  com.arron.onion-sentinel.evaluation-artifact-maintenance.plist \
  com.arron.onion-sentinel.application-log-maintenance.plist \
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
launchctl unload "$LAUNCHD_DIR/com.arron.onion-sentinel.evaluation-artifact-maintenance.plist" >/dev/null 2>&1 || true
launchctl unload "$LAUNCHD_DIR/com.arron.onion-sentinel.application-log-maintenance.plist" >/dev/null 2>&1 || true
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
wait_for_harness_maintenance_readiness
launchctl load "$LAUNCHD_DIR/com.arron.onion-sentinel.harness-maintenance.plist"
launchctl load "$LAUNCHD_DIR/com.arron.onion-sentinel.evaluation-artifact-maintenance.plist"
launchctl load "$LAUNCHD_DIR/com.arron.onion-sentinel.application-log-maintenance.plist"
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
