"""Administration and operational imports for the report-portal facade."""
from __future__ import annotations

from portal_admin_dashboard import (
    AdminDashboardSources,
    compose_admin_dashboard,
    render_admin_dashboard as render_admin_dashboard_view,
)
from portal_admin_versions import (
    AdminVersionSources,
    compose_admin_action_version_info,
)
from portal_admin_availability import (
    AdminAvailabilitySources,
    AdminCommandOutcome,
    compose_admin_action_availability,
)
from portal_cron_failures import (
    CronFailureSources,
    compose_cron_failure_records,
    render_cron_failure_log,
)
from portal_admin_action_state import (
    AdminActionStateSources,
    action_log_path,
    action_status_path,
    claim_action_lock,
    latest_action_outcome,
    read_action_lock,
    read_action_status,
    release_action_lock,
    running_action,
    update_action_lock_pid,
    write_action_status,
)
from portal_admin_action_runner import (
    AdminActionRunnerSources,
    start_admin_action as run_admin_action,
)
from portal_admin_session_store import (
    admin_session_cookie_header as compose_admin_session_cookie,
    admin_session_hash as derive_admin_session_hash,
    create_admin_session as create_persisted_admin_session,
    destroy_admin_session as destroy_persisted_admin_session,
    ensure_admin_token as ensure_persisted_admin_token,
    expired_admin_session_cookie_header as compose_expired_admin_session_cookie,
    load_admin_password_record as load_persisted_admin_password_record,
    load_admin_sessions as load_persisted_admin_sessions,
    parse_cookie_header as parse_request_cookie_header,
    prune_admin_sessions as prune_persisted_admin_sessions,
    save_admin_sessions as save_persisted_admin_sessions,
    verify_admin_password as verify_persisted_admin_password,
)
from portal_admin_service_probes import (
    AdminServiceProbeSources,
    ServiceCommandOutcome,
    codex_app_status as probe_codex_app_status,
    codex_cli_status as probe_codex_cli_status,
    docker_status as probe_docker_status,
    macs_fan_control_status as probe_macs_fan_control_status,
    matching_process_lines,
)
from portal_admin_services import (
    AdminServiceStartSources,
    compose_admin_service_statuses,
    start_admin_service as start_allowed_admin_service,
)
from portal_disk_inventory import (
    DiskInventorySources,
    DiskScanOutcome,
    compose_local_disk_inventory,
    compose_local_disk_usage,
)
from portal_hermes_backup_health import (
    HermesBackupSources,
    backup_base_path,
    backup_timestamp_from_name,
    compose_backup_inventory,
    compose_latest_hermes_backup_metric,
)
from portal_update_health import (
    UpdateCommandOutcome,
    UpdateHealthSources,
    compose_brew_update_source_metric,
    compose_hermes_update_source_metric,
    compose_latest_running_update_action,
    compose_latest_update_action_failure,
    compose_macos_update_metric,
    compose_prioritized_updates_metric,
    read_macos_update_status as load_macos_update_status,
)
from portal_pcap_health import PcapHealthSources, compose_pcap_workflow_health
from portal_home_dashboard import (
    HomeDashboardSources,
    compose_home_dashboard,
    render_home_dashboard,
)
from portal_dhcp_discovery import (
    DhcpDiscoveryDependencies,
    compose_dhcp_discovery_response,
)

__all__ = tuple(
    name for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
)
