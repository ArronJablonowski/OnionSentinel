"""SOC, incident, catalog, and HTTP imports for the report-portal facade."""
from __future__ import annotations

from portal_soc_review_metadata import (
    SocReviewDependencies,
    apply_soc_review_metadata,
    embedded_reviewer as _soc_embedded_reviewer,
    parse_review_json as _soc_review_json,
    review_epoch as _modular_soc_review_epoch,
    review_final_status as _soc_review_final_status,
    review_defaults as _soc_review_defaults,
    reviewer_automation_authorization as _soc_reviewer_automation_authorization,
)
from portal_soc_evidence_metadata import (
    SocEvidenceDependencies,
    compose_soc_evidence_metadata,
)
from portal_soc_incident_metadata import (
    SocIncidentDependencies,
    apply_soc_incident_metadata,
    incident_defaults as _soc_incident_defaults,
)
from portal_soc_alert_presenter import (
    SocAlertPresentationDependencies,
    compose_soc_alert_row,
)
from portal_soc_ai_status import (
    SocAiStatusPolicy,
    compose_soc_ai_status,
    severity_meets_threshold as _modular_severity_meets_threshold,
)
from portal_soc_pcap_status import (
    SocPcapStatusDependencies,
    compose_pcap_status,
    load_pcap_request_statuses,
)
from portal_soc_pcap_artifacts import (
    PcapArtifactSources,
    build_pcap_analysis_index,
    has_parsed_pcap as _modular_has_parsed_pcap,
    newest_pcap_analysis_record,
)
from portal_soc_pcap_renderer import render_pcap_summary
from portal_soc_enrichment_status import compose_enrichment_status
from portal_soc_ai_artifact_context import (
    AiArtifactContextDependencies,
    compose_page_ai_artifact_context,
)
from portal_soc_ai_artifacts import (
    AiArtifactSources,
    AiGroupArtifactDependencies,
    build_ai_artifact_index,
    group_has_analysis_artifact as _modular_group_has_analysis_artifact,
    latest_analysis_mtime as _modular_latest_analysis_mtime,
    latest_prompt_mtime as _modular_latest_prompt_mtime,
)
from portal_soc_group_query import (
    SocAlertQuerySnapshot,
    SocGroupQueryDependencies,
    SocGroupQueryRequest,
    SocGroupQueryRequestPolicy,
    SocGroupSnapshotDependencies,
    compose_group_query_payload,
    compose_group_query_snapshot,
    fallback_query_plan,
    parse_group_query_request,
    summary_query_plan,
)
from portal_soc_group_enrichment import (
    group_enrichment_query_plan,
    merge_page_enrichment,
    page_group_keys,
    project_group_enrichment_rows,
)
from portal_soc_metrics import (
    compose_metrics_payload,
    compose_status_payload,
    exclude_group_rows,
    metrics_query_plan,
)
from portal_live_revisions import (
    RevisionSchemaDependencies,
    bounded_file_revision as _bounded_file_revision,
    incident_response_revision,
    revision_digest as _revision_digest,
)
from portal_metric_detail_renderer import (
    metric_detail_shell as render_metric_detail_shell,
    render_hermes_backups_detail as render_hermes_backup_metrics,
    render_local_disk_detail as render_local_disk_metrics,
    render_macos_updates_detail as render_macos_update_metrics,
    render_portal_update_detail as render_portal_update_metrics,
    render_prioritized_updates_detail as render_prioritized_update_metrics,
    render_system_uptime_detail as render_system_uptime_metrics,
)
from portal_incident_actions import (
    IncidentStatusPayloadError,
    normalize_incident_status_payload,
)
from portal_incident_read_model import (
    IncidentRowCallbacks,
    empty_incident_page,
    parse_incident_list_request,
)
from portal_incident_list_service import compose_incident_list_rows
from portal_incident_read_service import (
    IncidentReadServiceSources,
    incident_detail_response,
    incident_list_response,
)
from portal_incident_reanalysis import (
    IncidentReanalysisQueryError,
    compose_reanalysis_progress_payload,
    load_reanalysis_progress,
    parse_reanalysis_run_id,
)
from portal_incident_report_renderer import (
    IncidentReportRenderCallbacks,
    render_incident_response_report,
)
from portal_investigation_audit_renderer import (
    InvestigationAuditRenderCallbacks,
    render_investigation_query_audit,
)
from portal_review_panel_renderer import (
    ReviewPanelRenderCallbacks,
    render_analyst_review_panel as render_review_panel,
)
from portal_incident_review_model import (
    compose_incident_detail_payload,
    compose_incident_review_state,
    parse_analysis_response,
)
from portal_incident_repository import (
    incident_schema_ready,
    load_current_incident_analysis,
    load_incident_detail_records,
    load_incident_list_records,
    load_incident_review_records,
)
from portal_json_body import parse_json_body
from portal_request_routes import (
    classify_get_route,
    classify_post_route,
    head_content_type,
    is_head_route,
)
from portal_report_catalog import (
    Report,
    category_for as classify_report_category,
    human_size as format_human_size,
    is_daily_threat_brief_file as classify_daily_threat_brief,
    report_id as derive_report_id,
    scan_reports as discover_reports,
    should_skip_dir as exclude_report_directory,
    soc_alerts_default_path as project_soc_alerts_default_path,
    soc_alerts_report as select_soc_alerts_report,
    title_from_html as read_report_title,
)
from portal_soc_read_dispatch import (
    SocReadCallbacks,
    dispatch_soc_read,
)
from portal_soc_write_dispatch import SocWriteCallbacks, dispatch_authorized_soc_write
from portal_software_inventory_service import (
    AssetLabelSnapshot,
    append_incomplete_asset_warning,
    database_query_parameters,
    enrich_database_payload,
    load_asset_label_snapshot,
)
from portal_asset_inventory_service import (
    apply_asset_overlays,
    asset_public_record,
    asset_record_state,
    compose_local_response as compose_local_asset_inventory_response,
    current_asset_projection,
    database_query_parameters as asset_database_query_parameters,
    database_unavailable_payload as asset_database_unavailable_payload,
    resolve_asset_ip as resolve_asset_ip_record,
)
from portal_asset_dhcp_overlay import (
    annotate_exact_ip_dhcp_macs,
    dhcp_asset_inventory_overlay,
    mac_address_scope,
)
from portal_asset_mutation_service import (
    execute_asset_mutation,
    normalize_asset_mutation_payload,
    normalize_asset_review_payload,
)
from portal_asset_repository import AssetInventoryRepository, DhcpStateRepository
from portal_asset_store_client import (
    AlertStoreRequestError,
    AssetStoreClient,
    load_asset_store_write_token,
)
from portal_cti_program_service import (
    CtiProgramCallbacks,
    read_cti_program,
)
from portal_soc_settings_write import SocSettingsWriteCallbacks
from portal_admin_service_write import AdminServiceWriteCallbacks
from portal_resource_library_write import ResourceLibraryWriteCallbacks
from portal_resource_library_store import (
    clean_resource_tags as normalize_resource_tags,
    find_resource_library_pdf as locate_resource_library_pdf,
    load_resource_library_metadata as load_resource_metadata_file,
    move_resource_to_removal as move_resource_file_to_removal,
    rename_resource_file as rename_resource_library_file,
    resource_favorites as project_resource_favorites,
    resource_library_id_for as derive_resource_library_id,
    sanitize_resource_filename as normalize_resource_filename,
    save_resource_library_metadata as save_resource_metadata_file,
    set_resource_favorite as update_resource_favorite,
    set_resource_tags as update_resource_tags,
    unique_destination as available_resource_destination,
)
from portal_admin_form_service import AdminFormCallbacks, prepare_admin_form
from portal_admin_read_service import prepare_admin_read
from portal_health_read_service import compose_portal_health
from portal_http_handler import build_portal_handler
from portal_resource_action_read import read_resource_action_status
from portal_catalog_read_service import CatalogReadCallbacks, dispatch_catalog_read
from portal_catalog_delivery import CatalogDeliveryCallbacks, deliver_catalog_route
from portal_general_read_service import GeneralReadCallbacks, dispatch_general_read
from portal_post_intake import prepare_post_intake
from portal_json_write_service import JsonWriteCallbacks, dispatch_json_write
from portal_llm_runtime_state import llm_runtime_model_state
from portal_llm_activity import (
    compose_current_llm_analysis,
    decorate_llm_analysis_record as project_llm_analysis_record,
    llm_agent_execution_state as project_llm_agent_execution_state,
    merge_live_llm_activity as project_live_llm_activity,
)
from portal_llm_active_store import (
    ActiveLlmSources,
    active_llm_record_paths,
    llm_analysis_process_active as active_llm_process_present,
    llm_queue_size,
    read_active_llm_analyses as load_active_llm_analyses,
    read_bounded_llm_record,
)
from portal_llm_history import (
    PARENT_RUN_FIELDS as LLM_PARENT_RUN_FIELDS,
    compose_llm_activity_snapshot,
    hydrate_llm_reviewer_from_parent as hydrate_projected_llm_reviewer,
    llm_analysis_run_timestamp as projected_llm_run_timestamp,
    llm_log_sort_timestamp as projected_llm_log_sort_timestamp,
    llm_primary_run_identity as projected_llm_primary_identity,
    llm_reviewer_started_at as projected_llm_reviewer_started_at,
    project_adjudication_rows,
    project_database_primary_rows,
    project_second_opinion_rows,
    reconcile_llm_primary_logs as reconcile_projected_llm_primary_logs,
)
from portal_llm_history_store import (
    LlmHistoryStoreSources,
    read_adjudication_history_rows,
    read_primary_history_rows,
    read_second_opinion_history_rows,
)
from portal_llm_history_api import (
    LlmHistoryApiSources,
    llm_analysis_log_limit as bounded_llm_analysis_log_limit,
    llm_analysis_log_page as bounded_llm_analysis_log_page,
    llm_analysis_logs_response as compose_llm_analysis_logs_response,
    read_llm_agent_activity_snapshot as load_llm_agent_activity_snapshot,
)
from portal_soc_alert_status_write import (
    SocAlertStatusWriteSources,
    update_soc_alert_status as apply_soc_alert_status_update,
)
from portal_soc_alert_status_store import (
    SocAlertStatusStoreSources,
    ensure_soc_alert_status_schema,
    load_active_soc_group_ids,
    load_manually_escalated_group_ids,
    load_soc_alert_group_counts,
    load_soc_group_statuses,
    normalize_soc_alert_status_meta as normalize_status_meta,
    soc_alert_group_summary_available as group_summary_available,
    write_soc_group_status,
    write_soc_group_statuses,
)
from portal_soc_alert_status_service import (
    SocAlertStatusPersistenceSources,
    load_soc_alert_statuses as load_persisted_soc_alert_statuses,
    load_soc_alert_statuses_from_db as load_persisted_soc_alert_statuses_from_db,
    save_soc_alert_statuses as save_persisted_soc_alert_statuses,
    save_soc_alert_statuses_to_db as save_persisted_soc_alert_statuses_to_db,
    write_soc_alert_status as persist_soc_alert_status,
    write_soc_alert_status_json_snapshot as write_persisted_soc_alert_status_snapshot,
)
from portal_soc_adjudication_policy import (
    SOC_ANALYST_ACTIVITY_DISPOSITIONS,
    SOC_ANALYST_ADJUDICATION_OUTCOMES,
    SOC_ANALYST_DETECTION_VALIDITIES,
    SOC_ANALYST_EVENT_STATUSES,
    SOC_ANALYST_HANDLING_VALUES,
    adjudication_verdict_contradictions,
    derive_legacy_detection_outcome,
    legacy_verdict_factors,
    normalize_soc_adjudication_payload as normalize_adjudication_payload,
)
from portal_soc_adjudication_history import (
    SocAdjudicationHistorySources,
    read_soc_adjudication_history,
)
from portal_soc_pcap_request_policy import (
    PcapRequestPolicySources,
    bounded_int as bounded_pcap_int,
    normalize_pcap_request as normalize_pcap_request_policy,
    pcap_request_id as projected_pcap_request_id,
)
from portal_soc_pcap_request_store import (
    PcapRequestStoreSources,
    insert_pcap_request as store_pcap_request,
    pcap_capture_file_from_json as extract_pcap_capture_file,
    read_pcap_request_candidate,
)
from portal_soc_pcap_request_service import (
    PcapRequestServiceSources,
    request_soc_alert_pcap,
)
from portal_soc_action_service import (
    SocActionServiceSources,
    escalate_soc_alert,
    forward_controlled_dispatch_contract,
    queue_soc_alert_analysis,
)
from portal_sse_stream import send_soc_alert_events
from portal_beacon_history import project_beacon_history
from portal_n8n_container_status import (
    N8nContainerStatusSources,
    compose_n8n_container_status,
)
from response_cache import ResponseCache

__all__ = tuple(
    name for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
)
