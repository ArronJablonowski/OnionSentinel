'use strict';

const REQUIRED_COLUMNS = Object.freeze({
  alerts: [
    'alert_id', 'first_seen', 'last_seen', 'seen_count', 'timestamp', 'rule_name',
    'event_dataset', 'severity', 'severity_label', 'source_ip', 'source_port',
    'destination_ip', 'destination_port', 'network_protocol', 'transport_protocol',
    'traffic_direction', 'triage_score', 'triage_level', 'routing', 'filter_status',
    'filter_reason', 'suppression_key', 'raw_event_json', 'enrichment_json',
    'alert_json', 'rule_id', 'stable_group_id', 'stable_group_key',
  ],
  alert_group_summary: [
    'group_id', 'group_key', 'representative_alert_id', 'first_seen', 'last_seen',
    'raw_alert_count', 'total_seen_count', 'timestamp', 'rule_name', 'event_dataset',
    'severity', 'severity_label', 'source_ip', 'source_port', 'destination_ip',
    'destination_port', 'network_protocol', 'transport_protocol', 'traffic_direction',
    'triage_score', 'triage_level', 'routing', 'filter_status', 'filter_reason',
    'suppression_key', 'updated_at',
  ],
  alert_group_alias: ['legacy_group_id', 'stable_group_id', 'stable_group_key', 'updated_at'],
  ai_analysis_runs: [
    'analysis_id', 'group_id', 'alert_id', 'agent_role', 'generated_at', 'model',
    'model_path', 'detection_outcome', 'bluf', 'summary', 'confidence', 'artifact_path',
    'evidence_hash', 'response_json', 'created_at',
  ],
  ai_second_opinion_runs: [
    'analysis_id', 'group_id', 'alert_id', 'agent_role', 'trigger', 'status',
    'reviewer_error', 'primary_model', 'primary_model_path', 'primary_outcome',
    'primary_confidence', 'reviewer_model', 'reviewer_model_path', 'reviewer_outcome',
    'reviewer_confidence', 'agreement', 'material_disagreement', 'disputed_fields_json',
    'comparison_json', 'reviewer_runtime_seconds', 'memory_candidates_promoted',
    'generated_at', 'created_at', 'updated_at',
  ],
  ai_disagreement_adjudication_runs: [
    'analysis_id', 'group_id', 'alert_id', 'agent_role', 'status', 'mode',
    'adjudicator_error', 'model_route', 'decision', 'confidence', 'confidence_score',
    'resolved_fields_json', 'remaining_disagreements_json', 'evidence_used_json',
    'rationale', 'additional_evidence_needed_json', 'adjudicator_runtime_seconds',
    'automation_authorized', 'human_adjudication_required', 'generated_at',
    'created_at', 'updated_at',
  ],
  alert_correlations: [
    'source_group_id', 'related_group_id', 'analysis_id', 'correlation_score',
    'reasons_json', 'shared_observables_json', 'model_status', 'model_confidence',
    'model_hypothesis', 'created_at', 'updated_at',
  ],
  durable_jobs: [
    'id', 'job_type', 'dedupe_key', 'payload_json', 'status', 'priority',
    'attempt_count', 'max_attempts', 'next_attempt_at', 'lease_expires_at',
    'lease_token', 'last_error', 'created_at', 'updated_at', 'completed_at',
    'last_completed_at', 'processing_started_at', 'rerun_requested', 'requested_at',
  ],
  incident_response_cases: [
    'case_id', 'group_id', 'dashboard_group_id', 'representative_alert_id', 'status',
    'agent_status', 'escalated_at', 'updated_at', 'escalated_by', 'reason',
    'latest_analysis_id', 'latest_model', 'latest_generated_at', 'latest_error',
  ],
  incident_response_events: ['id', 'case_id', 'event_type', 'actor', 'detail_json', 'created_at'],
  incident_reanalysis_runs: [
    'run_id', 'release_id', 'scope', 'status', 'requested_by', 'reason', 'total_count',
    'created_at', 'updated_at', 'completed_at', 'controlled_dispatch_id',
    'controlled_receipt_json',
  ],
  incident_reanalysis_run_cases: [
    'run_id', 'case_id', 'group_id', 'dashboard_group_id', 'representative_alert_id',
    'status', 'skip_reason', 'latest_error', 'queued_at', 'started_at', 'completed_at',
    'latest_attempt_id', 'analysis_id', 'executed_model', 'executed_provider',
    'executed_model_path', 'result_generated_at', 'updated_at',
  ],
  incident_reanalysis_attempts: [
    'attempt_id', 'run_id', 'case_id', 'group_id', 'durable_attempt_count', 'status',
    'latest_error', 'analysis_id', 'executed_model', 'executed_provider',
    'executed_model_path', 'result_generated_at', 'started_at', 'completed_at', 'updated_at',
  ],
  pipeline_stage_events: [
    'id', 'event_key', 'stage', 'event_type', 'item_key', 'size_bytes', 'occurred_at',
  ],
});

function createControlledEvaluationSchema({all, get, initializeDurableJobs,
  initializePipelineMetrics}) {
  for (const [name, value] of Object.entries({all, get, initializeDurableJobs,
    initializePipelineMetrics})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function assertColumns() {
    for (const [tableName, columns] of Object.entries(REQUIRED_COLUMNS)) {
      const present = new Set(
        (await all(`PRAGMA table_info(${tableName})`)).map((row) => String(row.name || '')),
      );
      if (columns.some((column) => !present.has(column))) {
        throw new Error(`controlled evaluation schema is missing ${tableName} columns`);
      }
    }
  }

  async function assertDispatchIndex() {
    const name = 'idx_incident_reanalysis_runs_controlled_dispatch';
    const index = (await all('PRAGMA index_list(incident_reanalysis_runs)'))
      .find((row) => String(row.name || '') === name);
    const columns = index
      ? (await all(`PRAGMA index_info(${name})`)).map((row) => String(row.name || ''))
      : [];
    const definition = index ? await get(
      `SELECT sql FROM sqlite_master
       WHERE type = 'index' AND tbl_name = 'incident_reanalysis_runs'
         AND name = ?`,
      [name],
    ) : null;
    const sql = String(definition?.sql || '').replace(/\s+/g, ' ').trim().toLowerCase();
    if (!index || Number(index.unique || 0) !== 1 || Number(index.partial || 0) !== 1
      || columns.length !== 1 || columns[0] !== 'controlled_dispatch_id'
      || !/^create unique index(?: if not exists)? idx_incident_reanalysis_runs_controlled_dispatch on incident_reanalysis_runs\s*\(\s*controlled_dispatch_id\s*\)\s*where controlled_dispatch_id is not null;?$/.test(sql)) {
      throw new Error(
        'controlled evaluation schema is missing incident reanalysis dispatch uniqueness',
      );
    }
  }

  async function assertSchema() {
    const journalRow = await get('PRAGMA journal_mode');
    if (String(journalRow?.journal_mode || '').toLowerCase() !== 'delete') {
      throw new Error('controlled evaluation requires SQLite DELETE journal mode');
    }
    await assertColumns();
    await assertDispatchIndex();
    initializeDurableJobs();
    initializePipelineMetrics();
  }

  return {assertSchema};
}

module.exports = {REQUIRED_COLUMNS, createControlledEvaluationSchema};
