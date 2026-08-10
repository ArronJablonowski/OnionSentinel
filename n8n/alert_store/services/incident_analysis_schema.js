'use strict';

function createIncidentAnalysisSchema({run, ensureColumn}) {
  if (typeof run !== 'function') throw new TypeError('run must be a function');
  if (typeof ensureColumn !== 'function') throw new TypeError('ensureColumn must be a function');

  async function installAnalysisRuns() {
    await run(`
      CREATE TABLE IF NOT EXISTS ai_analysis_runs (
        analysis_id TEXT PRIMARY KEY, group_id TEXT NOT NULL, alert_id TEXT NOT NULL,
        agent_role TEXT NOT NULL DEFAULT 'soc-analyst', generated_at TEXT NOT NULL,
        model TEXT, model_path TEXT, detection_outcome TEXT, bluf TEXT, summary TEXT,
        confidence TEXT, artifact_path TEXT, evidence_hash TEXT,
        response_json TEXT NOT NULL, created_at TEXT NOT NULL
      )
    `);
    await ensureColumn('ai_analysis_runs', 'agent_role', "TEXT NOT NULL DEFAULT 'soc-analyst'");
    await run('CREATE INDEX IF NOT EXISTS idx_ai_analysis_runs_group ON ai_analysis_runs(group_id, generated_at DESC)');
    await run('CREATE INDEX IF NOT EXISTS idx_ai_analysis_runs_alert ON ai_analysis_runs(alert_id, generated_at DESC)');
    await run('CREATE INDEX IF NOT EXISTS idx_ai_analysis_runs_role_group ON ai_analysis_runs(agent_role, group_id, generated_at DESC)');
  }

  async function installIncidentCases() {
    await run(`
      CREATE TABLE IF NOT EXISTS incident_response_cases (
        case_id TEXT PRIMARY KEY, group_id TEXT NOT NULL UNIQUE,
        dashboard_group_id TEXT NOT NULL, representative_alert_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open'
          CHECK(status IN ('open', 'in_progress', 'resolved')),
        agent_status TEXT NOT NULL DEFAULT 'queued'
          CHECK(agent_status IN ('queued', 'analyzing', 'analyzed', 'failed')),
        escalated_at TEXT NOT NULL, updated_at TEXT NOT NULL, escalated_by TEXT,
        reason TEXT, latest_analysis_id TEXT, latest_model TEXT,
        latest_generated_at TEXT, latest_error TEXT
      )
    `);
    await run('CREATE INDEX IF NOT EXISTS idx_incident_cases_status_updated ON incident_response_cases(status, updated_at DESC)');
    await run('CREATE INDEX IF NOT EXISTS idx_incident_cases_agent_status ON incident_response_cases(agent_status, updated_at DESC)');
    await run('CREATE INDEX IF NOT EXISTS idx_incident_cases_dashboard_group ON incident_response_cases(dashboard_group_id)');
    await ensureColumn('incident_response_cases', 'resolution_reason', 'TEXT');
    await ensureColumn('incident_response_cases', 'resolved_at', 'TEXT');
    await ensureColumn('incident_response_cases', 'resolved_by', 'TEXT');
    await run(`
      CREATE TABLE IF NOT EXISTS incident_response_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL,
        event_type TEXT NOT NULL, actor TEXT, detail_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        FOREIGN KEY(case_id) REFERENCES incident_response_cases(case_id)
      )
    `);
    await run('CREATE INDEX IF NOT EXISTS idx_incident_events_case_created ON incident_response_events(case_id, created_at DESC)');
  }

  async function installReanalysisRuns() {
    await run(`
      CREATE TABLE IF NOT EXISTS incident_reanalysis_runs (
        run_id TEXT PRIMARY KEY, release_id TEXT NOT NULL,
        scope TEXT NOT NULL CHECK(scope IN ('single_case', 'all_cases')),
        status TEXT NOT NULL DEFAULT 'queued'
          CHECK(status IN ('queued', 'running', 'completed', 'partial', 'failed')),
        requested_by TEXT, reason TEXT, total_count INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL, completed_at TEXT
      )
    `);
    await run('CREATE INDEX IF NOT EXISTS idx_incident_reanalysis_runs_created ON incident_reanalysis_runs(created_at DESC)');
    await ensureColumn('incident_reanalysis_runs', 'controlled_dispatch_id', 'TEXT');
    await ensureColumn('incident_reanalysis_runs', 'controlled_receipt_json', 'TEXT');
    await run(`CREATE UNIQUE INDEX IF NOT EXISTS
      idx_incident_reanalysis_runs_controlled_dispatch
      ON incident_reanalysis_runs(controlled_dispatch_id)
      WHERE controlled_dispatch_id IS NOT NULL`);
    await run(`
      CREATE TABLE IF NOT EXISTS incident_reanalysis_run_cases (
        run_id TEXT NOT NULL, case_id TEXT NOT NULL, group_id TEXT NOT NULL,
        dashboard_group_id TEXT NOT NULL, representative_alert_id TEXT NOT NULL,
        status TEXT NOT NULL
          CHECK(status IN ('queued', 'running', 'completed', 'failed', 'skipped')),
        skip_reason TEXT, latest_error TEXT, queued_at TEXT, started_at TEXT,
        completed_at TEXT, latest_attempt_id TEXT, analysis_id TEXT,
        executed_model TEXT, executed_provider TEXT, executed_model_path TEXT,
        result_generated_at TEXT, updated_at TEXT NOT NULL,
        PRIMARY KEY(run_id, case_id),
        FOREIGN KEY(run_id) REFERENCES incident_reanalysis_runs(run_id),
        FOREIGN KEY(case_id) REFERENCES incident_response_cases(case_id)
      )
    `);
    for (const name of ['latest_attempt_id', 'analysis_id', 'executed_model',
      'executed_provider', 'executed_model_path', 'result_generated_at']) {
      await ensureColumn('incident_reanalysis_run_cases', name, 'TEXT');
    }
    await run('CREATE INDEX IF NOT EXISTS idx_incident_reanalysis_cases_status ON incident_reanalysis_run_cases(run_id, status)');
    await run('CREATE INDEX IF NOT EXISTS idx_incident_reanalysis_cases_case ON incident_reanalysis_run_cases(case_id, updated_at DESC)');
  }

  async function installReanalysisAttempts() {
    await run(`
      CREATE TABLE IF NOT EXISTS incident_reanalysis_attempts (
        attempt_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, case_id TEXT NOT NULL,
        group_id TEXT NOT NULL, durable_attempt_count INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL CHECK(status IN ('running', 'completed', 'failed')),
        latest_error TEXT, analysis_id TEXT, executed_model TEXT,
        executed_provider TEXT, executed_model_path TEXT, result_generated_at TEXT,
        started_at TEXT NOT NULL, completed_at TEXT, updated_at TEXT NOT NULL,
        FOREIGN KEY(run_id, case_id)
          REFERENCES incident_reanalysis_run_cases(run_id, case_id)
      )
    `);
    await run('CREATE INDEX IF NOT EXISTS idx_incident_reanalysis_attempts_case ON incident_reanalysis_attempts(run_id, case_id, started_at DESC)');
    await run('CREATE INDEX IF NOT EXISTS idx_incident_reanalysis_attempts_group ON incident_reanalysis_attempts(group_id, started_at DESC)');
    await run('CREATE UNIQUE INDEX IF NOT EXISTS idx_incident_reanalysis_attempts_analysis ON incident_reanalysis_attempts(analysis_id) WHERE analysis_id IS NOT NULL');
  }

  async function install() {
    await installAnalysisRuns();
    await installIncidentCases();
    await installReanalysisRuns();
    await installReanalysisAttempts();
  }

  return {install};
}

module.exports = {createIncidentAnalysisSchema};
