'use strict';

function createAiReviewSchema({run, ensureColumn}) {
  if (typeof run !== 'function') throw new TypeError('run must be a function');
  if (typeof ensureColumn !== 'function') throw new TypeError('ensureColumn must be a function');

  async function installSecondOpinions() {
    await run(`
      CREATE TABLE IF NOT EXISTS ai_second_opinion_runs (
        analysis_id TEXT PRIMARY KEY, group_id TEXT NOT NULL, alert_id TEXT NOT NULL,
        agent_role TEXT NOT NULL, trigger TEXT, status TEXT NOT NULL,
        reviewer_error TEXT, primary_model TEXT, primary_model_path TEXT,
        primary_outcome TEXT, primary_confidence TEXT, reviewer_model TEXT,
        reviewer_model_path TEXT, reviewer_outcome TEXT, reviewer_confidence TEXT,
        agreement TEXT, material_disagreement INTEGER NOT NULL DEFAULT 0,
        disputed_fields_json TEXT NOT NULL DEFAULT '[]',
        comparison_json TEXT NOT NULL DEFAULT '{}', reviewer_runtime_seconds REAL,
        memory_candidates_promoted INTEGER NOT NULL DEFAULT 0,
        generated_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      )
    `);
    await ensureColumn('ai_second_opinion_runs', 'reviewer_error', 'TEXT');
    await run('CREATE INDEX IF NOT EXISTS idx_ai_second_opinion_generated ON ai_second_opinion_runs(generated_at DESC)');
    await run('CREATE INDEX IF NOT EXISTS idx_ai_second_opinion_agreement ON ai_second_opinion_runs(agreement, generated_at DESC)');
    await run('CREATE INDEX IF NOT EXISTS idx_ai_second_opinion_group ON ai_second_opinion_runs(group_id, generated_at DESC)');
  }

  async function installMachineAdjudications() {
    await run(`
      CREATE TABLE IF NOT EXISTS ai_disagreement_adjudication_runs (
        analysis_id TEXT PRIMARY KEY, group_id TEXT NOT NULL, alert_id TEXT NOT NULL,
        agent_role TEXT NOT NULL, status TEXT NOT NULL,
        mode TEXT NOT NULL DEFAULT 'shadow', adjudicator_error TEXT, model_route TEXT,
        decision TEXT, confidence TEXT, confidence_score REAL,
        resolved_fields_json TEXT NOT NULL DEFAULT '[]',
        remaining_disagreements_json TEXT NOT NULL DEFAULT '[]',
        evidence_used_json TEXT NOT NULL DEFAULT '[]', rationale TEXT,
        additional_evidence_needed_json TEXT NOT NULL DEFAULT '[]',
        adjudicator_runtime_seconds REAL, automation_authorized INTEGER NOT NULL DEFAULT 0,
        human_adjudication_required INTEGER NOT NULL DEFAULT 1,
        generated_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      )
    `);
    await run('CREATE INDEX IF NOT EXISTS idx_ai_adjudication_generated ON ai_disagreement_adjudication_runs(generated_at DESC)');
    await run('CREATE INDEX IF NOT EXISTS idx_ai_adjudication_decision ON ai_disagreement_adjudication_runs(decision, generated_at DESC)');
    await run('CREATE INDEX IF NOT EXISTS idx_ai_adjudication_group ON ai_disagreement_adjudication_runs(group_id, generated_at DESC)');
  }

  async function installAnalystAdjudications() {
    await run(`
      CREATE TABLE IF NOT EXISTS analyst_adjudications (
        adjudication_id TEXT PRIMARY KEY, dashboard_group_id TEXT NOT NULL,
        stable_group_id TEXT NOT NULL, case_id TEXT, analysis_id TEXT NOT NULL,
        outcome_override TEXT NOT NULL, confidence TEXT NOT NULL, rationale TEXT NOT NULL,
        evidence_gap TEXT, next_action TEXT, reviewer TEXT NOT NULL, event_status TEXT,
        detection_validity TEXT, activity_disposition TEXT, handling TEXT,
        duplicate_of TEXT, case_resolution_reason TEXT, created_at TEXT NOT NULL
      )
    `);
    for (const name of ['event_status', 'detection_validity', 'activity_disposition',
      'handling', 'duplicate_of']) await ensureColumn('analyst_adjudications', name, 'TEXT');
    await run('CREATE INDEX IF NOT EXISTS idx_analyst_adjudications_group_created ON analyst_adjudications(dashboard_group_id, created_at DESC)');
    await run('CREATE INDEX IF NOT EXISTS idx_analyst_adjudications_analysis_created ON analyst_adjudications(analysis_id, created_at DESC)');
    await run('CREATE INDEX IF NOT EXISTS idx_analyst_adjudications_case_created ON analyst_adjudications(case_id, created_at DESC)');
  }

  async function installCorrelations() {
    await run(`
      CREATE TABLE IF NOT EXISTS alert_correlations (
        source_group_id TEXT NOT NULL, related_group_id TEXT NOT NULL,
        analysis_id TEXT NOT NULL, correlation_score REAL NOT NULL,
        reasons_json TEXT NOT NULL, shared_observables_json TEXT NOT NULL,
        model_status TEXT NOT NULL DEFAULT 'candidate', model_confidence TEXT,
        model_hypothesis TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        PRIMARY KEY (source_group_id, related_group_id)
      )
    `);
    await run('CREATE INDEX IF NOT EXISTS idx_alert_correlations_related ON alert_correlations(related_group_id, correlation_score DESC)');
    await run('CREATE INDEX IF NOT EXISTS idx_alert_correlations_source ON alert_correlations(source_group_id, correlation_score DESC)');
  }

  async function install() {
    await installSecondOpinions();
    await installMachineAdjudications();
    await installAnalystAdjudications();
    await installCorrelations();
  }

  return {install};
}

module.exports = {createAiReviewSchema};
