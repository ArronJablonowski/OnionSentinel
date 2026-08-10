'use strict';

function createIncidentReanalysisRunPersistence({get, all, run, nowUtc}) {
  async function snapshot(runId) {
    const runRow = await get(
      `SELECT run_id, release_id, scope, status, requested_by, reason,
              total_count, created_at, updated_at, completed_at
       FROM incident_reanalysis_runs WHERE run_id = ?`,
      [runId],
    );
    if (!runRow) return null;
    const counts = {queued: 0, running: 0, completed: 0, failed: 0, skipped: 0};
    const rows = await all(
      `SELECT status, COUNT(*) AS count
       FROM incident_reanalysis_run_cases WHERE run_id = ? GROUP BY status`,
      [runId],
    );
    for (const row of rows) {
      if (Object.prototype.hasOwnProperty.call(counts, row.status)) {
        counts[row.status] = Number(row.count || 0);
      }
    }
    return {...runRow, total_count: Number(runRow.total_count || 0), counts};
  }

  async function refresh(runId) {
    if (!runId) return null;
    const current = await snapshot(runId);
    if (!current) return null;
    const {counts} = current;
    const terminal = counts.completed + counts.failed + counts.skipped;
    let status = 'queued';
    if (counts.running > 0) status = 'running';
    else if (counts.queued > 0) status = 'queued';
    else if (current.total_count === 0) status = 'completed';
    else if (counts.failed === current.total_count) status = 'failed';
    else if (
      terminal >= current.total_count
      && (counts.failed > 0 || counts.skipped > 0)
    ) status = 'partial';
    else if (terminal >= current.total_count) status = 'completed';
    const updatedAt = nowUtc();
    const completedAt = ['completed', 'partial', 'failed'].includes(status)
      ? updatedAt
      : null;
    await run(
      `UPDATE incident_reanalysis_runs
       SET status = ?, updated_at = ?, completed_at = ?
       WHERE run_id = ?`,
      [status, updatedAt, completedAt, runId],
    );
    return snapshot(runId);
  }

  async function supersedeCase(caseId, replacementRunId, updatedAt) {
    const priorRuns = await all(
      `SELECT DISTINCT run_id FROM incident_reanalysis_run_cases
       WHERE case_id = ? AND status = 'queued' AND run_id != ?`,
      [caseId, replacementRunId],
    );
    if (!priorRuns.length) return;
    await run(
      `UPDATE incident_reanalysis_run_cases
       SET status = 'skipped', skip_reason = ?, latest_error = NULL,
           completed_at = ?, updated_at = ?
       WHERE case_id = ? AND status = 'queued' AND run_id != ?`,
      [
        `Superseded by newer reanalysis run ${replacementRunId}`,
        updatedAt,
        updatedAt,
        caseId,
        replacementRunId,
      ],
    );
    for (const item of priorRuns) await refresh(String(item.run_id || ''));
  }

  return {refresh, snapshot, supersedeCase};
}

module.exports = {createIncidentReanalysisRunPersistence};
