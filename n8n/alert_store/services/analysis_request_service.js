'use strict';

function createAnalysisRequestService({
  controlledEvaluationMode,
  identityConflict,
  withWriteGate,
  withTransaction,
  requestAiReanalysis,
  requestIncidentEscalation,
  requestIncidentReanalysis,
  retireControlledEvaluation,
  signalAiWorkers,
}) {
  for (const [name, value] of Object.entries({
    controlledEvaluationMode,
    identityConflict,
    withWriteGate,
    withTransaction,
    requestAiReanalysis,
    requestIncidentEscalation,
    requestIncidentReanalysis,
    retireControlledEvaluation,
    signalAiWorkers,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  const transactionally = (operation) => withWriteGate(
    () => withTransaction(operation),
  );

  function requireControlledCohort(payload) {
    if (controlledEvaluationMode() && !payload?.cohort_id) {
      throw identityConflict(
        'controlled evaluation requires a frozen cohort dispatch identity',
      );
    }
  }

  async function requestAi(payload) {
    requireControlledCohort(payload);
    const result = await transactionally(() => requestAiReanalysis(payload));
    void signalAiWorkers('manual-ai-reanalysis');
    return result;
  }

  async function escalateIncident(payload) {
    const result = await transactionally(() => requestIncidentEscalation(payload));
    void signalAiWorkers('incident-response-escalation');
    return result;
  }

  async function reanalyzeIncident(payload) {
    requireControlledCohort(payload);
    const result = await transactionally(
      () => requestIncidentReanalysis(payload, payload?.case_id),
    );
    void signalAiWorkers('incident-response-case-reanalysis');
    return result;
  }

  async function retireEvaluation(payload) {
    return transactionally(() => retireControlledEvaluation(payload));
  }

  async function reanalyzeAllIncidents(payload) {
    const result = await transactionally(() => requestIncidentReanalysis(payload));
    void signalAiWorkers('incident-response-bulk-reanalysis');
    return result;
  }

  return {
    requestAi,
    escalateIncident,
    reanalyzeIncident,
    retireEvaluation,
    reanalyzeAllIncidents,
  };
}

module.exports = {createAnalysisRequestService};
