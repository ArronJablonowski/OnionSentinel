'use strict';

function createAnalysisResultService({
  controlledEvaluationMode,
  requestHasOwnField,
  identityConflict,
  withWriteGate,
  withTransaction,
  controlledResultAdmission,
  recordAnalysisResult,
  transitionJobStatus,
  applyControlledResultAdmission,
}) {
  for (const [name, value] of Object.entries({
    controlledEvaluationMode,
    requestHasOwnField,
    identityConflict,
    withWriteGate,
    withTransaction,
    controlledResultAdmission,
    recordAnalysisResult,
    transitionJobStatus,
    applyControlledResultAdmission,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function submit(payload) {
    if (
      !controlledEvaluationMode()
      && requestHasOwnField(payload, 'controlled_job')
    ) {
      throw identityConflict(
        'controlled result identity requires controlled evaluation mode',
      );
    }
    const result = await withWriteGate(async () => {
      let admission = null;
      const recorded = await withTransaction(async () => {
        admission = await controlledResultAdmission(payload);
        const stored = await recordAnalysisResult(payload);
        if (controlledEvaluationMode() && admission?.completeRequired) {
          const completed = await transitionJobStatus(
            admission.jobType,
            admission.stableGroupId,
            'completed',
            '',
            admission.leaseToken,
            true,
          );
          if (!completed.updated) {
            throw identityConflict(
              'controlled evaluation result could not complete its exact job',
            );
          }
        }
        return stored;
      });
      applyControlledResultAdmission(admission);
      return recorded;
    });
    return {...result, submission_sha256: payload.__body_sha256};
  }

  return {submit};
}

module.exports = {createAnalysisResultService};
