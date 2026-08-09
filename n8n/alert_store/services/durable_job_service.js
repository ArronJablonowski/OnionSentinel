'use strict';

function createDurableJobService({
  safeString,
  withWriteGate,
  withTransaction,
  controlledTransitionAdmission,
  transitionJobStatus,
  applyControlledTransition,
  completePendingByDedupeKeys,
}) {
  for (const [name, value] of Object.entries({
    safeString,
    withWriteGate,
    withTransaction,
    controlledTransitionAdmission,
    transitionJobStatus,
    applyControlledTransition,
    completePendingByDedupeKeys,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function transitionStatus(payload) {
    const jobType = safeString(payload?.job_type, 64);
    const dedupeKey = safeString(payload?.dedupe_key, 256);
    const status = safeString(payload?.status, 32).toLowerCase();
    const leaseToken = safeString(payload?.lease_token, 128);
    const retryable = payload?.retryable !== false;
    if (!jobType || !dedupeKey) {
      throw new Error('job_type and dedupe_key are required');
    }
    const transition = await withWriteGate(async () => {
      let controlledAdmission = null;
      const committed = await withTransaction(async () => {
        controlledAdmission = await controlledTransitionAdmission(payload);
        return transitionJobStatus(
          jobType,
          dedupeKey,
          status,
          safeString(payload?.error, 1000),
          leaseToken,
          retryable,
          payload,
        );
      });
      applyControlledTransition(controlledAdmission, committed);
      return committed;
    });
    return {
      updated: transition.updated,
      job_type: jobType,
      dedupe_key: transition.resolvedKey,
      status,
      lease_token: transition.leaseToken,
      claim: transition.claim || null,
    };
  }

  async function reconcileCompleted(payload) {
    const jobType = safeString(payload?.job_type, 64);
    const dedupeKeys = Array.isArray(payload?.dedupe_keys)
      ? payload.dedupe_keys
        .map((value) => safeString(value, 256))
        .filter(Boolean)
        .slice(0, 2000)
      : [];
    if (!jobType || !dedupeKeys.length) {
      throw new Error('job_type and dedupe_keys are required');
    }
    const reconciled = await withWriteGate(
      () => withTransaction(
        () => completePendingByDedupeKeys(jobType, dedupeKeys),
      ),
    );
    return {job_type: jobType, reconciled};
  }

  return {transitionStatus, reconcileCompleted};
}

module.exports = {createDurableJobService};
