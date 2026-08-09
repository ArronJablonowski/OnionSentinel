'use strict';

function createAnalystStateService({
  analystStatusSnapshot,
  updateAnalystStatus,
  analystAdjudicationSnapshot,
  recordAnalystAdjudication,
  updateIncidentCaseStatus,
  withWriteGate,
  withTransaction,
}) {
  for (const [name, value] of Object.entries({
    analystStatusSnapshot,
    updateAnalystStatus,
    analystAdjudicationSnapshot,
    recordAnalystAdjudication,
    updateIncidentCaseStatus,
    withWriteGate,
    withTransaction,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  const transactionalWrite = (operation) => withWriteGate(
    () => withTransaction(operation),
  );

  return {
    statusSnapshot: () => analystStatusSnapshot(),
    putStatus: (payload) => updateAnalystStatus(payload),
    adjudicationSnapshot: (searchParams) => analystAdjudicationSnapshot(searchParams),
    recordAdjudication: (payload) => transactionalWrite(
      () => recordAnalystAdjudication(payload),
    ),
    putIncidentStatus: (payload) => transactionalWrite(
      () => updateIncidentCaseStatus(payload),
    ),
  };
}

module.exports = {createAnalystStateService};
