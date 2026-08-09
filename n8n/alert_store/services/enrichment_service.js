'use strict';

function createEnrichmentService({
  assertDiskWriteAdmission,
  enrichAlert,
  cachedInvestigationEnrichment,
  queryInvestigationEnrichment,
}) {
  for (const [name, value] of Object.entries({
    assertDiskWriteAdmission,
    enrichAlert,
    cachedInvestigationEnrichment,
    queryInvestigationEnrichment,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function enrich(payload) {
    assertDiskWriteAdmission('alert enrichment');
    return enrichAlert(payload);
  }

  async function cachedInvestigation(payload) {
    return cachedInvestigationEnrichment(
      payload?.indicator_type,
      payload?.indicator,
    );
  }

  async function queryInvestigation(payload) {
    assertDiskWriteAdmission('investigation enrichment');
    return queryInvestigationEnrichment(
      payload?.indicator_type,
      payload?.indicator,
    );
  }

  return {enrich, cachedInvestigation, queryInvestigation};
}

module.exports = {createEnrichmentService};
