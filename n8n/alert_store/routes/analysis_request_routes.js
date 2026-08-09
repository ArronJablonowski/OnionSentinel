'use strict';

function createAnalysisRequestRoutes({service, readJsonBody, sendJson}) {
  if (!service || typeof service !== 'object') {
    throw new TypeError('analysis request service is required');
  }
  for (const [name, value] of Object.entries({readJsonBody, sendJson})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  return [
    ['/ai/request', 'requestAi', 202],
    ['/incidents/escalate', 'escalateIncident', 202],
    ['/incidents/reanalyze', 'reanalyzeIncident', 202],
    ['/controlled-evaluations/retire', 'retireEvaluation', 200],
    ['/incidents/reanalyze-all', 'reanalyzeAllIncidents', 202],
  ].map(([path, method, status]) => ({
    method: 'POST',
    path,
    handler: async ({request, response}) => sendJson(
      response,
      status,
      await service[method](await readJsonBody(request)),
    ),
  }));
}

module.exports = {createAnalysisRequestRoutes};
