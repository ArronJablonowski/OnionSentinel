'use strict';

function createAnalysisResultRoutes({service, readJsonBody, sendJson}) {
  if (!service || typeof service.submit !== 'function') {
    throw new TypeError('analysis result service is required');
  }
  for (const [name, value] of Object.entries({readJsonBody, sendJson})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  return [{
    method: 'POST',
    path: '/analysis/result',
    handler: async ({request, response}) => sendJson(
      response,
      200,
      await service.submit(await readJsonBody(request, true)),
    ),
  }];
}

module.exports = {createAnalysisResultRoutes};
