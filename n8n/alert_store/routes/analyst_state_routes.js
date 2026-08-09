'use strict';

function createAnalystStateRoutes({service, readJsonBody, sendJson}) {
  if (!service || typeof service !== 'object') {
    throw new TypeError('analyst state service is required');
  }
  for (const [name, value] of Object.entries({readJsonBody, sendJson})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  return [
    {
      method: 'GET',
      path: '/analyst-status',
      handler: async ({response}) => sendJson(
        response, 200, await service.statusSnapshot(),
      ),
    },
    {
      method: 'POST',
      path: '/analyst-status',
      handler: async ({request, response}) => sendJson(
        response, 200, await service.putStatus(await readJsonBody(request)),
      ),
    },
    {
      method: 'GET',
      path: '/adjudications',
      handler: async ({response, parsedUrl}) => sendJson(
        response, 200, await service.adjudicationSnapshot(parsedUrl.searchParams),
      ),
    },
    {
      method: 'POST',
      path: '/adjudications',
      handler: async ({request, response}) => sendJson(
        response, 201, await service.recordAdjudication(await readJsonBody(request)),
      ),
    },
    {
      method: 'POST',
      path: '/incidents/status',
      handler: async ({request, response}) => sendJson(
        response, 200, await service.putIncidentStatus(await readJsonBody(request)),
      ),
    },
  ];
}

module.exports = {createAnalystStateRoutes};
