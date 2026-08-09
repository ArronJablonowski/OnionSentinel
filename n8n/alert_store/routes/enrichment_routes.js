'use strict';

function createEnrichmentRoutes({
  service,
  authorizeInvestigation,
  readJsonBody,
  sendJson,
}) {
  if (!service || typeof service !== 'object') {
    throw new TypeError('enrichment service is required');
  }
  for (const [name, value] of Object.entries({
    authorizeInvestigation,
    readJsonBody,
    sendJson,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  return [
    {
      method: 'POST',
      path: '/enrich',
      handler: async ({request, response}) => {
        if (request.url !== '/enrich') {
          sendJson(response, 404, {ok: false, status: 'not_found'});
          return;
        }
        const result = await service.enrich(await readJsonBody(request));
        sendJson(response, result.ok ? 200 : 400, result);
      },
    },
    {
      method: 'POST',
      path: '/investigations/enrichment/cache',
      handler: async ({request, response}) => {
        authorizeInvestigation(request);
        sendJson(
          response,
          200,
          await service.cachedInvestigation(await readJsonBody(request)),
        );
      },
    },
    {
      method: 'POST',
      path: '/investigations/enrichment/query',
      handler: async ({request, response}) => {
        authorizeInvestigation(request);
        sendJson(
          response,
          200,
          await service.queryInvestigation(await readJsonBody(request)),
        );
      },
    },
  ];
}

module.exports = {createEnrichmentRoutes};
