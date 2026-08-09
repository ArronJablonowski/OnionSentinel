'use strict';

function createPcapRoutes({service, readJsonBody, sendJson}) {
  if (!service || typeof service !== 'object') {
    throw new TypeError('PCAP service is required');
  }
  for (const [name, value] of Object.entries({readJsonBody, sendJson})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  const post = (path, method) => ({
    method: 'POST',
    path,
    handler: async ({request, response}) => sendJson(
      response,
      200,
      await service[method](await readJsonBody(request)),
    ),
  });

  return [
    post('/pcap/request', 'request'),
    {
      method: 'GET',
      path: '/pcap/requests',
      handler: async ({response, parsedUrl}) => sendJson(
        response,
        200,
        await service.list(parsedUrl.searchParams),
      ),
    },
    post('/pcap/claim', 'claim'),
    post('/pcap/complete', 'complete'),
    post('/pcap/progress', 'progress'),
    post('/pcap/retry', 'retry'),
    post('/pcap/analysis-status', 'analysisStatus'),
    post('/pcap/requeue', 'requeue'),
  ];
}

module.exports = {createPcapRoutes};
