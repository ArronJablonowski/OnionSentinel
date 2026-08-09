'use strict';

function createHealthRoutes({service, sendJson}) {
  if (!service || typeof service !== 'object') {
    throw new TypeError('health service is required');
  }
  if (typeof sendJson !== 'function') {
    throw new TypeError('sendJson must be a function');
  }
  return [
    {
      method: 'GET',
      path: '/health',
      handler: async ({response}) => sendJson(
        response, 200, await service.healthSnapshot(),
      ),
    },
    {
      method: 'GET',
      path: '/metrics',
      handler: async ({response}) => sendJson(
        response, 200, {ok: true, metrics: await service.metricsSnapshot()},
      ),
    },
    {
      method: 'GET',
      path: '/jobs/stats',
      handler: async ({response}) => sendJson(
        response, 200, {ok: true, jobs: await service.jobStats()},
      ),
    },
  ];
}

module.exports = {createHealthRoutes};
