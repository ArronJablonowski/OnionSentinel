'use strict';

function createDurableJobRoutes({service, readJsonBody, sendJson}) {
  if (!service || typeof service !== 'object') {
    throw new TypeError('durable job service is required');
  }
  for (const [name, value] of Object.entries({readJsonBody, sendJson})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  return [
    {
      method: 'POST',
      path: '/jobs/status',
      handler: async ({request, response}) => {
        const result = await service.transitionStatus(await readJsonBody(request));
        sendJson(response, result.updated ? 200 : 404, {
          ok: result.updated,
          job_type: result.job_type,
          dedupe_key: result.dedupe_key,
          status: result.status,
          lease_token: result.lease_token,
          claim: result.claim,
        });
      },
    },
    {
      method: 'POST',
      path: '/jobs/reconcile-completed',
      handler: async ({request, response}) => {
        const result = await service.reconcileCompleted(await readJsonBody(request));
        sendJson(response, 200, {
          ok: true,
          job_type: result.job_type,
          reconciled: result.reconciled,
        });
      },
    },
  ];
}

module.exports = {createDurableJobRoutes};
