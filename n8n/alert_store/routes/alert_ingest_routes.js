'use strict';

function createAlertIngestRoutes({service, sendJson}) {
  if (!service || typeof service.ingest !== 'function') {
    throw new TypeError('alert ingest service is required');
  }
  if (typeof sendJson !== 'function') throw new TypeError('sendJson must be a function');

  return [{
    method: 'POST',
    path: '/alert',
    handler: async ({request, response}) => {
      if (request.url !== '/alert') {
        sendJson(response, 404, {ok: false, status: 'not_found'});
        return;
      }
      const result = await service.ingest(request);
      sendJson(response, result.ok ? 200 : 400, result);
    },
  }];
}

module.exports = {createAlertIngestRoutes};
