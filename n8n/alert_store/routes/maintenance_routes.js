'use strict';

function createMaintenanceRoutes({service, sendJson}) {
  if (!service || typeof service !== 'object') {
    throw new TypeError('maintenance service is required');
  }
  if (typeof sendJson !== 'function') throw new TypeError('sendJson must be a function');

  return [
    ['/rescore', 'rescore'],
    ['/refresh-groups', 'refreshGroups'],
  ].map(([path, method]) => ({
    method: 'POST',
    path,
    handler: async ({request, response}) => {
      if (request.url !== path) {
        sendJson(response, 404, {ok: false, status: 'not_found'});
        return;
      }
      sendJson(response, 200, await service[method]());
    },
  }));
}

module.exports = {createMaintenanceRoutes};
