'use strict';

function createHttpRequestBoundary({
  controlledEvaluationMode,
  controlledRequests,
  isShutdownStarted,
  controlledRequestAuthorized,
  routeRegistry,
  sendJson,
  serviceMetrics,
  writeBeacon,
}) {
  async function handle(request, response) {
    try {
      const parsedUrl = new URL(request.url, 'http://alert-store.local');
      if (isShutdownStarted()) {
        request.resume();
        sendJson(response, 503, {ok: false, status: 'shutting_down'});
        return;
      }
      if (
        controlledEvaluationMode
        && request.method === 'POST'
        && !controlledRequestAuthorized(request)
      ) {
        request.resume();
        sendJson(response, 403, {
          ok: false,
          status: 'forbidden',
          reason: 'controlled evaluation authorization failed',
        });
        return;
      }
      if (
        controlledEvaluationMode
        && !controlledRequests.has(
          `${String(request.method || '').toUpperCase()} ${request.url}`,
        )
      ) {
        request.resume();
        sendJson(response, 403, {
          ok: false,
          status: 'forbidden',
          reason: 'route is disabled in controlled evaluation mode',
        });
        return;
      }
      if (await routeRegistry.dispatch({request, response, parsedUrl})) return;
      sendJson(response, 404, {ok: false, status: 'not_found'});
    } catch (error) {
      if (request.method === 'POST' && request.url === '/alert') {
        serviceMetrics.ingest_errors += 1;
        writeBeacon('error', {}, null, error);
      }
      sendJson(response, Number(error.statusCode || 400), {
        ok: false,
        status: 'rejected',
        reason: error.message,
      });
    }
  }

  return {handle};
}

module.exports = {createHttpRequestBoundary};
