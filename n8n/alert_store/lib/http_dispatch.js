'use strict';

function requestPath(url) {
  try {
    return new URL(url, 'http://127.0.0.1').pathname;
  } catch {
    return String(url || '').split('?', 1)[0].slice(0, 512);
  }
}

function createRequestDispatcher({
  handleRequest,
  postRequestAdmission,
  logger,
  sendJson,
  randomUUID,
  monotonicNow,
}) {
  for (const [name, value] of Object.entries({
    handleRequest,
    sendJson,
    randomUUID,
    monotonicNow,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  if (!postRequestAdmission || typeof postRequestAdmission.tryAcquire !== 'function') {
    throw new TypeError('postRequestAdmission.tryAcquire must be a function');
  }
  if (!logger || typeof logger.log !== 'function') {
    throw new TypeError('logger.log must be a function');
  }

  return async function dispatchRequest(request, response) {
    const requestId = randomUUID();
    const started = monotonicNow();
    const path = requestPath(request.url);
    response.setHeader('X-Request-ID', requestId);
    response.once('finish', () => {
      logger.log(
        response.statusCode >= 500 ? 'error' : (
          response.statusCode >= 400 ? 'warning' : 'info'
        ),
        'http.request.completed',
        {
          request_id: requestId,
          method: request.method,
          path,
          status_code: response.statusCode,
          duration_ms: Number(monotonicNow() - started) / 1_000_000,
          remote_address: request.socket?.remoteAddress || null,
        },
      );
    });
    if (request.method !== 'POST') {
      await handleRequest(request, response);
      return;
    }
    const release = postRequestAdmission.tryAcquire();
    if (!release) {
      logger.log('warning', 'http.request.rejected_capacity', {
        request_id: requestId,
        method: request.method,
        path,
      });
      request.resume();
      response.setHeader('Retry-After', '1');
      sendJson(response, 503, {
        ok: false,
        status: 'busy',
        reason: 'alert-store POST capacity is busy',
      });
      return;
    }
    try {
      await handleRequest(request, response);
    } finally {
      release();
    }
  };
}

module.exports = {createRequestDispatcher, requestPath};
