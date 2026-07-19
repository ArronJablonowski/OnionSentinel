'use strict';

// HTTP resource limits are kept outside alert-store business logic so the
// ingestion contract can be tested without initializing SQLite or providers.
function positiveNumber(value, fallback, minimum = 1) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.max(minimum, parsed) : fallback;
}

function statusError(message, statusCode) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function readJsonObject(request, {maxBytes}) {
  const limit = positiveNumber(maxBytes, 10 * 1024 * 1024, 1024);
  return new Promise((resolve, reject) => {
    let settled = false;
    let bytes = 0;
    const chunks = [];
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      callback(value);
    };
    const fail = (error) => finish(reject, error);
    const declaredHeader = request.headers['content-length'];
    const declaredLength = declaredHeader === undefined ? null : Number(declaredHeader);
    if (declaredLength !== null && (!Number.isInteger(declaredLength) || declaredLength < 0)) {
      request.resume();
      fail(statusError('invalid Content-Length header', 400));
      return;
    }
    if (declaredLength !== null && declaredLength > limit) {
      request.resume();
      fail(statusError(`payload exceeds ${limit} byte limit`, 413));
      return;
    }
    request.on('data', (chunk) => {
      if (settled) return;
      bytes += chunk.length;
      if (bytes > limit) {
        chunks.length = 0;
        request.resume();
        fail(statusError(`payload exceeds ${limit} byte limit`, 413));
        return;
      }
      chunks.push(chunk);
    });
    request.on('aborted', () => fail(statusError('request body was aborted', 400)));
    request.on('error', fail);
    request.on('end', () => {
      if (settled) return;
      if (declaredLength !== null && bytes !== declaredLength) {
        fail(statusError('request body length did not match Content-Length', 400));
        return;
      }
      try {
        const payload = JSON.parse(Buffer.concat(chunks, bytes).toString('utf8') || '{}');
        if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
          throw statusError('payload must be a JSON object', 400);
        }
        finish(resolve, payload);
      } catch (error) {
        fail(error.statusCode ? error : statusError(`invalid JSON: ${error.message}`, 400));
      }
    });
  });
}

function configureHttpServer(server, options = {}) {
  server.requestTimeout = positiveNumber(options.requestTimeoutMs, 30000);
  server.headersTimeout = Math.min(
    server.requestTimeout,
    positiveNumber(options.headersTimeoutMs, 10000),
  );
  server.keepAliveTimeout = positiveNumber(options.keepAliveTimeoutMs, 5000);
  server.maxRequestsPerSocket = positiveNumber(options.maxRequestsPerSocket, 100);
  server.maxConnections = positiveNumber(options.maxConnections, 256);
  server.on('clientError', (error, socket) => {
    if (!socket.writable || socket.destroyed) return;
    const status = error.code === 'HPE_HEADER_OVERFLOW' ? '431 Request Header Fields Too Large' : '400 Bad Request';
    socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
  });
  return server;
}

function createRequestAdmission(maxActiveRequests = 32) {
  const limit = Math.floor(positiveNumber(maxActiveRequests, 32));
  let activeRequests = 0;
  let rejectedRequests = 0;

  function tryAcquire() {
    if (activeRequests >= limit) {
      rejectedRequests += 1;
      return null;
    }
    activeRequests += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      activeRequests = Math.max(0, activeRequests - 1);
    };
  }

  function snapshot() {
    return {
      active_requests: activeRequests,
      max_active_requests: limit,
      rejected_requests: rejectedRequests,
    };
  }

  return {tryAcquire, snapshot};
}

module.exports = {configureHttpServer, createRequestAdmission, readJsonObject};
