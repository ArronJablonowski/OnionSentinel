'use strict';

const http = require('node:http');
const https = require('node:https');


function positiveInteger(value, fallback, minimum = 1) {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= minimum ? parsed : fallback;
}

function responseError(message, code, statusCode = null) {
  const error = new Error(message);
  error.code = code;
  if (statusCode !== null) error.statusCode = statusCode;
  return error;
}

function shortProviderDetail(value) {
  if (!value || typeof value !== 'object') return '';
  const detail = value.detail || value.message || value.error;
  return typeof detail === 'string' ? detail.replace(/\s+/g, ' ').slice(0, 240) : '';
}

/**
 * Perform one bounded JSON request.
 *
 * Provider responses are untrusted input. Both Content-Length and observed
 * bytes are checked so a broken upstream cannot exhaust the alert-store heap.
 * Non-2xx responses fail by default; callers may explicitly allow a semantic
 * status such as Shodan InternetDB's documented 404 "not found" response.
 */
function requestJson({
  method = 'GET',
  url,
  headers = {},
  body = null,
  timeoutMs = 5000,
  maxResponseBytes = 5 * 1024 * 1024,
  allowedStatusCodes = [],
} = {}) {
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      reject(responseError('invalid request URL', 'ERR_INVALID_URL'));
      return;
    }
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      reject(responseError(`unsupported request protocol: ${parsed.protocol}`, 'ERR_UNSUPPORTED_PROTOCOL'));
      return;
    }

    const responseLimit = positiveInteger(maxResponseBytes, 5 * 1024 * 1024, 1024);
    const requestTimeout = positiveInteger(timeoutMs, 5000, 100);
    const acceptedStatuses = new Set(
      (Array.isArray(allowedStatusCodes) ? allowedStatusCodes : [])
        .map(Number)
        .filter((value) => Number.isInteger(value) && value >= 100 && value <= 599),
    );
    const payload = body === null || body === undefined
      ? null
      : (typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
    const client = parsed.protocol === 'https:' ? https : http;
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      callback(value);
    };
    const fail = (error) => finish(reject, error);

    const req = client.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: `${parsed.pathname}${parsed.search}`,
        method,
        headers: {
          Accept: 'application/json',
          'User-Agent': 'Onion-Sentinel/1.0',
          ...(payload !== null ? {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
          } : {}),
          ...headers,
        },
      },
      (res) => {
        const statusCode = Number(res.statusCode || 0);
        const declaredHeader = res.headers['content-length'];
        const declaredLength = declaredHeader === undefined ? null : Number(declaredHeader);
        if (declaredLength !== null && (!Number.isSafeInteger(declaredLength) || declaredLength < 0)) {
          const error = responseError('provider returned an invalid Content-Length', 'ERR_INVALID_RESPONSE_LENGTH', statusCode);
          fail(error);
          res.destroy(error);
          return;
        }
        if (declaredLength !== null && declaredLength > responseLimit) {
          const error = responseError(
            `provider response exceeds ${responseLimit} byte limit`,
            'ERR_RESPONSE_TOO_LARGE',
            statusCode,
          );
          fail(error);
          res.destroy(error);
          return;
        }

        let receivedBytes = 0;
        const chunks = [];
        res.on('data', (chunk) => {
          if (settled) return;
          receivedBytes += chunk.length;
          if (receivedBytes > responseLimit) {
            chunks.length = 0;
            const error = responseError(
              `provider response exceeds ${responseLimit} byte limit`,
              'ERR_RESPONSE_TOO_LARGE',
              statusCode,
            );
            fail(error);
            res.destroy(error);
            return;
          }
          chunks.push(chunk);
        });
        res.on('aborted', () => fail(responseError('provider response was aborted', 'ERR_RESPONSE_ABORTED', statusCode)));
        res.on('error', fail);
        res.on('end', () => {
          if (settled) return;
          if (!res.complete || (declaredLength !== null && receivedBytes !== declaredLength)) {
            fail(responseError('provider response ended before all bytes arrived', 'ERR_TRUNCATED_RESPONSE', statusCode));
            return;
          }
          const raw = Buffer.concat(chunks, receivedBytes).toString('utf8');
          let parsedBody = null;
          if (raw) {
            try {
              parsedBody = JSON.parse(raw);
            } catch {
              fail(responseError('provider returned invalid JSON', 'ERR_INVALID_JSON_RESPONSE', statusCode));
              return;
            }
          }
          const successful = statusCode >= 200 && statusCode < 300;
          if (!successful && !acceptedStatuses.has(statusCode)) {
            const detail = shortProviderDetail(parsedBody);
            fail(responseError(
              `provider returned HTTP ${statusCode}${detail ? `: ${detail}` : ''}`,
              'ERR_HTTP_STATUS',
              statusCode,
            ));
            return;
          }
          finish(resolve, {statusCode, headers: res.headers, body: parsedBody});
        });
      },
    );
    req.setTimeout(requestTimeout, () => {
      req.destroy(responseError(`request timed out: ${parsed.hostname}`, 'ERR_REQUEST_TIMEOUT'));
    });
    req.on('error', fail);
    if (payload !== null) req.write(payload);
    req.end();
  });
}


module.exports = {requestJson};
