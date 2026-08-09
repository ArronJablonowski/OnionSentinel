'use strict';

function createRequestAuthorization({
  assetWriteToken,
  evaluationToken,
  controlledEvaluationMode,
  timingSafeEqual,
}) {
  if (typeof assetWriteToken !== 'string') throw new TypeError('assetWriteToken must be a string');
  if (typeof evaluationToken !== 'string') throw new TypeError('evaluationToken must be a string');
  if (typeof controlledEvaluationMode !== 'boolean') {
    throw new TypeError('controlledEvaluationMode must be a boolean');
  }
  if (typeof timingSafeEqual !== 'function') throw new TypeError('timingSafeEqual must be a function');

  function constantTimeMatch(expectedValue, suppliedValue) {
    if (typeof suppliedValue !== 'string') return false;
    const expected = Buffer.from(expectedValue, 'utf8');
    const supplied = Buffer.from(suppliedValue, 'utf8');
    return expected.length === supplied.length && timingSafeEqual(expected, supplied);
  }

  function assetWriteAuthorized(request) {
    return constantTimeMatch(
      assetWriteToken,
      request.headers['x-onion-sentinel-asset-token'],
    );
  }

  function requireAssetWrite(request) {
    if (assetWriteAuthorized(request)) return;
    const error = new Error('asset-store write authorization failed');
    error.statusCode = 403;
    throw error;
  }

  function controlledEvaluationAuthorized(request) {
    if (!controlledEvaluationMode) return true;
    const supplied = request.headers['x-onion-sentinel-evaluation-token'];
    if (typeof supplied !== 'string' || !/^[a-f0-9]{64}$/.test(supplied)) return false;
    return constantTimeMatch(evaluationToken, supplied);
  }

  return {assetWriteAuthorized, requireAssetWrite, controlledEvaluationAuthorized};
}

module.exports = {createRequestAuthorization};
