'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createAnalysisResultRoutes} = require('../routes/analysis_result_routes');

test('preserves the exact result route, raw-body digest request, and response envelope', async () => {
  const calls = [];
  const routes = createAnalysisResultRoutes({
    service: {submit: async (payload) => {
      calls.push({name: 'submit', payload});
      return {ok: true, submission_sha256: payload.__body_sha256};
    }},
    readJsonBody: async (_request, includeBodySha256) => {
      calls.push({name: 'readJsonBody', includeBodySha256});
      return {__body_sha256: 'digest-1'};
    },
    sendJson: (_response, status, payload) => calls.push({name: 'sendJson', status, payload}),
  });
  assert.deepEqual(routes.map(({method, path}) => `${method} ${path}`), [
    'POST /analysis/result',
  ]);
  await routes[0].handler({request: {}, response: {}});
  assert.deepEqual(calls, [
    {name: 'readJsonBody', includeBodySha256: true},
    {name: 'submit', payload: {__body_sha256: 'digest-1'}},
    {name: 'sendJson', status: 200, payload: {ok: true, submission_sha256: 'digest-1'}},
  ]);
});
