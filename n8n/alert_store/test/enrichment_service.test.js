'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createEnrichmentService} = require('../services/enrichment_service');

function harness() {
  const calls = [];
  const service = createEnrichmentService({
    assertDiskWriteAdmission: (reason) => calls.push({name: 'disk', reason}),
    enrichAlert: async (payload) => {
      calls.push({name: 'enrichAlert', payload});
      return {ok: true};
    },
    cachedInvestigationEnrichment: async (...args) => {
      calls.push({name: 'cached', args});
      return {ok: true};
    },
    queryInvestigationEnrichment: async (...args) => {
      calls.push({name: 'query', args});
      return {ok: true};
    },
  });
  return {calls, service};
}

test('checks disk admission before alert and live investigation enrichment', async () => {
  const env = harness();
  await env.service.enrich({alert_id: 'alert-1'});
  await env.service.queryInvestigation({indicator_type: 'ip', indicator: '192.0.2.1'});
  assert.deepEqual(env.calls, [
    {name: 'disk', reason: 'alert enrichment'},
    {name: 'enrichAlert', payload: {alert_id: 'alert-1'}},
    {name: 'disk', reason: 'investigation enrichment'},
    {name: 'query', args: ['ip', '192.0.2.1']},
  ]);
});

test('cached investigation lookup remains read-only and forwards exact indicators', async () => {
  const env = harness();
  await env.service.cachedInvestigation({indicator_type: 'domain', indicator: 'example.test'});
  assert.deepEqual(env.calls, [{name: 'cached', args: ['domain', 'example.test']}]);
});
