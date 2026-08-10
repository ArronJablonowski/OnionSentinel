'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  createApplicationGraphRuntime,
} = require('../composition/application_graph_runtime');

test('loads without constructing persistence or network owners', () => {
  assert.equal(typeof createApplicationGraphRuntime, 'function');
});

test('fails closed before graph construction when a section is absent', () => {
  assert.throws(
    () => createApplicationGraphRuntime(),
    /runtime application graph runtime section is required/,
  );
  assert.throws(
    () => createApplicationGraphRuntime({runtime: {}}),
    /platform application graph runtime section is required/,
  );
  assert.throws(
    () => createApplicationGraphRuntime({runtime: {}, platform: {}}),
    /foundation application graph runtime section is required/,
  );
  assert.throws(
    () => createApplicationGraphRuntime({
      runtime: {},
      platform: {},
      foundation: {},
    }),
    /serialization application graph runtime section is required/,
  );
});
