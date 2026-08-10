'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  verifyInstallScriptPolicy,
} = require('../verify_install_script_policy');

test('accepts only pinned sqlite3 with no pending dependency scripts', () => {
  assert.doesNotThrow(() => verifyInstallScriptPolicy(
    { allowScripts: { 'sqlite3@6.0.1': true } },
    { allowScripts: [] },
  ));
});

test('rejects unpinned, additional, or pending install scripts', () => {
  assert.throws(
    () => verifyInstallScriptPolicy(
      { allowScripts: { sqlite3: true } },
      { allowScripts: [] },
    ),
    /approve only the pinned sqlite3@6\.0\.1/,
  );
  assert.throws(
    () => verifyInstallScriptPolicy(
      {
        allowScripts: {
          'sqlite3@6.0.1': true,
          'unexpected@1.0.0': true,
        },
      },
      { allowScripts: [] },
    ),
    /approve only the pinned sqlite3@6\.0\.1/,
  );
  assert.throws(
    () => verifyInstallScriptPolicy(
      { allowScripts: { 'sqlite3@6.0.1': true } },
      { allowScripts: [{ name: 'unexpected', changes: [] }] },
    ),
    /unreviewed dependency install scripts: unexpected/,
  );
});
