'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createAlertGroupAliasResolution,
} = require('../services/alert_group_alias_resolution');

function conflict(message) {
  return Object.assign(new Error(message), {statusCode: 409});
}

function owner(rows = [], queries = []) {
  return createAlertGroupAliasResolution({
    all: async (sql) => { queries.push(sql); return rows; },
    conflict,
  });
}

function alias(stableGroupId, stableGroupKey = '') {
  return {stable_group_id: stableGroupId, stable_group_key: stableGroupKey};
}

test('requires database-read and conflict dependency owners', () => {
  assert.throws(() => createAlertGroupAliasResolution({conflict}), /all/);
  assert.throws(() => createAlertGroupAliasResolution({all() {}}), /conflict/);
});

test('loads one normalized snapshot with the exact read-only query', async () => {
  const queries = [];
  const rows = [
    {legacy_group_id: ' ABCDEF123456 ', stable_group_id: 'abcdef123457', stable_group_key: 'key'},
  ];
  const snapshot = await owner(rows, queries).loadSnapshot();
  assert.equal(queries.length, 1);
  assert.match(queries[0], /SELECT legacy_group_id, stable_group_id, stable_group_key/);
  assert.match(queries[0], /FROM alert_group_alias/);
  assert.equal(snapshot.get('abcdef123456'), rows[0]);
});

test('rejects missing and duplicate normalized legacy identities', async () => {
  await assert.rejects(
    owner([{legacy_group_id: '', stable_group_id: 'abcdef123456'}]).loadSnapshot(),
    (error) => error.statusCode === 409 && /alias map is ambiguous/.test(error.message),
  );
  await assert.rejects(owner([
    {legacy_group_id: 'ABCDEF123456', stable_group_id: 'abcdef123457'},
    {legacy_group_id: 'abcdef123456', stable_group_id: 'abcdef123458'},
  ]).loadSnapshot(), /alias map is ambiguous/);
});

test('normalizes an identity and carries one consistent canonical key through a chain', () => {
  const aliases = new Map([
    ['abcdef123456', alias('ABCDEF123457', 'stable-key')],
    ['abcdef123457', alias('abcdef123458', 'stable-key')],
  ]);
  assert.deepEqual(owner().resolve(' ABCDEF123456 ', aliases), {
    stableGroupId: 'abcdef123458', stableGroupKey: 'stable-key',
  });
  assert.deepEqual(owner().resolve('abcdef123459', aliases), {
    stableGroupId: 'abcdef123459', stableGroupKey: '',
  });
});

test('rejects invalid initial and aliased stable identities with exact conflict status', () => {
  assert.throws(
    () => owner().resolve('not-hex', new Map()),
    (error) => error.statusCode === 409 && /invalid stable group identity/.test(error.message),
  );
  assert.throws(
    () => owner().resolve('abcdef123456', new Map([
      ['abcdef123456', alias('not-hex')],
    ])),
    /invalid stable group alias/,
  );
});

test('fails closed on cycles and conflicting canonical keys', () => {
  assert.throws(
    () => owner().resolve('abcdef123456', new Map([
      ['abcdef123456', alias('abcdef123457')],
      ['abcdef123457', alias('abcdef123456')],
    ])),
    /alias cycle detected/,
  );
  assert.throws(
    () => owner().resolve('abcdef123456', new Map([
      ['abcdef123456', alias('abcdef123457', 'key-one')],
      ['abcdef123457', alias('abcdef123458', 'key-two')],
    ])),
    /alias key is ambiguous/,
  );
});

test('accepts 63 aliases and rejects a 64-alias chain', () => {
  function chain(count) {
    const aliases = new Map();
    for (let index = 0; index < count; index += 1) {
      const current = (0xabcdef123456n + BigInt(index)).toString(16);
      const next = (0xabcdef123456n + BigInt(index + 1)).toString(16);
      aliases.set(current, alias(next));
    }
    return aliases;
  }
  assert.equal(
    owner().resolve('abcdef123456', chain(63)).stableGroupId,
    (0xabcdef123456n + 63n).toString(16),
  );
  assert.throws(
    () => owner().resolve('abcdef123456', chain(64)),
    /alias chain is too deep/,
  );
});
