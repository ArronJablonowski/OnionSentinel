'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  STABLE_GROUP_KEY_MAX_UTF8_BYTES,
  validPinnedStableGroupKey,
} = require('../lib/group_identity');

test('stable group key pins use an exact bounded UTF-8 contract', () => {
  const exactAscii = 'a'.repeat(STABLE_GROUP_KEY_MAX_UTF8_BYTES);
  const exactMultibyte = '\u00e9'.repeat(
    STABLE_GROUP_KEY_MAX_UTF8_BYTES / 2,
  );

  assert.equal(Buffer.byteLength(exactAscii, 'utf8'), 2048);
  assert.equal(Buffer.byteLength(exactMultibyte, 'utf8'), 2048);
  assert.equal(validPinnedStableGroupKey(exactAscii), true);
  assert.equal(validPinnedStableGroupKey(exactMultibyte), true);
  assert.equal(validPinnedStableGroupKey('v2|valid-group'), true);
});

test('stable group key pins reject empty, NUL, oversized, and invalid Unicode', () => {
  assert.equal(validPinnedStableGroupKey(''), false);
  assert.equal(validPinnedStableGroupKey('v2|bad\0group'), false);
  assert.equal(validPinnedStableGroupKey('\u00e9'.repeat(1025)), false);
  assert.equal(validPinnedStableGroupKey('\ud800'), false);
  assert.equal(validPinnedStableGroupKey(Buffer.alloc(1)), false);
});
