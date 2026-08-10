'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createProjectSerialization} = require('../lib/project_serialization');

const fixedDate = new Date(2026, 0, 2, 3, 4, 5, 6);
const serialization = createProjectSerialization({nowDate: () => fixedDate});

function expectedOffset(date) {
  const minutes = -date.getTimezoneOffset();
  const sign = minutes >= 0 ? '+' : '-';
  const absolute = Math.abs(minutes);
  return `${sign}${String(Math.floor(absolute / 60)).padStart(2, '0')}:${String(absolute % 60).padStart(2, '0')}`;
}

test('project offset reflects the date-specific local UTC offset', () => {
  assert.equal(serialization.projectOffset(fixedDate), expectedOffset(fixedDate));
});

test('timestamp format keeps local fields, two spaces, milliseconds, and offset', () => {
  assert.equal(serialization.formatProjectTimestamp(fixedDate),
    `2026-01-02  03:04:05.006${expectedOffset(fixedDate)}`);
  const wholeSecond = new Date(2026, 0, 2, 3, 4, 5, 0);
  assert.equal(serialization.formatProjectTimestamp(wholeSecond),
    `2026-01-02  03:04:05${expectedOffset(wholeSecond)}`);
});

test('nowUtc formats the injected current date', () => {
  assert.equal(serialization.nowUtc(), serialization.formatProjectTimestamp(fixedDate));
});

test('timestamp parser preserves null, invalid, UTC-default, and explicit-offset behavior', () => {
  assert.equal(serialization.parseProjectTimestamp(''), null);
  assert.equal(serialization.parseProjectTimestamp('invalid'), null);
  assert.equal(serialization.parseProjectTimestamp('2026-01-02  03:04:05').getTime(),
    Date.parse('2026-01-02T03:04:05Z'));
  assert.equal(serialization.parseProjectTimestamp('2026-01-02T03:04:05-07:00').getTime(),
    Date.parse('2026-01-02T03:04:05-07:00'));
});

test('timestamp normalization converts embedded historical timestamps', () => {
  const utc = '2026-01-02T03:04:05.006Z';
  const expected = serialization.formatProjectTimestamp(new Date(utc));
  assert.equal(serialization.normalizeTimestampValue(` seen ${utc} `), `seen ${expected}`);
  assert.equal(serialization.normalizeTimestampValue(''), null);
  assert.equal(serialization.normalizeTimestampValue(null), null);
});

test('unparseable timestamp-shaped text only normalizes the separator', () => {
  assert.equal(serialization.normalizeTimestampValue('2026-99-99T03:04:05'),
    '2026-99-99  03:04:05');
});

test('recursive normalization preserves object and array shape', () => {
  const utc = '2026-01-02T03:04:05Z';
  const expected = serialization.formatProjectTimestamp(new Date(utc));
  assert.deepEqual(serialization.normalizeJsonTimestamps({
    first: utc, items: [1, {second: `at ${utc}`}], empty: null,
  }), {first: expected, items: [1, {second: `at ${expected}`}], empty: null});
});

test('jsonText normalizes timestamps and maps nullish roots to null', () => {
  assert.equal(serialization.jsonText(undefined), 'null');
  assert.equal(serialization.jsonText(null), 'null');
  const utc = '2026-01-02T03:04:05Z';
  assert.equal(serialization.jsonText({seen: utc}), JSON.stringify({
    seen: serialization.formatProjectTimestamp(new Date(utc)),
  }));
});

test('canonical JSON recursively sorts objects while preserving array order', () => {
  assert.equal(serialization.canonicalJsonText({z: 1, a: {d: 4, c: 3}, list: [
    {b: 2, a: 1}, 'second',
  ]}), '{"a":{"c":3,"d":4},"list":[{"a":1,"b":2},"second"],"z":1}');
});
