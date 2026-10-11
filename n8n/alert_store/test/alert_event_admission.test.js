'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const {eventAdmissionReason} = require('../lib/alert_event_admission');
const policy = {enabled: true, time_zone: 'America/Denver', min_event_date: '2026-10-08'};
const now = new Date('2026-10-08T15:00:00Z');
test('drops yesterday, admits local midnight and offset timestamps', () => {
  for (const timestamp of ['2026-10-08T05:59:59Z', '2026-08-26  18:45:20.050-06:00']) {
    assert.equal(eventAdmissionReason({timestamp}, policy, now), 'event_before_today');
  }
  for (const timestamp of ['2026-10-08T06:00:00Z', '2026-10-08  07:40:40.719-06:00']) {
    assert.equal(eventAdmissionReason({timestamp}, policy, now), null);
  }
});
test('does not replace original time with receipt time; rejects missing and naive times', () => {
  assert.equal(eventAdmissionReason({timestamp: now.toISOString(), security_onion: {
    raw_event: {'@timestamp': '2026-08-26T00:00:00Z'}}}, policy, now), 'event_before_today');
  for (const timestamp of [null, 'broken', '2026-10-08T08:00:00']) {
    assert.equal(eventAdmissionReason({timestamp}, policy, now), 'missing_or_invalid_original_event_time');
  }
});
test('cutoff rolls forward daily and handles daylight saving offsets', () => {
  assert.equal(eventAdmissionReason({timestamp: '2026-10-08T23:59:00-06:00'}, policy,
    new Date('2026-10-09T06:00:00Z')), 'event_before_today');
  assert.equal(eventAdmissionReason({timestamp: '2026-11-02T07:00:00Z'}, policy,
    new Date('2026-11-02T10:00:00Z')), null);
});
