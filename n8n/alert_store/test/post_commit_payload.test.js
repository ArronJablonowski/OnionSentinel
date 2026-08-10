'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createPostCommitPayload} = require('../services/post_commit_payload');

function owner() {
  return createPostCommitPayload({
    nowUtc: () => '2026-08-10T03:00:00.000Z',
    nestedField: (value, key) => key.split('.').reduce(
      (current, part) => current?.[part], value,
    ),
  });
}

test('requires both timestamp and nested-field dependency owners', () => {
  assert.throws(() => createPostCommitPayload({nestedField() {}}), /nowUtc/);
  assert.throws(() => createPostCommitPayload({nowUtc() {}}), /nestedField/);
});

test('projects stored values, policy metadata, provenance, and report identity', () => {
  const rawAlert = {
    alert_id: 'raw-id', rule_name: 'raw-rule', event_dataset: 'raw-dataset',
    severity: 3, severity_label: 'raw-label',
    source: {ip: '192.0.2.10'}, destination: {ip: '198.51.100.20'},
  };
  const campaign = {campaign_id: 'campaign-1'};
  const payload = owner().build(rawAlert, {
    status: 'accepted', stored: 1, campaign,
    alert: {
      alert_id: 'stored-id', rule_name: 'stored-rule', event_dataset: 'stored-dataset',
      severity: 0, severity_label: 'stored-label', source_ip: '10.0.0.1',
      destination_ip: '10.0.0.2', traffic_direction: 'row-direction',
      triage_score: 0, triage_level: 'low', routing: 'row-routing',
      filter_status: 'row-filter', filter_reason: 'row-reason',
      suppression_key: 'row-key', first_seen: 'first', last_seen: 'last', seen_count: 7,
    },
    triage: {
      traffic_direction: 'triage-direction', score: 0, level: 'medium',
      routing: 'triage-routing', reasons: ['reason-1'],
    },
    filter: {status: 'suppressed', reason: 'filter-reason', key: 'filter-key', rule: 'rule-1'},
    notification: {channel: 'email', status: 'queued'},
  });

  assert.deepEqual(payload, {
    ok: true, stage: 'alert-store-post-commit', status: 'accepted', stored: true,
    original_alert: rawAlert, alert_id: 'stored-id', rule_name: 'stored-rule',
    event_dataset: 'stored-dataset', severity: 0, severity_label: 'stored-label',
    source_ip: '10.0.0.1', destination_ip: '10.0.0.2',
    traffic_direction: 'triage-direction', triage_score: 0, triage_level: 'medium',
    routing: 'triage-routing', triage_reasons: ['reason-1'],
    filter_status: 'suppressed', filter_reason: 'filter-reason',
    suppression_key: 'filter-key', suppression_rule: 'rule-1',
    notification_channel: 'email', notification_status: 'queued',
    first_seen: 'first', last_seen: 'last', seen_count: 7,
    authorized_activity_campaign: campaign, should_write_report: true,
    report_decision: 'write_markdown_report', report_job_id: 'alert-report:stored-id',
    committed_at: '2026-08-10T03:00:00.000Z',
  });
});

test('preserves raw fallbacks and exact absent-owner defaults', () => {
  const rawAlert = {
    alert_id: 'raw-id', rule_name: 'raw-rule', event_dataset: 'raw-dataset',
    severity: 0, severity_label: 'raw-label',
    source: {ip: '192.0.2.10'}, destination: {ip: '198.51.100.20'},
  };
  assert.deepEqual(owner().build(rawAlert, {status: 'failed', stored: 0}), {
    ok: true, stage: 'alert-store-post-commit', status: 'failed', stored: false,
    original_alert: rawAlert, alert_id: 'raw-id', rule_name: 'raw-rule',
    event_dataset: 'raw-dataset', severity: 0, severity_label: 'raw-label',
    source_ip: '192.0.2.10', destination_ip: '198.51.100.20',
    traffic_direction: null, triage_score: null, triage_level: null,
    routing: 'unknown', triage_reasons: [], filter_status: 'failed',
    filter_reason: null, suppression_key: null, suppression_rule: null,
    notification_channel: 'telegram', notification_status: 'unknown',
    first_seen: null, last_seen: null, seen_count: null,
    authorized_activity_campaign: null, should_write_report: false,
    report_decision: 'write_markdown_report', report_job_id: 'alert-report:raw-id',
    committed_at: '2026-08-10T03:00:00.000Z',
  });
});

test('duplicate status overrides routing without making a report eligible', () => {
  const payload = owner().build({alert_id: 'alert-1'}, {
    status: 'already_seen', stored: true,
    alert: {alert_id: 'alert-1', routing: 'row-routing'},
    triage: {routing: 'triage-routing'},
  });
  assert.equal(payload.routing, 'duplicate-suppressed');
  assert.equal(payload.should_write_report, false);
  assert.equal(payload.report_job_id, 'alert-report:alert-1');
});
