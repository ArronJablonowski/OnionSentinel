'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const policy = require('../lib/analyst_review_policy');

const safeString = (value, limit = 240) => String(value || '').trim().slice(0, limit);
const parseJsonObject = (value) => {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(String(value || '{}'));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
};
const reviewer = policy.createReviewerPolicy({safeString, parseJsonObject});

test('legacy verdict factors retain compatibility outcome semantics', () => {
  for (const outcome of policy.analystAdjudicationOutcomes) {
    const expected = outcome === 'duplicate' ? 'inconclusive' : outcome;
    assert.equal(
      policy.deriveAnalystLegacyOutcome(policy.analystLegacyVerdictFactors(outcome)),
      expected,
    );
  }
  assert.equal(policy.deriveAnalystLegacyOutcome({duplicate_of: 'case-42'}), 'duplicate');
});

test('rejects factored verdicts that could authorize contradictory actions', () => {
  const malicious = policy.analystVerdictContradictions('true_positive_malicious', {
    handling: 'no_action',
  });
  assert.ok(malicious.includes('malicious activity cannot use monitor/no_action handling'));
  const benign = policy.analystVerdictContradictions('true_positive_authorized_benign', {
    handling: 'contain',
  });
  assert.ok(benign.includes('benign or authorized activity cannot use contain handling'));
  const falsePositive = policy.analystVerdictContradictions('false_positive_logic_rule', {
    activity_disposition: 'malicious', handling: 'contain',
  });
  assert.ok(falsePositive.some((item) => /cannot authorize containment/.test(item)));
});

test('explicit reviewer authorization overrides legacy confidence fallback', () => {
  assert.deepEqual(reviewer.reviewerAutomationAuthorization({
    _second_opinion: {
      automation_authorization: {
        authorized: false, reason: 'human review', reason_code: 'DISPUTED',
      },
    },
  }, 'high'), {
    authorized: false,
    explicitly_recorded: true,
    reason: 'human review',
    reason_code: 'DISPUTED',
    legacy_confidence_fallback: false,
  });
  assert.equal(reviewer.reviewerAutomationAuthorization({}, 'medium').authorized, false);
  assert.equal(reviewer.reviewerAutomationAuthorization({}, 'high').authorized, true);
});

test('fails closed on corrupt or conflicting reviewer telemetry', () => {
  const telemetry = reviewer.conservativeReviewerTelemetry({
    _second_opinion: {
      status: 'completed',
      response: {confidence: 'high'},
      comparison: {agreement: 'agreement'},
    },
  }, {
    status: 'mystery',
    reviewer_confidence: 'low',
    agreement: 'disagreement',
    disputed_fields_json: '["detection_outcome"]',
  });
  assert.equal(telemetry.status, 'invalid_response');
  assert.equal(telemetry.status_conflict, true);
  assert.match(telemetry.reviewer_error, /missing, corrupt, or conflicts/);
  assert.equal(telemetry.reviewer_confidence, 'low');
  assert.deepEqual(telemetry.disputed_fields, ['detection_outcome']);
});
