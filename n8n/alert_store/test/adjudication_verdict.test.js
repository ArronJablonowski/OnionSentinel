'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'alert_store.js'), 'utf8');

function functionSource(name, endMarker) {
  const start = source.indexOf(`function ${name}(`);
  const end = source.indexOf(endMarker, start);
  assert.notStrictEqual(start, -1, `${name} must exist`);
  assert.notStrictEqual(end, -1, `${endMarker} must follow ${name}`);
  return source.slice(start, end);
}

const sandbox = {module: {exports: {}}};
vm.runInNewContext(
  [
    functionSource(
      'analystLegacyVerdictFactors',
      'function deriveAnalystLegacyOutcome(',
    ),
    functionSource(
      'deriveAnalystLegacyOutcome',
      'function analystVerdictContradictions(',
    ),
    functionSource('analystVerdictContradictions', '\nconst socAnalysisPolicy'),
    'module.exports = {deriveAnalystLegacyOutcome, analystVerdictContradictions};',
  ].join('\n'),
  sandbox,
);

const {deriveAnalystLegacyOutcome, analystVerdictContradictions} = sandbox.module.exports;
const authorizedUnknownIntent = {
  event_status: 'observed',
  detection_validity: 'unknown',
  activity_disposition: 'authorized_benign',
  handling: 'no_action',
  duplicate_of: null,
};

assert.strictEqual(
  deriveAnalystLegacyOutcome(authorizedUnknownIntent),
  'informational_no_action',
);
assert.deepStrictEqual(
  Array.from(analystVerdictContradictions('informational_no_action', authorizedUnknownIntent)),
  [],
);
assert.deepStrictEqual(
  Array.from(
    analystVerdictContradictions(
      'true_positive_authorized_benign',
      authorizedUnknownIntent,
    ),
  ),
  ['factored verdict derives informational_no_action, not true_positive_authorized_benign'],
);

const matchedIntent = {
  ...authorizedUnknownIntent,
  detection_validity: 'matched_intent',
};
assert.strictEqual(
  deriveAnalystLegacyOutcome(matchedIntent),
  'true_positive_authorized_benign',
);
assert.deepStrictEqual(
  Array.from(
    analystVerdictContradictions('true_positive_authorized_benign', matchedIntent),
  ),
  [],
);

const maliciousNoAction = {
  event_status: 'observed',
  detection_validity: 'matched_intent',
  activity_disposition: 'malicious',
  handling: 'no_action',
  duplicate_of: null,
};
assert.ok(
  analystVerdictContradictions('true_positive_malicious', maliciousNoAction)
    .includes('malicious activity cannot use monitor/no_action handling'),
);

console.log('adjudication verdict tests passed');
