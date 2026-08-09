'use strict';

const analystAdjudicationOutcomes = new Set([
  'true_positive_malicious',
  'true_positive_suspicious',
  'true_positive_authorized_benign',
  'false_positive_logic_rule',
  'false_positive_data_parser',
  'false_positive_bad_intel_ioc',
  'false_negative',
  'duplicate',
  'informational_no_action',
  'inconclusive',
]);
const analystAdjudicationConfidences = new Set(['low', 'medium', 'high']);
const analystEventStatuses = new Set(['observed', 'not_observed', 'unknown']);
const analystDetectionValidities = new Set([
  'matched_intent',
  'logic_error',
  'parser_error',
  'intel_error',
  'not_applicable',
  'unknown',
]);
const analystActivityDispositions = new Set([
  'malicious',
  'suspicious',
  'authorized_benign',
  'benign',
  'unknown',
]);
const analystHandlingValues = new Set([
  'contain',
  'escalate',
  'investigate',
  'monitor',
  'no_action',
]);
const reviewerFailureStatuses = new Set([
  'failed',
  'invalid',
  'invalid_response',
  'not_configured',
  'not_independent',
  'review_required_failed',
]);

function analystLegacyVerdictFactors(outcome) {
  const mapping = {
    true_positive_malicious: ['observed', 'matched_intent', 'malicious', 'contain'],
    true_positive_suspicious: ['observed', 'matched_intent', 'suspicious', 'investigate'],
    true_positive_authorized_benign: [
      'observed', 'matched_intent', 'authorized_benign', 'no_action',
    ],
    false_positive_logic_rule: ['observed', 'logic_error', 'unknown', 'monitor'],
    false_positive_data_parser: ['unknown', 'parser_error', 'unknown', 'investigate'],
    false_positive_bad_intel_ioc: ['observed', 'intel_error', 'unknown', 'monitor'],
    false_negative: ['observed', 'not_applicable', 'malicious', 'escalate'],
    duplicate: ['observed', 'unknown', 'unknown', 'no_action'],
    informational_no_action: ['observed', 'not_applicable', 'benign', 'no_action'],
    inconclusive: ['unknown', 'unknown', 'unknown', 'investigate'],
  };
  const [eventStatus, detectionValidity, activityDisposition, handling] = mapping[outcome];
  return {
    event_status: eventStatus,
    detection_validity: detectionValidity,
    activity_disposition: activityDisposition,
    handling,
    duplicate_of: null,
  };
}

function deriveAnalystLegacyOutcome(factors) {
  const duplicateOf = String(factors?.duplicate_of || '').trim();
  const validity = String(factors?.detection_validity || 'unknown');
  const eventStatus = String(factors?.event_status || 'unknown');
  const disposition = String(factors?.activity_disposition || 'unknown');
  const handling = String(factors?.handling || 'investigate');
  if (duplicateOf) return 'duplicate';
  if (validity === 'parser_error') return 'false_positive_data_parser';
  if (validity === 'logic_error') return 'false_positive_logic_rule';
  if (validity === 'intel_error') return 'false_positive_bad_intel_ioc';
  if (validity === 'matched_intent' && eventStatus === 'observed') {
    if (disposition === 'malicious') return 'true_positive_malicious';
    if (disposition === 'suspicious') return 'true_positive_suspicious';
    if (disposition === 'authorized_benign') return 'true_positive_authorized_benign';
    if (disposition === 'benign' && handling === 'no_action') return 'informational_no_action';
  }
  if (validity === 'not_applicable' && eventStatus === 'observed') {
    if (disposition === 'malicious') return 'false_negative';
    if (
      ['benign', 'authorized_benign'].includes(disposition)
      && handling === 'no_action'
    ) return 'informational_no_action';
  }
  return 'inconclusive';
}

function analystVerdictContradictions(outcome, explicitFactors) {
  const supplied = Object.fromEntries(
    Object.entries(explicitFactors || {}).filter(
      ([, value]) => value !== null && value !== '',
    ),
  );
  if (Object.keys(supplied).length === 0) return [];
  const factors = {...analystLegacyVerdictFactors(outcome), ...supplied};
  const derived = deriveAnalystLegacyOutcome(factors);
  const contradictions = [];
  if (derived !== outcome) {
    contradictions.push(`factored verdict derives ${derived}, not ${outcome}`);
  }
  if (
    factors.event_status === 'not_observed'
    && factors.detection_validity === 'matched_intent'
  ) {
    contradictions.push('an unobserved event cannot be a validated detection-intent match');
  }
  if (
    factors.activity_disposition === 'malicious'
    && ['monitor', 'no_action'].includes(factors.handling)
  ) contradictions.push('malicious activity cannot use monitor/no_action handling');
  if (
    ['authorized_benign', 'benign'].includes(factors.activity_disposition)
    && factors.handling === 'contain'
  ) contradictions.push('benign or authorized activity cannot use contain handling');
  if (factors.duplicate_of && ['contain', 'escalate'].includes(factors.handling)) {
    contradictions.push(
      'a duplicate record cannot independently authorize containment or escalation',
    );
  }
  if (outcome.startsWith('false_positive_')) {
    if (['malicious', 'suspicious'].includes(factors.activity_disposition)) {
      contradictions.push(
        'a false-positive label cannot classify activity as malicious or suspicious',
      );
    }
    if (['contain', 'escalate'].includes(factors.handling)) {
      contradictions.push(
        'a false-positive label cannot authorize containment or escalation',
      );
    }
  }
  return contradictions;
}

function createReviewerPolicy({safeString, parseJsonObject}) {
  for (const [name, value] of Object.entries({safeString, parseJsonObject})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  function reviewerAutomationAuthorization(responseJson, reviewerConfidence = '') {
    const response = (
      responseJson && typeof responseJson === 'object' && !Array.isArray(responseJson)
    ) ? responseJson : parseJsonObject(responseJson);
    const secondOpinion = (
      response._second_opinion
      && typeof response._second_opinion === 'object'
      && !Array.isArray(response._second_opinion)
    ) ? response._second_opinion : {};
    const authorization = (
      secondOpinion.automation_authorization
      && typeof secondOpinion.automation_authorization === 'object'
      && !Array.isArray(secondOpinion.automation_authorization)
    ) ? secondOpinion.automation_authorization : {};
    const hasExplicitDecision = Object.prototype.hasOwnProperty.call(
      authorization,
      'authorized',
    ) && typeof authorization.authorized === 'boolean';
    const confidence = safeString(reviewerConfidence, 16).toLowerCase();
    const legacyConfidenceDenial = Boolean(!hasExplicitDecision && confidence !== 'high');
    return {
      authorized: hasExplicitDecision ? authorization.authorized : !legacyConfidenceDenial,
      explicitly_recorded: hasExplicitDecision,
      reason: safeString(authorization.reason, 500),
      reason_code: safeString(authorization.reason_code, 100),
      legacy_confidence_fallback: legacyConfidenceDenial,
    };
  }

  function conservativeReviewerTelemetry(responseJson, secondOpinionRow = null) {
    const response = (
      responseJson && typeof responseJson === 'object' && !Array.isArray(responseJson)
    ) ? responseJson : parseJsonObject(responseJson);
    const embedded = (
      response._second_opinion
      && typeof response._second_opinion === 'object'
      && !Array.isArray(response._second_opinion)
    ) ? response._second_opinion : {};
    const embeddedPresent = Object.keys(embedded).length > 0;
    const embeddedReviewer = (
      embedded.response
      && typeof embedded.response === 'object'
      && !Array.isArray(embedded.response)
    ) ? embedded.response : {};
    const embeddedComparison = (
      embedded.comparison
      && typeof embedded.comparison === 'object'
      && !Array.isArray(embedded.comparison)
    ) ? embedded.comparison : {};
    const rowPresent = Boolean(
      secondOpinionRow
      && typeof secondOpinionRow === 'object'
      && !Array.isArray(secondOpinionRow),
    );
    const rowStatus = safeString(secondOpinionRow?.status, 64).toLowerCase();
    const embeddedStatus = safeString(embedded.status, 64).toLowerCase();
    const recognizedStatuses = new Set(['completed', ...reviewerFailureStatuses]);
    const corruptRow = Boolean(rowPresent && (!rowStatus || !recognizedStatuses.has(rowStatus)));
    const corruptEmbedded = Boolean(
      embeddedPresent && (!embeddedStatus || !recognizedStatuses.has(embeddedStatus)),
    );
    const statusConflict = Boolean(
      rowStatus && embeddedStatus && rowStatus !== embeddedStatus,
    );
    const failureStatus = [rowStatus, embeddedStatus].find(
      (status) => reviewerFailureStatuses.has(status),
    );
    const status = failureStatus || (
      corruptRow || corruptEmbedded || statusConflict
        ? 'invalid_response' : (rowStatus || embeddedStatus)
    );
    const rowDisputedFields = parseJsonObject(
      secondOpinionRow?.disputed_fields_json
        ? `{"items":${secondOpinionRow.disputed_fields_json}}`
        : '{"items":[]}',
    ).items;
    return {
      present: rowPresent || embeddedPresent,
      status,
      status_conflict: statusConflict,
      reviewer_confidence: (
        safeString(secondOpinionRow?.reviewer_confidence, 16).toLowerCase()
        || safeString(embeddedReviewer.confidence, 16).toLowerCase()
      ),
      reviewer_outcome: (
        safeString(secondOpinionRow?.reviewer_outcome, 100)
        || safeString(embeddedReviewer.detection_outcome, 100)
      ),
      reviewer_error: (
        safeString(secondOpinionRow?.reviewer_error, 1000)
        || safeString(embedded.error, 1000)
        || (
          corruptRow || corruptEmbedded || statusConflict
            ? 'reviewer telemetry is missing, corrupt, or conflicts with the immutable analysis response'
            : ''
        )
      ),
      agreement: (
        safeString(secondOpinionRow?.agreement, 64).toLowerCase()
        || safeString(embeddedComparison.agreement, 64).toLowerCase()
      ),
      material_disagreement: Boolean(
        Number(secondOpinionRow?.material_disagreement || 0)
        || embeddedComparison.material_disagreement
      ),
      disputed_fields: (
        Array.isArray(rowDisputedFields) && rowDisputedFields.length
          ? rowDisputedFields
          : (Array.isArray(embeddedComparison.disputed_fields)
            ? embeddedComparison.disputed_fields : [])
      ),
    };
  }

  return {reviewerAutomationAuthorization, conservativeReviewerTelemetry};
}

module.exports = {
  analystAdjudicationOutcomes,
  analystAdjudicationConfidences,
  analystEventStatuses,
  analystDetectionValidities,
  analystActivityDispositions,
  analystHandlingValues,
  reviewerFailureStatuses,
  analystLegacyVerdictFactors,
  deriveAnalystLegacyOutcome,
  analystVerdictContradictions,
  createReviewerPolicy,
};
