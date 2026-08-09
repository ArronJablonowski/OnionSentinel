'use strict';

const crypto = require('crypto');

const RETIREMENT_SCHEMA = 'onion-sentinel-controlled-evaluation-retirement-v1';
const RECEIPT_SCHEMA = 'onion-sentinel-controlled-evaluation-retirement-receipt-v1';
const EVENT_TYPE = 'controlled_evaluation_retired';
const RECEIPT_FIELDS = Object.freeze([
  'case_agent_status', 'idempotent', 'identity', 'job_after_sha256',
  'job_before_sha256', 'lineage_after_sha256', 'lineage_before_sha256',
  'model_invocations', 'ok', 'receipt_sha256', 'retired_at', 'retirement_id',
  'schema', 'security_onion_access', 'security_onion_writes_allowed',
  'skip_reason', 'status', 'target_after', 'target_before',
  'worker_wake_signaled',
]);
const REQUEST_FIELDS = Object.freeze([
  'absent_dispatch_ids', 'case_id', 'cohort_id', 'cohort_size',
  'completed_dispatch_ids', 'dispatch_id', 'expected_attempt_count',
  'expected_attempt_id', 'expected_job_payload_sha256',
  'expected_prior_analysis_id', 'failure_attestation_sha256', 'job_id',
  'manifest_sha256', 'member_rank', 'reanalysis_run_id', 'reason',
  'replacement_release_id', 'representative_alert_id', 'retired_release_id',
  'schema', 'stable_group_id', 'stable_group_key', 'start_sha256',
]);

function createControlledRetirementIdentity({
  controlledEvaluationMode,
  safeString,
  validIncidentCaseId,
  cohortIdPattern,
  dispatchIdPattern,
  releaseIdPattern,
  representativeAlertIdPattern,
  stableGroupIdPattern,
  validPinnedStableGroupKey,
  controlledRuntimeReleaseId,
}) {
  for (const [name, value] of Object.entries({
    safeString, validIncidentCaseId, validPinnedStableGroupKey,
    controlledRuntimeReleaseId,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  for (const [name, value] of Object.entries({
    cohortIdPattern, dispatchIdPattern, releaseIdPattern,
    representativeAlertIdPattern, stableGroupIdPattern,
  })) {
    if (!(value instanceof RegExp)) throw new TypeError(`${name} must be a RegExp`);
  }

  function conflict(message, statusCode = 409) {
    const error = new Error(message);
    error.statusCode = statusCode;
    return error;
  }

  function canonicalJsonText(value) {
    const canonicalize = (item) => {
      if (item === null || typeof item === 'string' || typeof item === 'boolean') return item;
      if (typeof item === 'number') {
        if (!Number.isFinite(item)) {
          throw conflict('controlled evaluation retirement JSON is not finite');
        }
        return item;
      }
      if (Array.isArray(item)) return item.map((entry) => canonicalize(entry));
      if (item && typeof item === 'object') {
        return Object.fromEntries(
          Object.keys(item).sort().map((key) => [key, canonicalize(item[key])]),
        );
      }
      throw conflict('controlled evaluation retirement JSON contains an unsupported value');
    };
    return JSON.stringify(canonicalize(value));
  }

  function sha256(value) {
    return crypto.createHash('sha256').update(canonicalJsonText(value), 'utf8').digest('hex');
  }

  function rawSha256(value) {
    return crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');
  }

  function normalize(payload) {
    if (!controlledEvaluationMode) {
      throw conflict('controlled evaluation retirement is unavailable in production mode', 403);
    }
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      throw conflict('controlled evaluation retirement request is invalid');
    }
    const suppliedFields = Object.keys(payload).sort();
    if (suppliedFields.length !== REQUEST_FIELDS.length
      || suppliedFields.some((field, index) => field !== REQUEST_FIELDS[index])) {
      throw conflict('controlled evaluation retirement request fields are not exact');
    }
    const completed = Array.isArray(payload.completed_dispatch_ids)
      ? [...payload.completed_dispatch_ids] : null;
    const absent = Array.isArray(payload.absent_dispatch_ids)
      ? [...payload.absent_dispatch_ids] : null;
    const ordered = completed && absent
      ? [...completed, payload.dispatch_id, ...absent] : [];
    const caseId = validIncidentCaseId(payload.case_id);
    const reason = safeString(payload.reason, 500);
    const exactStrings = [payload.cohort_id, payload.dispatch_id,
      payload.expected_attempt_id, payload.expected_job_payload_sha256,
      payload.expected_prior_analysis_id, payload.failure_attestation_sha256,
      payload.manifest_sha256, payload.reanalysis_run_id,
      payload.replacement_release_id, payload.representative_alert_id,
      payload.retired_release_id, payload.stable_group_id,
      payload.stable_group_key, payload.start_sha256];
    const analysisIdPattern = /^[A-Za-z0-9._:@=-]{1,160}$/;
    if (
      payload.schema !== RETIREMENT_SCHEMA
      || exactStrings.some((value) => typeof value !== 'string')
      || typeof payload.job_id !== 'number' || !Number.isSafeInteger(payload.job_id)
      || payload.job_id < 1 || typeof payload.member_rank !== 'number'
      || !Number.isSafeInteger(payload.member_rank) || payload.member_rank < 1
      || typeof payload.cohort_size !== 'number' || !Number.isSafeInteger(payload.cohort_size)
      || payload.cohort_size < 1 || payload.cohort_size > 100
      || payload.member_rank > payload.cohort_size
      || !completed || completed.length !== payload.member_rank - 1
      || !absent || absent.length !== payload.cohort_size - payload.member_rank
      || ordered.some((value) => typeof value !== 'string' || !dispatchIdPattern.test(value))
      || new Set(ordered).size !== payload.cohort_size
      || typeof payload.expected_attempt_count !== 'number'
      || payload.expected_attempt_count !== 1 || !caseId || payload.case_id !== caseId
      || !cohortIdPattern.test(payload.cohort_id) || !dispatchIdPattern.test(payload.dispatch_id)
      || !/^ira-[a-f0-9]{40}$/.test(payload.expected_attempt_id)
      || !dispatchIdPattern.test(payload.expected_job_payload_sha256)
      || (payload.expected_prior_analysis_id !== ''
        && !analysisIdPattern.test(payload.expected_prior_analysis_id))
      || !dispatchIdPattern.test(payload.failure_attestation_sha256)
      || !dispatchIdPattern.test(payload.manifest_sha256)
      || !/^irr-[a-z0-9-]{1,64}$/.test(payload.reanalysis_run_id)
      || !releaseIdPattern.test(payload.replacement_release_id)
      || payload.replacement_release_id !== controlledRuntimeReleaseId()
      || !representativeAlertIdPattern.test(payload.representative_alert_id)
      || !releaseIdPattern.test(payload.retired_release_id)
      || !stableGroupIdPattern.test(payload.stable_group_id)
      || !validPinnedStableGroupKey(payload.stable_group_key)
      || !dispatchIdPattern.test(payload.start_sha256)
      || typeof payload.reason !== 'string' || payload.reason !== reason || reason.length < 10
    ) throw conflict('controlled evaluation retirement identity is invalid');
    return {
      schema: RETIREMENT_SCHEMA, absent_dispatch_ids: absent, case_id: caseId,
      cohort_id: payload.cohort_id, cohort_size: payload.cohort_size,
      completed_dispatch_ids: completed, dispatch_id: payload.dispatch_id,
      expected_attempt_count: payload.expected_attempt_count,
      expected_attempt_id: payload.expected_attempt_id,
      expected_job_payload_sha256: payload.expected_job_payload_sha256,
      expected_prior_analysis_id: payload.expected_prior_analysis_id,
      failure_attestation_sha256: payload.failure_attestation_sha256,
      job_id: payload.job_id, manifest_sha256: payload.manifest_sha256,
      member_rank: payload.member_rank, reason,
      reanalysis_run_id: payload.reanalysis_run_id,
      replacement_release_id: payload.replacement_release_id,
      representative_alert_id: payload.representative_alert_id,
      retired_release_id: payload.retired_release_id,
      stable_group_id: payload.stable_group_id,
      stable_group_key: payload.stable_group_key, start_sha256: payload.start_sha256,
    };
  }

  return {conflict, canonicalJsonText, sha256, rawSha256, normalize};
}

module.exports = {EVENT_TYPE, RECEIPT_FIELDS, RECEIPT_SCHEMA, REQUEST_FIELDS,
  RETIREMENT_SCHEMA, createControlledRetirementIdentity};
