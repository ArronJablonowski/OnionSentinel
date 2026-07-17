// Authenticate post-commit work before n8n touches the Markdown corpus.
// alert-store owns retries, so rejected payloads return a structured result
// that leaves the durable job pending instead of silently losing work.
const expectedToken = String($vars.RELAY_WEBHOOK_TOKEN || '').trim();
const headers = $json.headers || {};
const body = $json.body || $json;
const suppliedToken = String(headers['x-relay-token'] || headers['X-Relay-Token'] || '').trim();
const errors = [];

if (!expectedToken || expectedToken === 'REPLACE_WITH_RELAY_TOKEN') {
  errors.push('RELAY_WEBHOOK_TOKEN is not configured in n8n');
} else if (suppliedToken !== expectedToken) {
  errors.push('invalid or missing X-Relay-Token');
}
if (!body || typeof body !== 'object' || Array.isArray(body)) {
  errors.push('body must be a JSON object');
} else {
  if (!body.alert_id) errors.push('missing alert_id');
  if (!body.report_job_id) errors.push('missing report_job_id');
  if (!body.committed_at) errors.push('missing committed_at');
  if (!body.original_alert || typeof body.original_alert !== 'object' || Array.isArray(body.original_alert)) {
    errors.push('missing original_alert object');
  }
  if (body.should_write_report !== true) errors.push('should_write_report must be true');
}

if (errors.length) {
  return [{json: {
    ok: false,
    status: 'rejected',
    stage: 'validate-committed-alert',
    reason: errors.join('; '),
    alert_id: body?.alert_id || null,
    report_written: false,
  }}];
}

return [{json: {
  ...body,
  ok: true,
  status: body.status || 'accepted',
  stage: 'validate-committed-alert',
}}];
