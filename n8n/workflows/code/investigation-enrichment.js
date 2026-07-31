// Authenticated, bounded investigation enrichment proxy. Provider selection,
// cache rechecks, rate limiting, normalization, and evidence retention remain
// owned by alert-store; n8n supplies the observable orchestration boundary.
const http = require('http');

const expectedToken = String($vars.RELAY_WEBHOOK_TOKEN || '').trim();
const headers = $json.headers || {};
const body = $json.body || $json;
const suppliedToken = String(headers['x-relay-token'] || headers['X-Relay-Token'] || '').trim();
const indicatorType = String(body?.indicator_type || '').trim().toLowerCase();
const indicator = String(body?.indicator || '').trim();

if (!expectedToken || expectedToken === 'REPLACE_WITH_RELAY_TOKEN') {
  throw new Error('RELAY_WEBHOOK_TOKEN is not configured in n8n');
}
if (suppliedToken !== expectedToken) {
  throw new Error('invalid or missing X-Relay-Token');
}
if (!['ip', 'domain', 'url', 'hash', 'cve'].includes(indicatorType)) {
  throw new Error('unsupported enrichment indicator_type');
}
if (!indicator || indicator.length > 2048) {
  throw new Error('indicator is missing or oversized');
}

const payload = JSON.stringify({indicator_type: indicatorType, indicator});
const result = await new Promise((resolve, reject) => {
  const request = http.request({
    hostname: 'alert-store',
    port: 8787,
    path: '/investigations/enrichment/query',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
      'X-Onion-Sentinel-Asset-Token': expectedToken,
    },
    timeout: 120000,
  }, (response) => {
    let responseBody = '';
    let bytes = 0;
    response.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > 8 * 1024 * 1024) {
        response.destroy(new Error('alert-store enrichment response exceeded 8 MiB'));
        return;
      }
      responseBody += chunk;
    });
    response.on('end', () => {
      let parsed;
      try { parsed = JSON.parse(responseBody); }
      catch { reject(new Error('alert-store returned invalid JSON')); return; }
      if (response.statusCode < 200 || response.statusCode >= 300 || parsed.ok !== true) {
        reject(new Error(`alert-store enrichment failed with HTTP ${response.statusCode}`));
        return;
      }
      resolve(parsed);
    });
  });
  request.on('timeout', () => request.destroy(new Error('alert-store enrichment timed out')));
  request.on('error', reject);
  request.write(payload);
  request.end();
});

return [{json: result}];
