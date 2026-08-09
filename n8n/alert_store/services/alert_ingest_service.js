'use strict';

function createAlertIngestService({
  metrics,
  now,
  readJsonBody,
  writeBeacon,
  isRelayHeartbeat,
  assertDiskWriteAdmission,
  storeAlert,
}) {
  if (!metrics || typeof metrics !== 'object') {
    throw new TypeError('ingest metrics are required');
  }
  for (const [name, value] of Object.entries({
    now,
    readJsonBody,
    writeBeacon,
    isRelayHeartbeat,
    assertDiskWriteAdmission,
    storeAlert,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function ingest(request) {
    const startedAt = now();
    metrics.ingest_requests += 1;
    const alert = await readJsonBody(request);
    writeBeacon('received', alert);
    if (isRelayHeartbeat(alert)) {
      const result = {ok: true, status: 'heartbeat', stored: false};
      const beacon = writeBeacon('heartbeat', alert, result);
      return {...result, beacon};
    }
    assertDiskWriteAdmission('alert ingestion');
    const result = await storeAlert(alert);
    const latency = now() - startedAt;
    metrics.ingest_latency_ms_total += latency;
    metrics.ingest_latency_ms_max = Math.max(metrics.ingest_latency_ms_max, latency);
    writeBeacon('stored', alert, result);
    return result;
  }

  return {ingest};
}

module.exports = {createAlertIngestService};
