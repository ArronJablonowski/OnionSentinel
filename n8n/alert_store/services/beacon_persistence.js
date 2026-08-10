'use strict';

function createBeaconPersistence({
  fs, path, processId, beaconPaths, beaconHistoryPaths, nowUtc, dateNow,
  parseProjectTimestamp, nestedField, integerField, nonNegativeIntegerField, logError,
}) {
  if (!fs || typeof fs.mkdirSync !== 'function' || typeof fs.writeFileSync !== 'function'
    || typeof fs.renameSync !== 'function' || typeof fs.readFileSync !== 'function') {
    throw new TypeError('fs must provide synchronous beacon persistence operations');
  }
  if (!path || typeof path.dirname !== 'function' || typeof path.join !== 'function'
    || typeof path.basename !== 'function') {
    throw new TypeError('path must provide dirname, join, and basename');
  }
  for (const [name, value] of Object.entries({
    nowUtc, dateNow, parseProjectTimestamp, nestedField, integerField,
    nonNegativeIntegerField, logError,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  if (!Array.isArray(beaconPaths) || !Array.isArray(beaconHistoryPaths)) {
    throw new TypeError('beacon paths must be arrays');
  }

  function writeJsonAtomic(filePath, payload) {
    // The dashboard polls this file directly, so write atomically to avoid
    // partially-read JSON while alert-store is updating the beacon.
    const directory = path.dirname(filePath);
    const tmpPath = path.join(directory, `.${path.basename(filePath)}.${processId}.tmp`);
    fs.mkdirSync(directory, {recursive: true});
    fs.writeFileSync(tmpPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
    fs.renameSync(tmpPath, filePath);
  }

  function n8nBeaconHistoryPaths() {
    const paths = new Set(beaconHistoryPaths);
    for (const filePath of beaconPaths) {
      paths.add(path.join(path.dirname(filePath), 'n8n-beacon-history.json'));
    }
    return [...paths];
  }

  function boundedPcapWorkflowState(raw) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
    const finiteNumber = (value) => {
      if (value === null || value === undefined || value === '') return null;
      return Number.isFinite(Number(value)) ? Number(value) : null;
    };
    return {
      state: String(raw.state || 'unknown').slice(0, 64),
      deferred: Boolean(raw.deferred),
      reason: String(raw.reason || '').slice(0, 300),
      metric: String(raw.metric || '').slice(0, 64),
      observed_percent: finiteNumber(raw.observed_percent),
      threshold_percent: finiteNumber(raw.threshold_percent),
      telemetry_age_seconds: finiteNumber(raw.telemetry_age_seconds),
      processed: nonNegativeIntegerField(raw.processed) || 0,
      operational_failures: nonNegativeIntegerField(raw.operational_failures) || 0,
    };
  }

  function writePcapWorkflowState(payload) {
    // Keep one latest-state file per beacon output directory. This avoids relying
    // on the bounded general beacon history during alert bursts while retaining
    // atomic local-only state with no credentials or packet evidence.
    const state = boundedPcapWorkflowState(payload?.pcap_workflow);
    if (payload?.component !== 'pcap_broker' || !state) return;
    const paths = new Set();
    for (const filePath of beaconPaths) {
      paths.add(path.join(path.dirname(filePath), 'pcap-workflow-state.json'));
    }
    for (const filePath of paths) {
      try {
        writeJsonAtomic(filePath, {
          generated_at: payload.generated_at,
          component: 'pcap_broker',
          relay_host: payload.relay_host ? String(payload.relay_host).slice(0, 128) : null,
          pcap_workflow: state,
        });
      } catch (writeError) {
        logError(`Unable to write PCAP workflow state ${filePath}: ${writeError.message}`);
      }
    }
  }

  function appendN8nBeaconHistory(payload) {
    const generatedAt = parseProjectTimestamp(payload?.generated_at);
    const cutoff = dateNow() - (72 * 60 * 60 * 1000);
    const entry = {...payload, history_recorded_at: nowUtc()};
    for (const filePath of n8nBeaconHistoryPaths()) {
      try {
        let history = [];
        try {
          const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8') || '[]');
          history = Array.isArray(parsed) ? parsed : [];
        } catch (_) {
          history = [];
        }
        history = history
          .filter((item) => {
            const itemDate = parseProjectTimestamp(
              item?.generated_at || item?.history_recorded_at,
            );
            return itemDate && itemDate.getTime() >= cutoff;
          })
          .slice(-1000);
        if (generatedAt || entry.history_recorded_at) history.push(entry);
        writeJsonAtomic(filePath, history);
      } catch (writeError) {
        logError(`Unable to write n8n beacon history ${filePath}: ${writeError.message}`);
      }
    }
  }

  function writeBeacon(stage, alert = {}, result = null, error = null) {
    const payload = {
      generated_at: nowUtc(),
      stage,
      ok: result ? Boolean(result.ok) : !error,
      status: result?.status || (error ? 'error' : 'received'),
      message_type: alert?.message_type || null,
      source: alert?.source || null,
      relay_host: alert?.relay_host || null,
      exported_at: alert?.exported_at || null,
      alert_count: Number.isFinite(Number(alert?.alert_count)) ? Number(alert.alert_count) : null,
      dropped_alert_count: Number.isFinite(Number(alert?.dropped_alert_count))
        ? Number(alert.dropped_alert_count) : null,
      filtered_alert_count: Number.isFinite(Number(alert?.filtered_alert_count))
        ? Number(alert.filtered_alert_count) : null,
      new_alert_count: Number.isFinite(Number(alert?.new_alert_count))
        ? Number(alert.new_alert_count) : null,
      duplicate_alert_count: Number.isFinite(Number(alert?.duplicate_alert_count))
        ? Number(alert.duplicate_alert_count) : null,
      posted_webhook_alerts: Number.isFinite(Number(alert?.posted_webhook_alerts))
        ? Number(alert.posted_webhook_alerts) : null,
      alert_id: alert?.alert_id || result?.alert?.alert_id || null,
      rule_name: alert?.rule_name || result?.alert?.rule_name || alert?.first_rule || null,
      source_ip: nestedField(alert, 'source.ip') || result?.alert?.source_ip || null,
      destination_ip: nestedField(alert, 'destination.ip')
        || result?.alert?.destination_ip || null,
      destination_port: integerField(nestedField(alert, 'destination.port'))
        || result?.alert?.destination_port || null,
      triage_level: result?.alert?.triage_level || result?.triage?.level || null,
      filter_status: result?.filter?.status || result?.alert?.filter_status || null,
      notification_status: result?.notification?.status || null,
      error: error ? String(error.message || error) : null,
      relay_previous_failure: alert?.relay_previous_failure || null,
      component: alert?.component || null,
      pcap_workflow: boundedPcapWorkflowState(alert?.pcap_workflow),
    };
    for (const filePath of beaconPaths) {
      try {
        writeJsonAtomic(filePath, payload);
      } catch (writeError) {
        logError(`Unable to write n8n beacon ${filePath}: ${writeError.message}`);
      }
    }
    if (stage !== 'received') {
      writePcapWorkflowState(payload);
      appendN8nBeaconHistory(payload);
    }
    return payload;
  }

  return {
    writeJsonAtomic,
    n8nBeaconHistoryPaths,
    boundedPcapWorkflowState,
    writePcapWorkflowState,
    appendN8nBeaconHistory,
    writeBeacon,
  };
}

module.exports = {createBeaconPersistence};
