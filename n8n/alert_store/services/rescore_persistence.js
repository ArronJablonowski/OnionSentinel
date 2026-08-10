'use strict';

function createRescorePersistence({
  all, run, scoreAlert, nestedField, integerField, jsonText, enrichmentRecord,
  rebuildGroupSummaries, scoringRulesName,
}) {
  const functions = {all, run, scoreAlert, nestedField, integerField, jsonText,
    enrichmentRecord, rebuildGroupSummaries};
  for (const [name, value] of Object.entries(functions)) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  if (typeof scoringRulesName !== 'string' || !scoringRulesName) {
    throw new TypeError('scoringRulesName must be a non-empty string');
  }

  async function updateRow(row) {
    const alert = JSON.parse(row.alert_json);
    alert.triage = scoreAlert(alert);
    await run(`
      UPDATE alerts
      SET source_port = $source_port,
          destination_port = $destination_port,
          network_protocol = $network_protocol,
          transport_protocol = $transport_protocol,
          traffic_direction = $traffic_direction,
          triage_score = $triage_score,
          triage_level = $triage_level,
          routing = $routing,
          raw_event_json = $raw_event_json,
          enrichment_json = $enrichment_json,
          alert_json = $alert_json
      WHERE alert_id = $alert_id`,
    {$source_port: integerField(nestedField(alert, 'source.port')),
      $destination_port: integerField(nestedField(alert, 'destination.port')),
      $network_protocol: nestedField(alert, 'network.protocol'),
      $transport_protocol: nestedField(alert, 'network.transport')
        || nestedField(alert, 'network.iana_number'),
      $traffic_direction: alert.triage.traffic_direction,
      $triage_score: alert.triage.score, $triage_level: alert.triage.level,
      $routing: alert.triage.routing,
      $raw_event_json: jsonText(nestedField(alert, 'security_onion.raw_event')),
      $enrichment_json: jsonText(enrichmentRecord(alert)),
      $alert_json: jsonText(alert), $alert_id: row.alert_id});
  }

  async function rescore() {
    const rows = await all('SELECT alert_id, alert_json FROM alerts');
    let rescored = 0;
    let skipped = 0;
    for (const row of rows) {
      try {
        await updateRow(row);
        rescored += 1;
      } catch (_error) {
        skipped += 1;
      }
    }
    const groupSummary = await rebuildGroupSummaries();
    return {ok: true, status: 'rescored', total_alerts: rows.length, rescored, skipped,
      group_summary_groups: groupSummary.groups, scoring_rules: scoringRulesName};
  }

  return {rescore};
}

module.exports = {createRescorePersistence};
