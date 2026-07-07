# Security Onion Alert Filtering Guide

## Purpose

This guide explains how to tune alert filtering in the current relay
architecture.

The important design choice is:

```text
Raspberry Pi = transport and retry safety
Mac Studio alert-store = filtering, suppression, scoring, routing
n8n = visible workflow stages and Markdown report writing
```

Do not add normal tuning rules to the Raspberry Pi relay. The Pi should stay a
dumb, reliable transport layer so the filtering behavior does not depend on the
forwarder type.

## Where Filtering Lives

Production policy file on the Mac Studio:

```text
$HOME/n8n-local/alert_store/config/scoring_rules.json
```

DR repo copy:

```text
n8n/alert_store/config/scoring_rules.json
```

The n8n workflow sends validated alerts to alert-store:

```text
n8n node: Store Score And Filter Alert
alert-store endpoint: http://alert-store:8787/alert
```

alert-store then decides:

```text
accepted   -> stored in SQLite, may generate Telegram, may generate Markdown
suppressed -> stored in SQLite, skips repeat Telegram/Markdown during TTL
dropped    -> not stored as a normal alert row, skips Telegram/Markdown
duplicate  -> updates existing SQLite row, skips Telegram/Markdown
escalated  -> suppression threshold hit, accepted again despite suppression
```

## Choosing The Right Control

Use `drop_rules` only for explicit noise that you are confident should never
create a report or notification.

Use `suppress_rules` for repeated patterns that should remain visible in
SQLite, but should not spam Telegram or Markdown reports.

Use `pair_adjustments` or `rule_adjustments` when the alert should still be
accepted, but its triage score should be lower or higher.

| Need | Use | Result |
| --- | --- | --- |
| Stop known worthless noise entirely | `drop_rules` | No normal alert row, no Markdown, no Telegram |
| Keep evidence but stop repeated noise | `suppress_rules` | Stored in SQLite, repeated Markdown/Telegram skipped during TTL |
| Lower a known benign pattern | `pair_adjustments` or `rule_adjustments` | Score/routing changes, alert still stored |
| Raise priority for important rule text | `keyword_adjustments` or `rule_adjustments` | Score/routing increases |
| Change severity thresholds globally | `thresholds` | Affects all scoring |

## Safe Tuning Workflow

1. Identify the noisy pattern from SQLite or the dashboard.

```bash
ssh <mac_user>@10.77.7.225 \
  'sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "
   SELECT filter_status, triage_level, rule_name, source_ip, destination_ip, COUNT(*) AS c
   FROM alerts
   GROUP BY filter_status, triage_level, rule_name, source_ip, destination_ip
   ORDER BY c DESC
   LIMIT 25;"'
```

2. Inspect recent examples.

```bash
ssh <mac_user>@10.77.7.225 \
  'sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "
   SELECT last_seen, filter_status, triage_level, triage_score, rule_name, source_ip, destination_ip, seen_count
   FROM alerts
   ORDER BY last_seen DESC
   LIMIT 25;"'
```

3. Edit the policy file.

```bash
ssh <mac_user>@10.77.7.225
cd $HOME/n8n-local
nano alert_store/config/scoring_rules.json
```

4. Validate the JSON before restarting alert-store.

```bash
python3 -m json.tool alert_store/config/scoring_rules.json >/dev/null
```

5. Recreate alert-store so it loads the new file.

```bash
/usr/local/bin/docker compose up -d --force-recreate alert-store
```

6. Rescore existing alerts if you changed scoring, thresholds, or adjustments.

```bash
/usr/local/bin/docker exec n8n node -e '(async()=>{const r=await fetch("http://alert-store:8787/rescore",{method:"POST"}); console.log(await r.text())})()'
```

7. Verify health and recent results.

```bash
/usr/local/bin/docker exec n8n node -e '(async()=>{const r=await fetch("http://alert-store:8787/health"); console.log(await r.text())})()'
/usr/local/bin/docker exec alert-store node /app/review_alerts.js --hours 24 --limit 20
```

8. Rebuild the SOC dashboard if you want the static portal refreshed
immediately.

```bash
python3 "$HOME/.hermes/scripts/build_soc_alerts_dashboard.py"
python3 "$HOME/n8n-local/bin/sync-soc-alerts-portal.py"
```

## Drop Rule Example

Use a drop rule only when you want the event to disappear from the analyst
workflow.

Example:

```json
{
  "name": "drop generic ICMP ping noise",
  "rule_contains": "GPL ICMP PING",
  "reason": "known low-value ping noise"
}
```

Where to put it:

```json
"drop_rules": [
  {
    "name": "drop generic ICMP ping noise",
    "rule_contains": "GPL ICMP PING",
    "reason": "known low-value ping noise"
  }
]
```

Drop rule matching supports:

```text
source_ip
destination_ip
rule_contains
keywords
```

Operational effect:

```text
status=dropped
filter_status=dropped
notification=skipped_filter
report_written=false
report_skip_reason=dropped_by_policy
```

## Suppression Rule Example

Use suppression when the pattern may still matter, but repeated alerts are too
noisy.

Example:

```json
{
  "name": "suppress repeated lab SSH scan pattern",
  "source_ip": "<example_ip>",
  "rule_contains": "<example ssh scan rule>",
  "levels": ["medium", "low"],
  "key_fields": [
    "triage.level",
    "rule_name",
    "source.ip",
    "destination.ip"
  ],
  "ttl_seconds": 1800,
  "escalation_threshold": 20,
  "reason": "repeated lab SSH scan pattern; suppress repeated reports for 30 minutes unless volume escalates"
}
```

Operational effect:

```text
first event in TTL window: accepted
repeat inside TTL: suppressed
every 20th repeat: escalated
after TTL expires: next event accepted again
```

Suppressed alerts remain in SQLite and appear in the dashboard. They skip repeat
Markdown and Telegram while the TTL is active.

## Triage Score Adjustment Example

Use score adjustments when the alert should still exist, but should route lower
or higher.

Example:

```json
{
  "source_ip": "<example_ip>",
  "destination_ip": "10.77.7.225",
  "rule_contains": "<example ssh scan rule>",
  "score_delta": -15,
  "reason": "known repeated internal SSH scan noise from lab host"
}
```

Where to put source/destination-specific tuning:

```json
"pair_adjustments": []
```

Where to put broader rule tuning:

```json
"rule_adjustments": []
```

## Verification Queries

Check status counts:

```bash
ssh <mac_user>@10.77.7.225 \
  'sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "
   SELECT COALESCE(filter_status, \"unset\") AS filter_status, COUNT(*)
   FROM alerts
   GROUP BY COALESCE(filter_status, \"unset\")
   ORDER BY COUNT(*) DESC;"'
```

Check suppression windows:

```bash
ssh <mac_user>@10.77.7.225 \
  'sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "
   SELECT suppression_key, rule_name, seen_count, suppressed_count, escalated_count, window_start, last_seen
   FROM suppression_log
   ORDER BY last_seen DESC
   LIMIT 20;"'
```

Check recent suppressed alerts:

```bash
ssh <mac_user>@10.77.7.225 \
  'sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "
   SELECT last_seen, triage_level, rule_name, source_ip, destination_ip, filter_reason
   FROM alerts
   WHERE filter_status = \"suppressed\"
   ORDER BY last_seen DESC
   LIMIT 20;"'
```

Check repeated alert groups the same way the dashboard should group them:

```bash
ssh <mac_user>@10.77.7.225 \
  'sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "
   WITH grouped AS (
     SELECT
       COALESCE(
         suppression_key,
         COALESCE(triage_level, \"unscored\") || \"|\" ||
         COALESCE(rule_name, \"unknown-rule\") || \"|\" ||
         COALESCE(source_ip, \"unknown-source\") || \"|\" ||
         COALESCE(destination_ip, \"unknown-destination\") || \"|\" ||
         COALESCE(filter_status, \"accepted\")
       ) AS alert_group_key,
       COUNT(*) AS raw_alert_count,
       COALESCE(SUM(seen_count), 0) AS total_seen_count,
       MAX(last_seen) AS last_seen,
       rule_name,
       source_ip,
       destination_ip,
       triage_level,
       filter_status
     FROM alerts
     GROUP BY alert_group_key
   )
   SELECT raw_alert_count, total_seen_count, triage_level, filter_status, rule_name, source_ip, destination_ip, last_seen
   FROM grouped
   ORDER BY total_seen_count DESC, raw_alert_count DESC
   LIMIT 25;"'
```

Dashboard expectation:

```text
one visible row per alert_group_key
duplicate/repeat count column = max(total_seen_count, raw_alert_count)
details show first_seen, last_seen, suppression_key, and representative alert content
```

Grouping note:

```text
Do not include source port in alert_group_key.
```

Source ports are usually ephemeral and will make repeated detections look
unique. Keep source port in expanded details/raw JSON for investigation, but
group by rule, source IP, destination IP, optional destination port, triage
level, and filter status.

## What Not To Do

- Do not put normal filtering on the Raspberry Pi.
- Do not hard-drop anything you may later need as evidence.
- Do not use a very long suppression TTL without an escalation threshold.
- Do not tune only from one alert. Check rule, source, destination, and recent
  volume first.
- Do not edit live JSON without validating it before restarting alert-store.

## Recovery Notes

If a bad policy change breaks alert-store:

```bash
ssh <mac_user>@10.77.7.225
cd $HOME/n8n-local
cp alert_store/config/scoring_rules.json alert_store/config/scoring_rules.json.broken
cp /path/to/known-good/scoring_rules.json alert_store/config/scoring_rules.json
python3 -m json.tool alert_store/config/scoring_rules.json >/dev/null
/usr/local/bin/docker compose up -d --force-recreate alert-store
```

The DR repo copy of the policy is:

```text
n8n/alert_store/config/scoring_rules.json
```
