# Security Onion n8n SOC Alert Investigation Workflow

## Purpose

Design and build an n8n workflow that receives normalized Security Onion alerts from the local relay, validates them, deduplicates them, enriches them lightly, scores them, and eventually sends curated alert context to a local AI analyst workflow.

The first implementation should avoid AI and focus on reliable intake, validation, dedupe, scoring, and storage.

## Current Decision

- [x] Prototype from this Mac first.
- [x] Use the restricted SSH relay as the Security Onion polling method.
- [x] Send one normalized alert per webhook POST.
- [x] Start with n8n workflow mechanics before adding AI.
- [x] Created local n8n dev instance using `npx n8n`.
- [x] Imported Phase 1 workflow: `Security Onion Alert Intake - Phase 1`.
- [x] Activated workflow ID: `G2HgyXF2IJLvAW1H`.
- [x] Tested valid-token, bad-token, and incomplete-payload validation.
- [x] Tested Security Onion -> Mac relay -> n8n end-to-end.
- [x] Chose Mac Studio as the long-term n8n workflow host: `10.77.7.225:5678`.
- [x] Confirmed Mac Studio is reachable and n8n is listening on `http://10.77.7.225:5678`.
- [x] Confirmed Mac Studio n8n is running in Docker container `n8n`.
- [x] Imported and activated Phase 1 workflow on Mac Studio n8n.
- [x] Tested Mac Studio production webhook path; now accepts valid alerts.
- [x] Tested unauthenticated n8n REST API; currently returns `401 Unauthorized`.
- [x] Tested SSH as `arron@10.77.7.225`; current key is denied.
- [x] Tested SSH as `<mac_user>@10.77.7.225`; access works.
- [x] Tested Security Onion -> Mac relay -> Mac Studio n8n end-to-end.
- [x] Added internal SQLite alert-store backend for n8n-side dedupe and storage.
- [x] Updated Mac Studio workflow to `Security Onion Alert Intake - Phase 2 SQLite`.
- [x] Tested n8n-side `accepted` and `already_seen` responses.
- [x] Tested Security Onion -> Mac relay -> Mac Studio n8n -> SQLite end-to-end.
- [x] Updated Mac Studio workflow to `Security Onion Alert Intake - Phase 3 Triage`.
- [x] Added deterministic enrichment and triage scoring.
- [x] Added SQLite columns for `traffic_direction`, `triage_score`, `triage_level`, and `routing`.
- [x] Tested Security Onion -> Mac relay -> Mac Studio n8n -> SQLite triage end-to-end.
- [x] Updated Mac Studio workflow to `Security Onion Alert Intake - Phase 4 Telegram`.
- [x] Added Telegram notification routing for high/critical accepted alerts.
- [x] Configured Telegram chat ID: `<example_identifier>`.
- [x] Added Telegram bot token to Mac Studio `.env`.
- [x] Sent live Telegram test notification.
- [x] Moved scoring/tuning rules into `scoring_rules.json`.
- [x] Updated n8n workflow to `Security Onion Alert Intake - Configurable Scoring`.
- [x] Added internal rescore action for applying tuning changes to stored alerts.
- [ ] Add local AI analysis after deterministic workflow is reliable.
- [ ] Move the relay from Mac to Raspberry Pi after the workflow is proven.

## Target Architecture

```text
Security Onion
  -> restricted SSH wrapper
  -> Mac relay prototype
  -> n8n webhook intake on Mac Studio 10.77.7.225
  -> validation and dedupe
  -> deterministic enrichment and scoring
  -> storage
  -> notification
  -> local AI analysis later
```

## Security Boundaries

- Security Onion does not connect to n8n or the AI host.
- n8n does not directly query Security Onion in the first version.
- The AI system does not receive credentials for Security Onion.
- The relay sends full-fidelity alert fields, including packet/payload fields when Security Onion provides them.
- The workflow uses a shared token header: `X-Relay-Token`.
- AI output is advisory only.

## Workflow Phases

### Phase 1: Webhook Intake

- [x] Create n8n webhook endpoint.
- [x] Require `X-Relay-Token`.
- [x] Validate required alert fields.
- [x] Return a clear success or failure response.
- [x] Test one alert from the Mac relay.

Minimal node flow:

```text
Webhook
  -> Code: validate token and required fields
  -> Respond to Webhook
```

Required fields:

```text
alert_id
timestamp
rule_name
event_dataset
source.ip or destination.ip
```

### Phase 2: Dedupe And Storage

- [x] Store each accepted `alert_id`.
- [x] Ignore duplicate alert IDs.
- [x] Store the normalized alert body.
- [x] Return `already_seen` for duplicates.
- [x] Persist storage in SQLite on the Mac Studio.
- [x] Keep the SQLite API internal to Docker, not exposed on the LAN.

Minimal node flow:

```text
Webhook
  -> Validate
  -> Data Store or file/db lookup by alert_id
  -> IF duplicate: respond already_seen
  -> Store alert
  -> Respond accepted
```

### Phase 3: Deterministic Enrichment And Scoring

- [x] Identify whether source and destination IPs are private or public.
- [x] Guess traffic direction: inbound, outbound, internal, external, or unknown.
- [x] Normalize severity into a local triage score.
- [x] Add rule metadata and rule-text highlights.
- [x] Add repeat-count context through SQLite `seen_count`.
- [x] Add routing decision: `store-only`, `analyst-review`, `<example_identifier>`, or `<example_identifier>`.

Example score factors:

```text
base severity
+ destination is Security Onion or infrastructure
+ outbound to public IP
+ repeated same rule/source
+ suspicious rule category
+ MITRE command-and-control metadata
- known noisy informational rule
```

Output:

```json
{
  "triage_score": 72,
  "triage_level": "high",
  "routing": "analyst-review"
}
```

Implemented score ranges:

```text
0-39: low
40-69: medium
70-84: high
85-100: critical
```

Implemented routing:

```text
critical/high -> <example_identifier>
medium -> analyst-review
low -> store-only
duplicates -> <example_identifier>
```

### Phase 4: Notification

- [x] Send high severity alerts immediately.
- [x] Send critical severity alerts immediately.
- [x] Store medium and low severity alerts without noisy notification.
- [x] Suppress duplicate notifications.
- [x] Add notification cooldown.
- [x] Add Telegram bot token to the Mac Studio `.env`.
- [x] Confirm live Telegram delivery to cell phone.
- [ ] Add digest later if useful.

Initial routing:

```text
critical/high -> immediate notification
medium -> store only, optional digest
low -> store only
```

Implemented Telegram routing:

```text
critical/high accepted alerts -> Telegram
medium/low accepted alerts -> SQLite only
duplicates -> no Telegram
cooldown key -> triage level + rule + source IP + destination IP
cooldown window -> 900 seconds
```

### Phase 5: AI Summary

- [x] Generate daily SQLite-backed Markdown rollups for local AI context.
- [x] Build a curated AI prompt payload.
- [x] Send only normalized alert fields and deterministic enrichments.
- [x] Require valid JSON output.
- [x] Validate AI response before storing Markdown/JSON analysis notes.

Daily AI context rollups:

```text
Script: $HOME/n8n-local/bin/<example_identifier>.py
Schedule: com.arron.soc.daily-rollup at 23:55 Mac Studio local time
Output: $HOME/n8n-local/soc-alerts/daily-rollups/<example_identifier>.md
```

The rollup is the first durable memory layer for the local AI analyst. It
summarizes SQLite alert state, grouped detection Count values, suppressions,
urgent alerts, new source/destination pairs, and Telegram notification activity.

SOC dashboard grouping:

```text
group key = suppression_key, otherwise triage_level|rule_name|source_ip|destination_ip|filter_status
source port is excluded from grouping
visible grouped row = newest alert in the group
Count = summed observations across grouped SQLite rows
Detailed Alert Report = includes Duplicate Alert Timeline when Count spans multiple alert rows
Duplicate Alert Timeline table = chronological alert firing timestamp, seen count, source IP, destination IP, destination port, short alert ID
```

Timestamp display policy:

```text
Project-generated ISO-style timestamps use exactly two spaces between date and time.
Preferred: 2026-07-02  19:48:41Z
Avoid the legacy T-separated date/time form in project-generated output.
Parsers remain tolerant of old Security Onion/SQLite rows that still contain T.
Dashboard rendering normalizes old T-separated values before display.
```

Live n8n beacon metric:

```text
alert-store writes /data/n8n-beacon.json on every POST /alert webhook request
alert-store also writes /portal/n8n-beacon.json through the Docker portal mount
served URL = /view/b68c5a48b9778061/n8n-beacon.json
SOC Alerts WebUI polls n8n-beacon.json every 3 seconds
metric updated = Last n8n beacon time, rule/status, source -> destination
dashboard rebuild seeds n8n-beacon.json from the newest real alert if no live beacon exists
```

Curated AI prompt packages:

- Include `<example_identifier>` so AI analysis weighs duplicate Count, total observations, first/last seen, and repeat timing when recommending next actions and tuning actions.

```text
Script: $HOME/n8n-local/bin/<example_identifier>.py
Output: $HOME/n8n-local/soc-alerts/ai-prompts
Default policy: local LLM first, hosted second opinion allowed for high/critical
```

Local AI analysis runner:

```text
Script: $HOME/n8n-local/bin/<example_identifier>.py
Default model: devstral:latest via local Ollama
Output: $HOME/n8n-local/soc-alerts/ai-analysis
```

Editable SOC Analyst system prompt:

```text
Prompt file: $HOME/n8n-local/config/<example_identifier>.md
Dashboard page: http://10.77.7.225:8765/view/b68c5a48b9778061/settings.html
Save API: /api/soc-settings/analyst-prompt
```

- The Settings page shows the current `SOC Analyst` system prompt in an editable code block.
- Saving requires a valid LAN Portal Administration session. If Save returns `Sign in to Administration`, open `http://10.77.7.225:8765/admin`, sign in, then save again from Settings.
- `<example_identifier>.py` loads this file immediately before calling Ollama, so new analyses use the updated prompt without restarting n8n or launchd.
- `<example_identifier>.py` also records the same prompt text in the prompt package `instructions.role` field so evidence bundles and model calls stay aligned.
- The DR installer creates the file on a fresh Mac Studio but does not overwrite an existing tuned production prompt.

Manual command:

```bash
$HOME/n8n-local/bin/<example_identifier>.py --generate-prompt --levels critical,high,medium --hours 24 --related-limit 8 --model devstral:latest --timeout 240
```

2026-07-02 validation:

```text
newest prompt package -> devstral:latest -> validated JSON -> Markdown AI note
alert: <example scan rule>
```

AI prompt guardrails:

```text
Use only the provided JSON.
Do not invent packet contents, users, processes, hostnames, filenames, or commands.
If evidence is missing, say so.
Return valid JSON only.
```

Expected AI response:

```json
{
  "summary": "Short analyst summary.",
  "likely_meaning": "What the alert may indicate.",
  "severity_reasoning": "Why this matters.",
  "<example_identifier>": [],
  "<example_identifier>": [],
  "confidence": "medium",
  "escalation_needed": true
}
```

### Phase 6: Investigation Notes

- [x] Generate Markdown investigation notes.
- [x] Save notes into Obsidian or a dedicated investigations folder.
- [x] Include alert details, scoring, SOC query starters, and analyst checkboxes.
- [x] Generate daily SOC rollup notes for local AI and analyst review.
- [ ] Add AI summary once Phase 5 is implemented.

Example investigation note:

```markdown
# Security Onion Alert Investigation

## Alert
- Time:
- Rule:
- Severity:
- Source:
- Destination:
- VLAN:
- Community ID:

## Deterministic Triage

## AI Summary

## Recommended Next Steps

## Analyst Notes

## Status
- [ ] Reviewed
- [ ] False positive
- [ ] Needs follow-up
- [ ] Escalated
```

Implemented investigation note files:

```text
Mac Studio renderer:
$HOME/n8n-local/alert_store/investigation_notes.js

Local source copy:
work/alert-store/investigation_notes.js

Local Obsidian exporter:
work/alert-store/<example_identifier>.py

Default Obsidian output:
<obsidian_vault>/Security Onion/reports/investigations
```

Export high/critical investigation notes:

```bash
python3 work/alert-store/<example_identifier>.py \
  --hours 24 \
  --levels critical,high \
  --limit 10
```

Current validation result:

```text
High/critical export: count=0 because there are currently no urgent alerts.
Medium sample export: count=1, written to reports/investigations/test-samples.
```

## Retired Mac Relay Automation

- [x] Retired the Mac-side relay polling LaunchAgent.
- [x] Retired the Mac-side report export LaunchAgent.
- [x] Removed the local Application Support relay runtime copy.
- [x] Removed the Obsidian/report sync helper.

The live polling path now runs on the Raspberry Pi at `10.88.8.8`. This Mac is no longer required to stay awake for alert polling. Current host/service details are maintained in:

```text
<obsidian_vault>/Security Onion/<example_identifier>.md
```

## Raspberry Pi Relay Cutover

- [x] Deploy relay to Raspberry Pi at `10.88.8.8`.
- [x] Install relay app under `/opt/so-alert-relay`.
- [x] Store n8n webhook token in `/etc/so-alert-relay/relay.env`.
- [x] Install `so-alert-relay.service` and `so-alert-relay.timer`.
- [x] Disable Mac launchd relay polling job.
- [x] Restrict Security Onion relay SSH key to `from="10.88.8.8"`.
- [x] Reduce Security Onion wrapper lookback from `90m` to `10m`.
- [x] Add relay-side drop filters for GPL ICMP ping and relay self SSH scan noise.
- [x] Verify scheduled timer run posts `0` alerts when only filtered noise is present.
- [x] Add Pi-side failure/recovery wrapper for relay failures.
- [x] Add Mac Studio monitor LaunchAgent for Docker/n8n/alert-store health.
- [x] Test Mac Studio Telegram monitor path.
- [x] Allow Pi DNS and outbound TCP/443 for Pi direct Telegram failure/recovery delivery.
- [x] Add Mac Studio automatic local AI analysis trigger.
- [x] Validate scheduled AI trigger with a real Security Onion alert.

Current Pi relay status:

```text
Pi: <relay_user>@10.88.8.8
Timer: enabled
Interval: 5 minutes
Last scheduled validation: dropped 100, posted 0
Mac launchd relay: unloaded
Mac Studio alert-store urgent count: 0
Telegram notifications from cutover: 0
```

Failure notification components:

```text
Pi:
/opt/so-alert-relay/app/<example_identifier>.py
/opt/so-alert-relay/state/health_state.json

Mac Studio:
$HOME/n8n-local/bin/monitor-n8n-stack.zsh
$HOME/Library/LaunchAgents/com.arron.n8n.monitor-stack.plist
```

## Automatic Local AI Analysis

- [x] Deploy continuous-drain AI trigger on the Mac Studio.
- [x] Load launchd label `com.arron.soc.ai-analysis`.
- [x] Run every 5 minutes.
- [x] Prevent overlapping Ollama jobs with a lock file.
- [x] Skip alerts that already have a local AI analysis JSON artifact.
- [x] Refresh the SQLite-backed SOC dashboard while analysis is active and
      again after successful analysis.
- [x] Add animated SOC Alerts metric indicator for active local AI analysis.
- [x] Add live WebUI status polling through `soc-alerts-status.json` so the AI
      metric and per-alert AI status pills update every 5 seconds without a
      manual page refresh.

Live paths:

```text
Trigger script: $HOME/n8n-local/bin/<example_identifier>.py
LaunchAgent:    $HOME/Library/LaunchAgents/com.arron.soc.ai-analysis.plist
Lock file:      $HOME/n8n-local/run/ai-analysis.lock
Prompt output:  $HOME/n8n-local/soc-alerts/ai-prompts
AI output:      $HOME/n8n-local/soc-alerts/ai-analysis
Stdout log:     $HOME/n8n-local/logs/ai-analysis.out.log
Stderr log:     $HOME/n8n-local/logs/ai-analysis.err.log
Status JSON:    $HOME/report_portal/library/Cybersecurity/SOC Alerts/soc-alerts-status.json
```

Current trigger policy:

```text
every 5 minutes
critical, high, medium, low, and informational alerts
long lookback: 87600 hours
accepted, escalated, unknown, or suppressed filter status, with blank status treated as accepted
drain queued unanalyzed grouped detections until none remain
already analyzed group = any member alert has a local AI analysis artifact
test/validation alert IDs are skipped and should not count as queued work
local model: devstral:latest through Ollama
dashboard metric: Idle, or animated Analyzing while a runner process is active
queue priority: drain all critical newest-first, then all high newest-first, then all medium newest-first, then all low newest-first, then all informational newest-first; triage score only breaks same-time ties
launchd argument: `--max-per-run 0`, where zero means unlimited queue drain
```

2026-07-02 scheduler correction:

- The first automatic trigger selected by raw `alert_id`, so large duplicate
  groups could consume repeated runs while other grouped dashboard rows stayed
  `Not queued`.
- The trigger now computes the same duplicate group key as the dashboard and
  skips the whole group once any member alert has analysis.
- The trigger no longer caps candidate rows before group skipping. This avoids
  a large duplicate group hiding later eligible groups.
- The trigger now includes every real severity level, not only medium and
  above, because every unique accepted/escalated/unknown alert group should get
  local AI analysis.
- The trigger now uses continuous-drain mode: `--max-per-run 0`. Once a model
  job completes, the wrapper immediately selects the next queued unique group
  without waiting for the next 5-minute launchd interval. It keeps doing this
  until no eligible unanalyzed groups remain.
- Before every new selection, the wrapper re-queries SQLite and re-applies the
  full severity-first priority order. This means a newly arrived `critical`
  alert jumps ahead of older `high`, `medium`, `low`, or `informational`
  backlog as soon as the current analysis finishes.
- The selector is optimized for high-volume alert bursts. SQLite ranks eligible
  rows, collapses raw duplicates into one newest representative per dashboard
  group, and returns grouped candidates in strict severity-drain order. Python
  only skips groups that already have analysis artifacts or were already chosen
  earlier in the same drain loop.
- Real `suppressed` detections are eligible for local AI analysis so tuning and
  suppression decisions still get model review. Test/validation fixtures remain
  excluded and the dashboard labels them `Skipped` instead of `Queued`.
- The 5-minute launchd interval is now a safety wakeup for new alerts and missed
  runs, not the pacing mechanism for queued analysis.
- The lock file still prevents overlapping Ollama jobs. Queue priority is a
  strict severity drain: all eligible `critical` grouped detections are
  analyzed before any `high`, all `high` before any `medium`, all `medium`
  before any `low`, and all `low` before any `informational`. Within each
  severity bucket, newest alerts are analyzed first, followed by the next
  newest. The timestamp sort uses `last_seen`, falling back to `timestamp` and
  then `first_seen` if needed; triage score is only a final tiebreaker.
- The local AI runner repairs minor response schema drift, such as missing
  `tuning_reason`, with explicit safe defaults so a single imperfect local model
  response does not block later alerts.
- If `sync_report_portal.py` fails because an unrelated Hermes dashboard
  builder cannot access its source directory, the AI trigger still copies
  `~/SOC Alerts Web` directly to the SOC Alerts portal library path.

Validation:

```text
2026-07-02: launchd loaded, kickstart exit code 0.
2026-07-02: generated local AI artifacts for <example scan rule>.
2026-07-02: dashboard rebuild and portal sync completed after analysis.
2026-07-02: group-aware trigger generated local AI artifacts for ET INFO Python-urllib/ Suspicious User Agent.
```

## Mac Studio n8n Reboot Resilience

- [x] Confirm `n8n` and `alert-store` Docker containers use `restart: unless-stopped`.
- [x] Add Mac Studio helper script to run `docker compose up -d`.
- [x] Add Mac Studio LaunchAgent to run helper at login and every 5 minutes.
- [x] Test LaunchAgent with `launchctl kickstart`.
- [ ] Perform a controlled Mac Studio reboot test.

Container restart policy:

```text
n8n: restart=unless-stopped
alert-store: restart=unless-stopped
```

Helper script on Mac Studio:

```text
$HOME/n8n-local/bin/ensure-n8n-stack.zsh
```

LaunchAgent on Mac Studio:

```text
$HOME/Library/LaunchAgents/com.arron.n8n.ensure-stack.plist
```

Schedule:

```text
RunAtLoad: true
StartInterval: 300 seconds
```

Logs:

```text
$HOME/n8n-local/logs/ensure-n8n-stack-*.log
$HOME/n8n-local/logs/<example_identifier>.out.log
$HOME/n8n-local/logs/<example_identifier>.err.log
```

Check status:

```bash
ssh <mac_user>@10.77.7.225 \
  'launchctl print gui/502/com.arron.n8n.ensure-stack | grep -E "runs =|last exit code|run interval"'
```

Run immediately:

```bash
ssh <mac_user>@10.77.7.225 \
  'launchctl kickstart -k gui/502/com.arron.n8n.ensure-stack'
```

Verify service health:

```bash
curl http://10.77.7.225:5678/healthz

ssh <mac_user>@10.77.7.225 \
  '/usr/local/bin/docker exec n8n node -e '\''(async()=>{const r=await fetch("http://alert-store:8787/health"); console.log(await r.text())})()'\'''
```

Current validation:

```text
LaunchAgent runs: 2
Last exit code: 0
n8n health: {"status":"ok"}
alert-store health: {"ok":true,"status":"healthy"}
```

## Phase 1 Implementation Plan

We will start with the smallest reliable n8n workflow:

```text
Webhook
  -> Code: validate header token and required fields
  -> Respond to Webhook with JSON result
```

Validation rules:

- Reject missing `X-Relay-Token`.
- Reject invalid `X-Relay-Token`.
- Reject non-object JSON body.
- Reject missing `alert_id`.
- Reject missing `timestamp`.
- Reject missing `rule_name`.
- Reject missing `event_dataset`.
- Reject alerts with neither `source.ip` nor `destination.ip`.

Success response:

```json
{
  "ok": true,
  "status": "accepted",
  "alert_id": "..."
}
```

Failure response:

```json
{
  "ok": false,
  "status": "rejected",
  "reason": "missing alert_id"
}
```

## Phase 1 Test Plan

- [x] Start n8n.
- [x] Create workflow with webhook and validation code.
- [x] Activate or test the webhook.
- [x] Send a sample alert from the relay.
- [x] Confirm n8n returns accepted.
- [x] Send a bad token.
- [x] Confirm n8n rejects it.
- [x] Send malformed or incomplete alert.
- [x] Confirm n8n rejects it.

## Local n8n Dev Setup

Local n8n dev files live in:

```text
work/n8n-dev
```

Current note: the temporary local dev n8n process was stopped after the Mac Studio workflow was imported and tested. The active n8n target is now the Mac Studio at `10.77.7.225`.

Project-local n8n user folder:

```text
work/n8n-dev/user
```

Workflow file:

```text
work/n8n-dev/<example_identifier>.workflow.json
```

Workflow:

```text
Name: Security Onion Alert Intake - Phase 1
Local dev ID: G2HgyXF2IJLvAW1H
Mac Studio ID: j237Tnda0cPniG1e
Webhook path: /webhook/<example_identifier>
Local URL: http://127.0.0.1:5678/webhook/<example_identifier>
Mac Studio URL: http://10.77.7.225:5678/webhook/<example_identifier>
Shared dev token: example-dev-token
```

Start command:

```bash
cd work/n8n-dev
N8N_USER_FOLDER="$PWD/user" \
N8N_HOST=127.0.0.1 \
N8N_PORT=5678 \
N8N_PROTOCOL=http \
npx -y n8n start
```

Import command:

```bash
cd work/n8n-dev
N8N_USER_FOLDER="$PWD/user" \
npx -y n8n import:workflow --input <example_identifier>.workflow.json
```

Activate command:

```bash
cd work/n8n-dev
N8N_USER_FOLDER="$PWD/user" \
npx -y n8n update:workflow --id G2HgyXF2IJLvAW1H --active=true
```

## Phase 1 Test Results

Valid-token test:

```bash
curl -sS -X POST http://127.0.0.1:5678/webhook/<example_identifier> \
  -H 'Content-Type: application/json' \
  -H 'X-Relay-Token: example-dev-token' \
  --data-binary @SAMPLE_ALERT.json
```

Result:

```json
{
  "ok": true,
  "status": "accepted"
}
```

Bad-token test:

```json
{
  "ok": false,
  "status": "rejected",
  "reason": "invalid or missing X-Relay-Token"
}
```

Incomplete-payload test:

```json
{
  "ok": false,
  "status": "rejected",
  "reason": "missing timestamp; missing rule_name; missing event_dataset; missing source.ip or destination.ip"
}
```

Relay-to-n8n test:

```bash
rm -f work/so-alert-relay/state/seen.sqlite3

python3 work/so-alert-relay/relay.py \
  --pull-once \
  --webhook-url http://127.0.0.1:5678/webhook/<example_identifier> \
  --webhook-token example-dev-token
```

Result:

```text
alert_count=16
new_alert_count=16
<example_identifier>=16
```

Duplicate suppression test:

```text
alert_count=16
<example_identifier>=16
new_alert_count=0
<example_identifier>=0
```

Note: the Security Onion wrapper default lookback was widened from `15m` to `90m` for development testing because there were no fresh alerts in the 15-minute window.

## Initial Relay Test Command

After the webhook exists:

```bash
python3 work/so-alert-relay/relay.py \
  --pull-once \
  --webhook-url http://N8N_HOST:5678/webhook/<example_identifier> \
  --webhook-token <example_identifier>
```

For n8n test-mode webhooks, the path may be:

```text
http://N8N_HOST:5678/webhook-test/<example_identifier>
```

## Things To Avoid

- Do not let n8n execute remediation yet.
- Do not send full raw packet payloads to hosted AI; local SQLite/dashboard may retain them.
- Do not give n8n or AI direct Security Onion credentials.
- Do not rely on AI for severity decisions before deterministic scoring exists.
- Do not notify on every low/informational alert.

## Current Next Step

- [x] Determine whether n8n is already running locally or elsewhere.
- [x] If not running, start n8n locally for development.
- [x] Build the Phase 1 webhook validation workflow.
- [x] Import or recreate the Phase 1 workflow on Mac Studio n8n.
- [x] Test relay forwarding to Mac Studio n8n.
- [x] Build Phase 2 n8n dedupe and storage.
- [x] Build Phase 3 deterministic enrichment and scoring.
- [x] Build Phase 4 notification routing.
- [x] Add Telegram bot token and confirm phone delivery.

## Mac Studio Deployment Status

Target:

```text
Host: 10.77.7.225
n8n URL: http://10.77.7.225:5678
Webhook URL: http://10.77.7.225:5678/webhook/<example_identifier>
```

Current checks:

```text
Ping: reachable
TCP 5678: open
TCP 22: open
n8n web UI: reachable
Docker container: n8n
SQLite backend container: alert-store
Docker image: n8nio/n8n:latest
Production webhook /webhook/<example_identifier>: active and tested
n8n REST API without auth: 401 unauthorized
SSH arron@10.77.7.225 from this Mac: public key denied
SSH <mac_user>@10.77.7.225 from this Mac: works
```

## Phase 2 SQLite Backend

Files on the Mac Studio:

```text
$HOME/n8n-local/docker-compose.yml
$HOME/n8n-local/alert_store/alert_store.js
$HOME/n8n-local/alert_store_data/alerts.sqlite3
```

Local project files:

```text
work/alert-store/alert_store.js
work/n8n-dev/<example_identifier>.workflow.json
work/n8n-backup/docker-compose.sqlite.yml
```

Docker services:

```text
n8n: exposed on 10.77.7.225:5678
alert-store: internal Docker service on alert-store:8787
```

The `alert-store` service:

- Uses SQLite database `/data/alerts.sqlite3`.
- Stores one row per `alert_id`.
- Returns `accepted` for first-seen alerts.
- Returns `already_seen` for duplicate alerts.
- Increments `seen_count` on duplicates.
- Has no host-published port.

n8n environment added for the Code node:

```text
<example_identifier>=http,https,url,fs,path
```

This allows the built-in Node modules needed for the workflow to call the
internal SQLite backend and write Obsidian-compatible Markdown reports into the
mounted `/soc-alerts` directory.

SOC report output:

```text
$HOME/Documents/SOC Alerts
```

Implementation detail:

```text
$HOME/Documents/SOC Alerts -> $HOME/n8n-local/soc-alerts
$HOME/n8n-local/soc-alerts -> mounted into n8n as /soc-alerts
```

Deploy commands used:

```bash
scp work/n8n-backup/docker-compose.sqlite.yml \
  <mac_user>@10.77.7.225:$HOME/n8n-local/docker-compose.yml

scp work/alert-store/alert_store.js \
  <mac_user>@10.77.7.225:$HOME/n8n-local/alert_store/alert_store.js

scp work/n8n-dev/<example_identifier>.workflow.json \
  <mac_user>@10.77.7.225:$HOME/n8n-local/<example_identifier>.workflow.json

ssh <mac_user>@10.77.7.225 '
cd $HOME/n8n-local
/usr/local/bin/docker compose up -d n8n alert-store
/usr/local/bin/docker cp <example_identifier>.workflow.json \
  n8n:/tmp/<example_identifier>.workflow.json
/usr/local/bin/docker exec n8n \
  n8n import:workflow --input=/tmp/<example_identifier>.workflow.json
/usr/local/bin/docker exec n8n \
  n8n update:workflow --id=j237Tnda0cPniG1e --active=true
/usr/local/bin/docker restart n8n
'
```

Test results:

```text
New test alert: status=accepted, stored=true, seen_count=1
Duplicate test alert: status=already_seen, stored=false, seen_count=2
Bad token: status=rejected
Incomplete payload: status=rejected
Security Onion relay first run: alert_count=100, <example_identifier>=100
Security Onion relay second run: <example_identifier>=100, <example_identifier>=0
SQLite rows after test: 102 total, 100 real Security Onion alerts
```

## Phase 3 Deterministic Triage

Workflow:

```text
Security Onion Alert Intake - Phase 3 Triage
```

Additional SQLite columns:

```text
traffic_direction
triage_score
triage_level
routing
```

Triage factors currently implemented:

- Base score from Security Onion severity label or numeric severity.
- Traffic direction: internal, inbound, outbound, external, unknown.
- Infrastructure IP boost for `192.168.1.7` and `10.77.7.225`.
- Rule text/category boost for malware, command-and-control, exploit, scan, reconnaissance, hunting, and suspicious user-agent signals.
- Informational/low severity reduction.
- Duplicate response routing override to `<example_identifier>`.

Targeted test results:

```text
Internal scan to Mac Studio:
  traffic_direction=internal
  triage_score=71
  triage_level=high
  routing=<example_identifier>

Duplicate of same alert:
  status=already_seen
  routing=<example_identifier>

Public C2-like alert to Security Onion:
  traffic_direction=inbound
  triage_score=100
  triage_level=critical
  routing=<example_identifier>

Bad token:
  status=rejected
```

Relay test results:

```text
First run: alert_count=100, new_alert_count=100, <example_identifier>=100
Second run: alert_count=100, <example_identifier>=100, new_alert_count=0, <example_identifier>=0
Security Onion rows with triage populated: 100
SQLite triage summary:
  medium analyst-review: 88
  low store-only: 12
  high <example_identifier>: 2 test rows
  critical <example_identifier>: 1 test row
```

Operational note:

```text
After one workflow deployment/restart, n8n returned SQLITE_NOTADB from a stale SQLite sidecar file.
Stopping n8n, removing database.sqlite-shm and database.sqlite-wal, and starting n8n recreated clean sidecars.
```

## Phase 4 Telegram Notifications

Workflow:

```text
Security Onion Alert Intake - Phase 4 Telegram
```

Telegram config:

```text
Chat ID: <example_identifier>
Alert levels: critical, high
Cooldown: 900 seconds
Token storage: $HOME/n8n-local/.env on Mac Studio
```

Telegram message format:

```text
[LEVEL] Security Onion Alert
Rule name

Time: alert timestamp
Alert ID: shortened alert_id
Score: triage score
Direction: traffic direction
Route: routing decision

source.ip -> destination.ip

Why this alerted
Short explanation from deterministic triage

Reasons
- top deterministic reason
- top deterministic reason
```

Sensor name is intentionally omitted from Telegram notifications.

The bot token is not stored in the workflow JSON or in project docs. It should be entered locally with hidden terminal input:

```bash
printf "Telegram bot token: "
stty -echo
IFS= read -r TELEGRAM_BOT_TOKEN
stty echo
printf "\n"

printf "%s\n" "$TELEGRAM_BOT_TOKEN" | ssh <mac_user>@10.77.7.225 'cd $HOME/n8n-local && umask 077 && IFS= read -r token && printf "TELEGRAM_BOT_TOKEN=%s\n" "$token" > .env && /usr/local/bin/docker compose up -d --force-recreate alert-store'

unset TELEGRAM_BOT_TOKEN
```

Live test after adding token:

```text
High/critical test alert:
  triage_level=critical
  routing=<example_identifier>
  <example_identifier>=telegram
  notification_status=sent

Duplicate same alert ID:
  status=already_seen
  notification_status=skipped_duplicate
  notification_log sent_count=1

New alert ID with same level/rule/source/destination:
  status=accepted
  notification_status=skipped_cooldown
  <example_identifier>=900

Improved format test:
  notification_status=sent
  included timestamp
  included shortened alert ID
  included Why this alerted line
  omitted sensor name
```

## Alert Review Report

Operational CLI on Mac Studio:

```text
$HOME/n8n-local/alert_store/review_alerts.js
```

Run manually:

```bash
ssh <mac_user>@10.77.7.225 \
  '/usr/local/bin/docker exec alert-store node /app/review_alerts.js --hours 24 --limit 15'
```

Earlier project reports in this Mac's Obsidian vault were created manually by
running `review_alerts.js` over SSH from this Mac and redirecting the output to
the vault. Production report generation now lives on Mac Studio inside the n8n
workflow.

Old manual report location:

```text
<obsidian_vault>/Security Onion/reports/<example_identifier>.md
```

Current production report location:

```text
$HOME/Documents/SOC Alerts
```

Report sections:

- Summary.
- Alerts by triage level and route.
- Top rules.
- Top source/destination pairs.
- Urgent alerts.
- Telegram notifications.

Default behavior excludes phase/test alerts. Add `--include-tests` when testing notification behavior.

## Config-Driven Tuning

Active n8n workflow:

```text
Security Onion Alert Intake - Configurable Scoring
```

Scoring is now owned by `alert-store`, not by n8n workflow code.

Tuning file on Mac Studio:

```text
$HOME/n8n-local/alert_store/config/scoring_rules.json
```

Local project copy:

```text
work/alert-store/config/scoring_rules.json
```

Tuning workflow:

```bash
ssh <mac_user>@10.77.7.225
cd $HOME/n8n-local
nano alert_store/config/scoring_rules.json
/usr/local/bin/docker compose up -d --force-recreate alert-store
/usr/local/bin/docker exec n8n node -e '(async()=>{const r=await fetch("http://alert-store:8787/rescore",{method:"POST"}); console.log(await r.text())})()'
/usr/local/bin/docker exec alert-store node /app/review_alerts.js --hours 24 --limit 15
```

What each step does:

- Edit `scoring_rules.json` to change thresholds, infrastructure IPs, keyword adjustments, rule adjustments, or source/destination pair adjustments.
- Recreate `alert-store` so it loads the new config.
- Run the internal `/rescore` action so existing SQLite rows are updated with the new scoring rules.
- Regenerate the review report to see the effect.

Initial config adjustments added from the first review report:

```text
<example_ip> -> 10.77.7.225, <example ssh scan rule>: -15
<example_ip> -> 10.77.7.225, <example curl rule>: -10
```

Validation result:

```text
<example ssh scan rule> to 10.77.7.225: score 48, medium
<example curl rule> to 10.77.7.225: score 51, medium
Same SSH scan rule to 192.168.1.7 remains score 63, medium
```

## Real nmap Validation

Test command from this Mac:

```bash
nmap -Pn -T4 -p 1-1000 --reason <example_ip>
```

nmap result:

```text
<example_ip> open ports: 22, 53, 80, 443
```

Security Onion alert observed:

```text
Time: 2026-07-01  00:06:41.308Z
Rule: <example ssh scan rule>
Source: <example_ip>
Destination: <example_ip>
Alert ID: <alert_index>:<alert_id>
```

Tuning result:

```text
The temporary +30 validation override for <example_ip> -> <example_ip> was removed.
This real nmap alert now scores as medium, which is the desired level for this lab scan.
```

Pipeline result:

```text
Stored in SQLite: yes
Triage score: 48
Triage level: medium
Routing: analyst-review
Telegram notification: not sent for current tuning because Telegram is reserved for high/critical
Historical note: one Telegram notification was sent before the validation override was removed
```

Current report showing the validation:

```text
<obsidian_vault>/Security Onion/reports/<example_identifier>.md
```

Mac Studio import and activation commands used:

```bash
python3 - <<'PY'
import json, secrets, string
src = 'work/n8n-dev/<example_identifier>.workflow.json'
dst = '/tmp/<example_identifier>.macstudio.workflow.json'
w = json.load(open(src))
w['id'] = 'j237Tnda0cPniG1e'
w['active'] = False
json.dump(w, open(dst, 'w'), indent=2)
PY

scp /tmp/<example_identifier>.macstudio.workflow.json \
  <mac_user>@10.77.7.225:$HOME/n8n-local/<example_identifier>.macstudio.workflow.json

ssh <mac_user>@10.77.7.225 '
/usr/local/bin/docker cp \
  $HOME/n8n-local/<example_identifier>.macstudio.workflow.json \
  n8n:/tmp/<example_identifier>.workflow.json

/usr/local/bin/docker exec n8n \
  n8n import:workflow --input=/tmp/<example_identifier>.workflow.json

/usr/local/bin/docker exec n8n \
  n8n update:workflow --id=j237Tnda0cPniG1e --active=true

/usr/local/bin/docker restart n8n
'
```

Notes:

- The Mac Studio n8n CLI import required a non-null workflow ID.
- A temporary import copy was created with workflow ID `j237Tnda0cPniG1e`.
- Restarting the container was required before the production webhook registered.

Mac Studio webhook validation tests:

```text
Valid token: accepted
Bad token: rejected with invalid or missing X-Relay-Token
Incomplete payload: rejected with missing required field details
```

Mac Studio relay test:

```bash
tmpcfg=/tmp/<example_identifier>.json
rm -rf /tmp/<example_identifier>

jq '.relay.state_dir="/tmp/<example_identifier>"
  | .relay.batch_dir="/tmp/<example_identifier>/batches"
  | .relay.alerts_dir="/tmp/<example_identifier>/new-alerts"
  | .relay.db_path="/tmp/<example_identifier>/seen.sqlite3"' \
  work/so-alert-relay/config.json > "$tmpcfg"

python3 work/so-alert-relay/relay.py \
  --config "$tmpcfg" \
  --pull-once \
  --webhook-url http://10.77.7.225:5678/webhook/<example_identifier> \
  --webhook-token example-dev-token

python3 work/so-alert-relay/relay.py \
  --config "$tmpcfg" \
  --pull-once \
  --webhook-url http://10.77.7.225:5678/webhook/<example_identifier> \
  --webhook-token example-dev-token
```

Result:

```text
First run: alert_count=56, new_alert_count=56, <example_identifier>=56
Second run: alert_count=56, <example_identifier>=56, new_alert_count=0, <example_identifier>=0
```

## Current Filtering Architecture

As of 2026-07-01, rule filtering moved out of the Raspberry Pi relay and into
Mac Studio alert-store/n8n.

Current responsibility split:

```text
Raspberry Pi:
  - restricted SSH polling
  - exact alert_id dedupe for retry safety
  - local batch/new-alert evidence files
  - webhook transport to n8n

Mac Studio alert-store/n8n:
  - scoring
  - hard drop policy
  - TTL suppression windows
  - escalation thresholds
  - routing
  - Telegram notification decisions
  - Markdown report decisions
```

## Current n8n Workflow Nodes

As of 2026-07-01, the production n8n workflow is intentionally split into
small tuning-friendly stages instead of one large Code node.

Workflow export:

```text
/path/to/OnionSentinel/n8n/workflows/<example_identifier>.workflow.json
```

Live workflow:

```text
Security Onion Alert Intake - Configurable Scoring
ID: j237Tnda0cPniG1e
```

Node order:

| Node | Purpose | Tuning owner |
| --- | --- | --- |
| `Security Onion Alert Webhook` | Receives Pi relay POSTs on `/webhook/<example_identifier>` | n8n transport only |
| `Validate Relay Request` | Checks `X-Relay-Token`, JSON shape, and required alert fields | n8n intake validation |
| `Store Score And Filter Alert` | Sends the alert to `alert-store:8787/alert` and receives scoring, drop, suppression, and notification decisions | alert-store policy |
| `Route Report Decision` | Converts alert-store status into `should_write_report` and skip reasons | n8n routing |
| `Write SOC Markdown Report` | Writes one Markdown report to `/soc-alerts` only for accepted alerts | n8n report formatting |

Filtering and suppression are still configured in alert-store, not directly in
the n8n Code nodes. The n8n split makes each decision visible in workflow
execution history while keeping policy in one JSON file:

```text
$HOME/n8n-local/alert_store/config/scoring_rules.json
```

Validation performed after the split:

```text
accepted alert: status=accepted, report_written=true
hard-drop alert: status=dropped, report_written=false, report_skip_reason=dropped_by_policy
repeat alert first event: status=accepted, report_written=true
repeat alert second event: status=suppressed, report_written=false, report_skip_reason=suppressed_repeat
```

Pi live and template config should keep:

```json
"filters": {
  "drop_alerts": []
}
```

Policy now lives in:

```text
$HOME/n8n-local/alert_store/config/scoring_rules.json
```

Filtering/tuning runbook:

```text
<example_identifier>.md
```

Initial policy behavior:

- `drop_rules` hard-drop explicit low-value relay/noise patterns.
- `suppress_rules` store repeated alerts but suppress repeated reports and
  Telegram notifications for a TTL.
- Suppression windows expire.
- Escalation thresholds allow high-volume repeated patterns to break through
  suppression periodically.

The LAN Portal SOC Alerts page now uses SQLite-first API pagination/search for
the table body. The static builder still creates the shell, metrics, and local
Markdown/AI corpus pages, but the browser fetches grouped detections from
`/api/soc-alerts` in 75-row cursor pages so it does not load all alerts at once.
Markdown remains the local AI/reference corpus. Full rendered investigation
reports are also lazy-loaded through `/api/soc-alerts/<group_id>/detail` when a
row is expanded, so large Markdown/AI/raw-JSON report bodies do not inflate the
initial page load.

The SOC Alerts page also opens `GET /api/soc-alerts/events` as a Server-Sent
Events stream. The stream carries the current AI analysis state, per-group AI
status, n8n beacon, analyst status counts, and SQLite metrics. The page uses
those events to update cards and debounce a refresh of the current API slice,
while keeping slower polling as a fallback if EventSource is unavailable.

## Phase 8 Alert Detail Enrichment

Implemented 2026-07-02.

Goal:

```text
Each alert detail page should contain the richest practical Security Onion
context available, including packet, payload, PCAP, and HTTP body fields when
Security Onion provides them.
```

Implementation:

| Layer | Behavior |
| --- | --- |
| Security Onion exporter | Pulls the full available Security Onion alert document and adds it under `security_onion.raw_event` |
| Raspberry Pi relay | Forwards enriched alert JSON as transport; no rule filtering or enrichment decisions |
| Mac Studio alert-store | Stores full enriched alert JSON in SQLite `alerts.alert_json`, focused enrichment in `alerts.enrichment_json`, and selected raw SO context in `alerts.raw_event_json` |
| Mac Studio alert-store endpoint columns | Stores `source_port`, `destination_port`, `network_protocol`, and `transport_protocol` as first-class SQLite columns derived from alert JSON |
| SOC Alerts dashboard | Renders `AI Model Used`, `AI Analysis Output`, `Enriched Alert Details`, `Duplicate Alert Timeline`, and `Complete Alert JSON` sections from SQLite JSON/columns plus local AI artifacts, then appends missing sections to matching Markdown reports |
| Markdown corpus | Continues writing accepted alert reports under `$HOME/Documents/SOC Alerts` for local AI reference |

Full-fidelity mode:

```text
_source: true
No exporter-side field exclusions.
Packet, payload, payload_printable, PCAP, and HTTP body fields are retained when Security Onion provides them.
```

The Security Onion `message` field can contain the original Suricata event JSON
including a packet blob. In full-fidelity mode, the original raw `message`
remains in `security_onion.raw_event`; the normalized top-level `message` still
tries to extract the signature for dashboard readability.

Live validation:

```text
Security Onion exporter returned enriched keys including dns/http/tls/suricata/security_onion.
security_onion.raw_event present: yes.
raw packet/body fields retained when present: yes.
Pi relay posted enriched alerts successfully after deployment.
SOC Alerts dashboard rebuilt and contains Enriched Alert Details sections.
Detailed Alert Reports contain Complete Alert JSON.
Detailed Alert Reports contain AI Model Used and AI Analysis Output sections.
Alerts without matching local AI output explicitly show Not analyzed yet.
alert-store SQLite has raw_event_json and enrichment_json columns.
alert-store /rescore backfilled existing rows: 1217 rescored, 0 skipped.
Rows with packet/payload/PCAP strings in SQLite after validation: <count>
```

Data sensitivity warning:

```text
Full-fidelity mode can persist sensitive packet payloads, HTTP bodies, tokens,
credentials, internal URLs, and other traffic contents in SQLite, Markdown, and
the rendered dashboard. Keep the Mac Studio, SQLite database, SOC Alerts
directory, and LAN Portal restricted.
```

## Phase 8 Relay Noise Reduction

Implemented 2026-07-02.

Observed issue:

```text
Telegram showed repeated [FAILURE] and [RECOVERY] pairs.
```

Findings:

| Symptom | Root cause |
| --- | --- |
| `RuntimeError: Webhook returned HTTP 500` | n8n runtime SQLite was malformed/corrupt; n8n logged `SQLITE_NOTADB` and `SQLITE_CORRUPT` |
| `subprocess.TimeoutExpired ... so-ai-relay@192.168.1.7 ... timed out after 30 sec` | Intermittent Security Onion SSH/export timeout |

Mitigations:

```text
relay.ssh_timeout_seconds = 45
<example_identifier>=3
```

New notification behavior:

```text
Single failed poll: local log only
Three consecutive failed polls: Telegram [FAILURE]
Continued failures: local log only
Recovery Telegram: only after a failure notification was sent
```

Follow-up maintenance item:

```text
Repair n8n runtime SQLite during a maintenance window.
The SOC alert-store SQLite database is separate and passed integrity check.
```

## Phase 9 Test Alert Cleanup

Implemented 2026-07-02.

The Mac Studio alert-store SQLite database was backed up before deleting test
and validation rows:

```text
$HOME/n8n-local/alert_store_data/alerts.sqlite3.<example_identifier>.bak
```

Deleted alert rows matching these non-production prefixes:

```text
phase%
config-%
internal-test-%
sqlite-%
policy-%
codex-%
```

Validation after cleanup:

```text
Deleted test/validation rows: 20
Remaining matching test-prefix rows: 0
SQLite integrity_check: ok
SOC Alerts dashboard rebuilt from the cleaned SQLite store
Grouped dashboard reports after cleanup: 66
AI dashboard status after cleanup: 66 analyzed, 0 queued, 0 skipped
```

This cleanup removed validation artifacts from the analyst-facing table while
preserving the full SQLite backup for rollback or forensic comparison.
