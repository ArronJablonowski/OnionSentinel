# Disaster Recovery Runbook

Use this when the Pi SD card fails, the Mac Studio n8n stack breaks, or the Security Onion relay wrapper needs to be recreated.

## Assumptions

```text
Security Onion: aj@192.168.1.7
Pi relay: <relay_user>@10.88.8.8
Mac Studio: <mac_user>@10.77.7.225
Pi relay VLAN: 888 / 10.88.8.0/24
Pi relay IP: 10.88.8.8
```

## Recovery Priority

1. Restore network reachability.
2. Restore Mac Studio n8n and alert-store.
3. Restore Security Onion export wrapper.
4. Restore Pi relay.
5. Run end-to-end tests.

## 1. Network Checklist

pfSense VLAN 888 should allow:

```text
admin Mac or admin network -> 10.88.8.8 TCP/22
10.88.8.8 -> 192.168.1.7 TCP/22
10.88.8.8 -> 10.77.7.225 TCP/5678
10.88.8.8 -> DNS TCP/UDP 53
10.88.8.8 -> NTP UDP/123, preferably to the VLAN-local firewall/NTP service
temporary: 10.88.8.8 -> Internet UDP/123 until VLAN-local NTP is ready
10.88.8.8 -> api.telegram.org TCP/443
```

Keep broad Internet access disabled except during update windows.

After restoring the relay, pin `systemd-timesyncd` to the VLAN-local NTP
service using `relay/systemd/onion-sentinel-relay-vlan-timesyncd.conf.example`.
If the VLAN-local NTP service is not ready, use
`relay/systemd/onion-sentinel-relay-internet-timesyncd.conf.example` as a
temporary drop-in and allow only `10.88.8.8` to reach Internet UDP/123.
Confirm `timedatectl status` reports `System clock synchronized: yes` and
`timedatectl timesync-status` shows `Packet count` greater than `0`.

## 2. Restore Mac Studio n8n

On the Mac Studio:

```bash
cd /path/to/OnionSentinel
./n8n/bin/install-macstudio-stack.zsh
```

Create the SOC report directory used by n8n and expose it through the
Hermes/Obsidian-facing Documents path:

```bash
mkdir -p $HOME/n8n-local/soc-alerts
if [ -d "$HOME/Documents/SOC Alerts" ] && [ ! -L "$HOME/Documents/SOC Alerts" ] && [ -z "$(ls -A "$HOME/Documents/SOC Alerts")" ]; then
  rmdir "$HOME/Documents/SOC Alerts"
fi
if [ ! -e "$HOME/Documents/SOC Alerts" ]; then
  ln -s $HOME/n8n-local/soc-alerts "$HOME/Documents/SOC Alerts"
fi
```

This keeps Docker's bind mount inside `$HOME/n8n-local` while
still letting the Hermes portal read Markdown reports from
`$HOME/Documents/SOC Alerts`.

Edit:

```text
$HOME/n8n-local/.env
```

Required values:

```text
TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID
```

After editing `.env`, restart the host-native alert-store and recreate the
Docker-network proxy:

```bash
cd $HOME/n8n-local
launchctl kickstart -k gui/$(id -u)/com.arron.soc.alert-store
/usr/local/bin/docker compose up -d --force-recreate alert-store
```

Validate both the host service and Docker-network proxy:

```bash
curl -fsS http://127.0.0.1:8787/health
/usr/local/bin/docker exec n8n node -e 'fetch("http://alert-store:8787/health").then(r=>r.text()).then(console.log)'
```

If `TELEGRAM_CHAT_ID=unset`, alert-store can be healthy and still skip
high/critical Telegram sends because it has no destination chat. Medium and low
alerts are still intentionally stored without Telegram under the default
`TELEGRAM_ALERT_LEVELS=critical,high` policy.

The installer also creates editable SOC Analyst, Incident Responder, SIEM
Engineer, Cyber Threat Intel Analyst, and Threat Hunter system prompts plus the
AI model routing config only if they are missing:

```text
$HOME/n8n-local/config/soc_analyst_system_prompt.md
$HOME/n8n-local/config/incident_responder_system_prompt.md
$HOME/n8n-local/config/siem_engineer_system_prompt.md
$HOME/n8n-local/config/cyber_threat_intel_system_prompt.md
$HOME/n8n-local/config/threat_hunter_system_prompt.md
$HOME/n8n-local/config/ai_model_settings.json
```

The installer also seeds editable Cyber Security Agent Markdown memory files
only if they are missing:

```text
$HOME/n8n-local/soc-alerts/agent-memory/soc-analyst-memory.md
$HOME/n8n-local/soc-alerts/agent-memory/incident-responder-memory.md
$HOME/n8n-local/soc-alerts/agent-memory/siem-engineer-memory.md
$HOME/n8n-local/soc-alerts/agent-memory/cyber-threat-intel-memory.md
$HOME/n8n-local/soc-alerts/agent-memory/threat-hunter-memory.md
$HOME/n8n-local/soc-alerts/agent-memory/shared-agent-memory.md
```

Do not overwrite these files during normal DR redeploys if they have been tuned
or populated in production. The prompts and model routing can be edited from:

```text
http://10.77.7.225:8765/view/b68c5a48b9778061/settings.html
```

Open n8n:

```text
http://10.77.7.225:5678
```

Import:

```text
n8n/workflows/security-onion-configurable-scoring.workflow.json
n8n/workflows/onion-sentinel-pcap-broker.workflow.json
```

Replace:

```text
REPLACE_WITH_RELAY_TOKEN
REPLACE_WITH_PCAP_BROKER_TOKEN
```

Use one token for alert ingestion and a separate token for PCAP broker access.
The alert ingestion token must match `/etc/so-alert-relay/relay.env` on the Pi.
Create an n8n variable named `RELAY_WEBHOOK_TOKEN` with the same alert
ingestion token; the workflow reads `$vars.RELAY_WEBHOOK_TOKEN` so the live
token is not stored in workflow JSON, workflow history, or execution snapshots.
Create a second n8n variable named `PCAP_BROKER_TOKEN` with the same value as
the `pcap_broker.token` rendered into `/opt/so-alert-relay/app/config.json` on
the Pi. The PCAP broker workflow reads `$vars.PCAP_BROKER_TOKEN`, keeping that
live packet-evidence broker secret out of workflow JSON, workflow history, and
execution snapshots.

Activate both workflows. The PCAP broker workflow exposes relay-safe n8n proxy
routes and keeps alert-store reachable only on the Docker network:

```text
POST /webhook/pcap-requests
POST /webhook/pcap-claim
POST /webhook/pcap-complete
POST /webhook/pcap-artifact
```

The workflow writes one Obsidian-compatible Markdown report for each newly
accepted alert. Duplicate alerts return `report_written=false` and do not
create repeated files.

The alert intake workflow intentionally treats public enrichment as best-effort.
If the dedicated `Enrich Alert` node cannot reach alert-store or an upstream
provider stalls, it marks the alert with an `external_intel.errors` record and
continues to storage. `Store Score And Filter Alert` uses a 30 second
alert-store timeout. Do not reduce that timeout below normal `/alert` write
latency plus burst headroom.

Install Mac Studio packet-analysis tooling before expecting PCAP evidence in AI
reports. Zeek/zeek-cut provide structured network logs; TShark provides
protocol hierarchy and packet-field corroboration. The restore script copies the
worker and creates runtime-only directories:

```bash
/opt/homebrew/bin/brew install zeek wireshark
```

```text
$HOME/n8n-local/bin/process-pcap-evidence.py
$HOME/n8n-local/pcap-evidence/artifacts
$HOME/n8n-local/soc-alerts/pcap-analysis
$HOME/Library/LaunchAgents/com.arron.soc.pcap-analysis.plist
```

The `pcap_requests` table uses `created_at`, `claimed_at`, `completed_at`, and
`updated_at` to track broker lifecycle. If a restored database is older, restart
alert-store once after copying the current source so the additive schema
migration creates any missing lifecycle columns.

The dashboard can also queue packet evidence from the SOC Alerts table. The
`PCAP` row action calls the portal API, which writes or requeues a bounded
`pcap_requests` row and immediately returns `Queued` to the UI. The relay and
Security Onion wrapper still own capture fulfillment, so a dashboard/API
failure does not stop normal alert relay ingestion, and a relay/PCAP failure
does not stop analyst status changes or alert storage.

Alert-store also auto-queues PCAP requests for newly stored Critical and High
alerts by default through `PCAP_AUTO_REQUEST_LEVELS=critical,high`. This is
server-side ingest policy, not dashboard JavaScript. Set the variable to an
empty value during maintenance if operators need manual-only PCAP requests.

Set `ZEEK_BIN`, `ZEEK_CUT_BIN`, or `TSHARK_BIN` only if the tools are not on
the LaunchAgent `PATH`. Do not copy PCAP files or generated PCAP analysis
artifacts into the Git repo.

The Mac Studio also includes a conservative retention helper for runtime-only
packet evidence:

```bash
python3 $HOME/n8n-local/bin/maintain-pcap-evidence.py
python3 $HOME/n8n-local/bin/maintain-pcap-evidence.py --apply
```

Dry-run is the default. Raw PCAP artifacts default to 14 days, while derived
PCAP analysis JSON/Markdown defaults to 30 days. The helper refuses cleanup
paths outside `$HOME/n8n-local` so a bad argument cannot erase an operator
directory.

The optional LaunchAgent `com.arron.soc.pcap-retention` runs the helper daily
at 03:20 in dry-run mode. Keep the repo plist dry-run only; enable destructive
cleanup by adding `--apply` only to the rendered live plist after reviewing the
dry-run log.

System Health includes compact PCAP broker/parser health. `No Packets` PCAP
failures are expected negative evidence and are counted separately. Stale
pending/claimed requests older than 20 minutes and non-no-packet failures are
reported as PCAP warnings. The System Health page also lists recent PCAP broker
requests with status, request id, group id, artifact size, update time, and
sanitized error text. If `pcap-analysis.err.log` shows an old traceback
but `launchctl` reports `last exit code = 0`, run the worker directly before
assuming the schedule is broken:

```bash
python3 $HOME/n8n-local/bin/process-pcap-evidence.py --limit 1 --stdout
```

Oversize PCAP requests are counted separately from active warnings. They mean
the capture matched packets but exceeded the current inline JSON/base64 ingest
limit. Use a narrower window or more precise tuple for the immediate request;
keep larger PCAP support on the roadmap as chunked upload or direct
authenticated artifact transfer. Do not solve this by blindly raising the
Node.js request body limit.

Alert filtering and suppression are controlled on Mac Studio in:

```text
$HOME/n8n-local/alert_store/config/scoring_rules.json
```

After changing `scoring_rules.json`, restart the host-native alert-store:

```bash
cd $HOME/n8n-local
launchctl kickstart -k gui/$(id -u)/com.arron.soc.alert-store
```

Then verify health:

```bash
/usr/local/bin/docker exec n8n node -e '(async()=>{const r=await fetch("http://alert-store:8787/health"); console.log(await r.text()); if(!r.ok) process.exit(1);})().catch(()=>process.exit(1))'
```

If the SOC Alerts dashboard count or grouped rows look stale after a restore,
manually rebuild the grouped summary table:

```bash
/usr/local/bin/docker exec n8n node -e '(async()=>{const r=await fetch("http://alert-store:8787/refresh-groups",{method:"POST"}); console.log(await r.text()); if(!r.ok) process.exit(1);})().catch(()=>process.exit(1))'
```

Report output:

```text
$HOME/Documents/SOC Alerts
```

Portal refresh:

```bash
python3 $HOME/.hermes/scripts/build_soc_alerts_dashboard.py
python3 $HOME/n8n-local/bin/sync-soc-alerts-portal.py
```

Portal URL:

```text
http://10.77.7.225:8765/view/b68c5a48b9778061/
```

Low-severity report writer test:

```bash
cat > /tmp/soc-report-test-alert.json <<'JSON'
{
  "alert_id": "<example_alert_id>",
  "timestamp": "2026-07-01  20:31:15Z",
  "rule_name": "<example alert rule>",
  "event_dataset": "integration.test",
  "severity": 1,
  "severity_label": "low",
  "source": {"ip": "<example_ip>", "port": 4444},
  "destination": {"ip": "10.88.8.8", "port": 443},
  "network": {"transport": "tcp"},
  "rule_category": "test"
}
JSON

curl -sS -X POST http://127.0.0.1:5678/webhook/security-onion-alert \
  -H "Content-Type: application/json" \
  -H "X-Relay-Token: REPLACE_WITH_RELAY_TOKEN" \
  --data @/tmp/soc-report-test-alert.json
```

The dashboard sidebar health tile depends on `n8n-beacon.json`. During normal
operation, new alerts and quiet-cycle relay heartbeats both update that file.
If the tile is red, check the newest beacon timestamp and the Pi timer logs:

```bash
ssh aj_lobster@10.77.7.225 'cat "$HOME/report_portal/library/Cybersecurity/SOC Alerts/n8n-beacon.json"'
ssh aj_lobster@10.77.7.225 'curl -fsS "http://127.0.0.1:8765/api/system-health/beacons?hours=24"'
ssh aj@10.88.8.8 'systemctl list-timers --all so-alert-relay.timer --no-pager; sudo journalctl -u so-alert-relay.service -n 40 --no-pager'
```

The System Health page at `/view/b68c5a48b9778061/system-health.html` uses
`n8n-beacon-history.json` to show the last 24 hours of relay/n8n beacon events,
unsuccessful recovery-marked events, and gaps longer than 10 minutes between
successful beacons. The history file is generated beside `n8n-beacon.json` and
is runtime telemetry; do not commit it.

If n8n logs show SQLite I/O errors, validate both SQLite stores before
troubleshooting the relay:

```bash
ssh aj_lobster@10.77.7.225 'sqlite3 "$HOME/n8n-local/n8n_data/database.sqlite" "PRAGMA quick_check;"'
ssh aj_lobster@10.77.7.225 'sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "PRAGMA quick_check;"'
```

Alert-store SQLite maintenance:

```bash
ssh aj_lobster@10.77.7.225 'launchctl print gui/$(id -u)/com.arron.soc.alert-store-maintenance | grep -E "state =|last exit code|run interval|path ="'
ssh aj_lobster@10.77.7.225 '$HOME/n8n-local/bin/maintain-alert-store-sqlite.zsh'
ssh aj_lobster@10.77.7.225 'tail -80 "$HOME/n8n-local/logs/alert-store-sqlite-maintenance.log"'
ssh aj_lobster@10.77.7.225 'ls -lh "$HOME/n8n-local/alert_store_backups" | tail'
```

The maintenance job creates verified SQLite backups and recovered candidates
when corruption is detected. It also verifies that `alert_group_summary` matches
the raw `alerts` table and uses the local alert-store `/refresh-groups` endpoint
to repair stale grouped state. It sends Telegram on failure and recovery
transitions when the runtime `.env` contains Telegram credentials. It does not
replace the live DB unless `ALERT_STORE_AUTO_RECOVER=1` is explicitly set for
that run.

Alert-store SQLite should run with these durability defaults in the Mac Studio
runtime `.env` and repo compose template:

```text
ALERT_STORE_SQLITE_BUSY_TIMEOUT_MS=30000
ALERT_STORE_SQLITE_JOURNAL_MODE=DELETE
ALERT_STORE_SQLITE_SYNCHRONOUS=FULL
ALERT_STORE_SQLITE_TEMP_STORE=DEFAULT
```

The portal and alert-store can both write analyst workflow state and PCAP
request records, so all writer connections must use the same busy timeout and
DELETE/FULL durability settings. Dashboard generation should use read-only
SQLite connections. On the current Docker Desktop bind-mounted runtime path,
do not enable WAL; use a named Docker volume or host-native alert-store service
before reconsidering WAL. If a recovered DB must be swapped in, stop both
`alert-store` and the report portal before replacing `alerts.sqlite3`, then
remove stale `alerts.sqlite3-journal`, `alerts.sqlite3-wal`, and
`alerts.sqlite3-shm` sidecars before restarting.

If `quick_check` reports index-only damage such as `wrong # of entries in
index ...`, or page cleanup issues that still allow reads, use a short
alert-store maintenance window. Keep all backups in the Mac Studio runtime
tree and never copy them into Git:

```bash
ssh aj_lobster@10.77.7.225 'cd "$HOME/n8n-local" && /usr/local/bin/docker compose stop alert-store'
ssh aj_lobster@10.77.7.225 'launchctl bootout gui/$(id -u)/com.arron.soc.alert-store 2>/dev/null || true'
ssh aj_lobster@10.77.7.225 'launchctl bootout gui/$(id -u)/com.arron.reportportal 2>/dev/null || true'
ssh aj_lobster@10.77.7.225 'ts=$(date +%Y%m%dT%H%M%S%z); cp -p "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "$HOME/n8n-local/alert_store_backups/alerts.sqlite3.pre-index-repair-$ts.bak"'
ssh aj_lobster@10.77.7.225 'sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "REINDEX;"'
ssh aj_lobster@10.77.7.225 'ts=$(date +%Y%m%dT%H%M%S%z); out="$HOME/n8n-local/alert_store_data/alerts.repaired-$ts.sqlite3"; rm -f "$out"; sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "VACUUM INTO '\''$out'\'';"; sqlite3 "$out" "PRAGMA integrity_check;"; mv "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "$HOME/n8n-local/alert_store_data/alerts.sqlite3.pre-vacuum-replace-$ts.bak"; mv "$out" "$HOME/n8n-local/alert_store_data/alerts.sqlite3"; chmod 0644 "$HOME/n8n-local/alert_store_data/alerts.sqlite3"'
ssh aj_lobster@10.77.7.225 'launchctl bootstrap gui/$(id -u) "$HOME/Library/LaunchAgents/com.arron.soc.alert-store.plist" 2>/dev/null || launchctl kickstart -k gui/$(id -u)/com.arron.soc.alert-store'
ssh aj_lobster@10.77.7.225 'cd "$HOME/n8n-local" && /usr/local/bin/docker compose up -d alert-store'
ssh aj_lobster@10.77.7.225 'launchctl bootstrap gui/$(id -u) "$HOME/Library/LaunchAgents/com.arron.reportportal.plist" 2>/dev/null || launchctl kickstart -k gui/$(id -u)/com.arron.reportportal'
ssh aj_lobster@10.77.7.225 'sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "PRAGMA quick_check;"'
```

After the container is healthy, run one relay service cycle and confirm the
journal reports `alert_relay=ok pcap_broker=ok`.

If corruption is isolated to n8n execution history, stop n8n, back up the
database, recover or clear execution history, verify `PRAGMA quick_check;`,
then start n8n again. Do not copy the n8n runtime database into Git.

For high-volume relay webhooks, the repo compose template keeps bounded n8n
execution history in PostgreSQL and prunes old rows. Earlier SQLite-only
deployments used reduced execution persistence to limit write pressure, but the
PostgreSQL-backed deployment should keep successful and failed execution status
available for operational debugging.

If n8n continues to produce `SQLITE_IOERR` or `SQLITE_CORRUPT` during webhook
bursts after this tuning, migrate n8n from SQLite to PostgreSQL. The repo
compose template includes a PostgreSQL service for n8n metadata/execution state
only. Keep alert-store SQLite separate; it remains the operational alert
database.

SQLite-to-PostgreSQL migration outline:

```bash
ssh aj_lobster@10.77.7.225 'cd "$HOME/n8n-local" && ts=$(date +%Y%m%dT%H%M%S%z) && mkdir -p "n8n_data/migration-exports/$ts/entities" && /usr/local/bin/docker compose stop n8n && /usr/local/bin/docker compose run --rm --entrypoint n8n n8n export:entities --outputDir="/home/node/.n8n/migration-exports/$ts/entities" && printf "%s\n" "$ts" > n8n_data/migration-exports/latest-postgres-migration.txt'
ssh aj_lobster@10.77.7.225 'cd "$HOME/n8n-local" && /usr/local/bin/docker compose stop n8n'
ssh aj_lobster@10.77.7.225 'cd "$HOME/n8n-local" && /usr/local/bin/docker compose up -d postgres'
ssh aj_lobster@10.77.7.225 'cd "$HOME/n8n-local" && /usr/local/bin/docker compose run --rm --entrypoint n8n n8n import:entities --inputDir="/home/node/.n8n/migration-exports/<timestamp>/entities" --truncateTables'
ssh aj_lobster@10.77.7.225 'cd "$HOME/n8n-local" && /usr/local/bin/docker compose up -d n8n'
```

Use a runtime-only `N8N_POSTGRES_PASSWORD` in `$HOME/n8n-local/.env`. Do not
commit the migration export, PostgreSQL data directory, n8n runtime DB, or any
credential export.

## 3. Restore Security Onion Wrapper

Copy this repo to Security Onion or clone it there, then run:

```bash
cd /path/to/OnionSentinel
sudo ./security-onion/bin/install-security-onion-wrapper.sh
```

Create the forced-command authorized key:

```bash
sudo install -o so-ai-relay -g so-ai-relay -m 0700 -d /home/so-ai-relay/.ssh
sudo cp security-onion/ssh/authorized_keys.example /home/so-ai-relay/.ssh/authorized_keys
sudo nano /home/so-ai-relay/.ssh/authorized_keys
sudo chown so-ai-relay:so-ai-relay /home/so-ai-relay/.ssh/authorized_keys
sudo chmod 0600 /home/so-ai-relay/.ssh/authorized_keys
```

Replace:

```text
REPLACE_WITH_PUBLIC_KEY
```

with the Pi relay public key.

Test locally:

```bash
sudo -u so-ai-relay sudo -n /usr/local/sbin/export-recent-alerts | jq '.alerts | length'
```

For PCAP fulfillment, install a separate forced-command public key using
`security-onion/ssh/authorized_keys.pcap.example`. The associated wrapper is:

```text
/usr/local/sbin/export-pcap-window
```

It accepts a bounded JSON request on stdin and writes runtime-only artifacts to
`/nsm/pcapout/onion-sentinel`.

Security Onion captures on tagged VLAN interfaces in this deployment, so the
PCAP wrapper tests a VLAN-aware BPF expression before falling back to the plain
flow filter. Requests should also carry `suricata.capture_file` when Security
Onion provided it in the raw alert. The wrapper validates that capture path is
under `/nsm/suripcap`, prefers that file first, and then scans recent candidate
files. This keeps manual and automatic PCAP requests anchored to the actual
capture file that produced the detection instead of relying only on broad
timestamp searches.

Fulfilled PCAP broker metadata is not enough for LLM analysis by itself. The
preferred path is the n8n artifact ingestion route:

```text
POST /webhook/pcap-artifact
```

The relay requests a bounded inline artifact from the Security Onion
forced-command wrapper, uploads it through n8n, and alert-store validates the
request id, size, and SHA256 before writing the runtime-only tar under:

```text
$HOME/n8n-local/pcap-evidence/artifacts/<request_id>/
```

The Mac Studio parser then runs:

```bash
$HOME/n8n-local/bin/process-pcap-evidence.py --request-id <request_id>
```

and writes bounded Zeek/TShark summaries to
`$HOME/n8n-local/soc-alerts/pcap-analysis`. The SOC Analyst prompt builder
automatically includes those summaries for matching alerts.

When parsed PCAP evidence is newer than an existing SOC Analyst report, the AI
scheduler considers that grouped detection stale and rebuilds the prompt before
calling the local model again. The dashboard's lazy detail endpoint also
appends current parsed PCAP evidence even when the static detail fragment was
built before the PCAP parser finished.

If Security Onion returns a valid negative result, such as no packets matching
the requested flow/window, the dashboard shows `No Packets` instead of a
generic failure. Operators should treat that as useful evidence about capture
coverage or tuple/window selection, not as a broken broker.

`export-pcap-window` evaluates a validated `capture_file` first, then Security
Onion capture files newest-first before applying its candidate limit. If recent
matching packets exist but no packets are returned, confirm the installed
wrapper matches this repo before widening the requested time window. The
wrapper uses destination port by default for BPF flow filtering. Use
`require_source_port: true` only for controlled validation or rare cases where
the source port is intentionally the discriminator.

## 4. Restore Pi Relay

On the Pi:

```bash
sudo apt update
sudo apt install -y python3 openssh-client netcat-openbsd jq
cd /path/to/OnionSentinel
sudo ./relay/bin/install-relay.sh
```

Install the Security Onion SSH private key:

```bash
sudo install -o soalert -g soalert -m 0700 -d /opt/so-alert-relay/keys
sudo cp /path/to/so-ai-relay_ed25519 /opt/so-alert-relay/keys/so-ai-relay_ed25519
sudo chown soalert:soalert /opt/so-alert-relay/keys/so-ai-relay_ed25519
sudo chmod 0600 /opt/so-alert-relay/keys/so-ai-relay_ed25519
```

Edit:

```text
/etc/so-alert-relay/relay.env
```

Required values:

```text
RELAY_WEBHOOK_URL
RELAY_WEBHOOK_TOKEN
TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID
```

Test pull-only:

```bash
sudo -u soalert /usr/bin/python3 /opt/so-alert-relay/app/relay.py --config /opt/so-alert-relay/app/config.json --pull-once
```

PCAP fulfillment remains disabled until the n8n broker/proxy URL, separate
broker token, and path map are configured in
`/opt/so-alert-relay/app/config.json`. The default n8n proxy configuration is:

```json
"pcap_broker": {
  "enabled": true,
  "url": "http://10.77.7.225:5678/webhook",
  "token": "REPLACE_WITH_PCAP_BROKER_TOKEN",
  "requests_method": "POST",
  "paths": {
    "requests": "/pcap-requests",
    "claim": "/pcap-claim",
    "complete": "/pcap-complete",
    "artifact": "/pcap-artifact"
  },
  "upload_artifact": true,
  "artifact_upload_mode": "inline",
  "artifact_chunk_size_bytes": 524288,
  "timeout_seconds": 20,
  "limit": 3
}
```

When enabled, it uses a separate Security Onion forced-command key and this
relay mode:

```bash
sudo -u soalert /usr/bin/python3 /opt/so-alert-relay/app/relay.py --config /opt/so-alert-relay/app/config.json --process-pcap-requests
```

The relay filters the broker response and processes only `pending` requests.
That keeps fulfillment correct even if a proxy returns recent request history
alongside pending work. A request that reaches Security Onion and returns
`no matching packets found` is valid negative packet evidence, not a relay
transport failure.

Keep `artifact_upload_mode` set to `inline` until the updated PCAP broker
workflow export has been imported and activated in n8n. After that, set it to
`chunked` to send bounded artifact chunks through the same `/pcap-artifact`
webhook. Alert-store stores chunks in a runtime-only staging directory,
validates each chunk SHA256, reassembles only when all chunks are present, and
then verifies the full artifact SHA256 before writing the final artifact.

Test service:

```bash
sudo systemctl start so-alert-relay.service
sudo journalctl -u so-alert-relay.service -n 30 --no-pager
systemctl list-timers --all so-alert-relay.timer --no-pager
```

The Pi should not own normal rule filtering. Its live config should keep:

```json
"filters": {
  "drop_alerts": []
}
```

The Pi still deduplicates exact alert IDs locally to avoid retry storms, but
drop rules, suppression windows, routing, reports, and notifications belong to
Mac Studio alert-store/n8n.

Webhook retry defaults live in `/opt/so-alert-relay/app/config.json`:

```json
"retry_attempts": 3,
"retry_backoff_seconds": 1.5,
"retry_max_backoff_seconds": 10
```

The relay retries transient webhook failures (`408`, `409`, `425`, `429`, and
`5xx`) with bounded exponential backoff. It does not retry client/auth errors
such as `400`, `401`, or `403`. Alerts are marked seen immediately after their
own successful POST, so a partial outage resumes with unposted alerts rather
than replaying the whole batch.

The relay must also fail closed on n8n workflow-level rejects. n8n may return
HTTP 200 for a workflow execution that rejected the payload inside the
validation node. `relay.py` inspects the JSON response body and treats
`ok: false` or `status: rejected` as webhook failure. This is what makes stale
relay webhook tokens visible to `relay_health_wrapper.py`, systemd, journald,
and Telegram notifications.

The n8n validation node should use:

```javascript
const expectedToken = $vars.RELAY_WEBHOOK_TOKEN || 'REPLACE_WITH_RELAY_TOKEN';
```

Do not enable broad Code-node environment-variable access just for this token.

When debugging a stale beacon, confirm the relay env and config token sources
are not drifting. Do not print token values:

```bash
ssh <relay_user>@10.88.8.8 'sudo python3 - <<'"'"'PY'"'"'
import hashlib, json
from pathlib import Path
cfg=json.loads(Path("/opt/so-alert-relay/app/config.json").read_text())
env={}
for line in Path("/etc/so-alert-relay/relay.env").read_text().splitlines():
    if line.strip() and not line.startswith("#") and "=" in line:
        k,v=line.split("=",1)
        env[k]=v.strip().strip("\"").strip("'")
for label, token in [("config", cfg.get("webhook",{}).get("token") or ""), ("env", env.get("RELAY_WEBHOOK_TOKEN") or "")]:
    print(label, "len", len(token), "sha256_12", hashlib.sha256(token.encode()).hexdigest()[:12])
PY'
```

For high-volume bursts, the wrapper must have enough time to let n8n return a
response for each new alert. Keep these timeout controls in
`/etc/so-alert-relay/relay.env`:

```bash
RELAY_COMMAND_TIMEOUT_SECONDS=300
RELAY_PCAP_TIMEOUT_SECONDS=180
RELAY_FAILURE_NOTIFY_THRESHOLD=3
```

Do not pass `RELAY_WEBHOOK_TOKEN` on the command line in production. The
wrapper should pass only `--webhook-url`; `relay.py` reads the token from
`/etc/so-alert-relay/relay.env` through the service environment so process
listings do not expose token material.

## 5. Harden Pi SSH

Apply this only after confirming at least one admin public key exists in:

```text
/home/aj/.ssh/authorized_keys
```

Install the key-only SSH drop-in:

```bash
sudo cp relay/ssh/99-key-only-admin.conf /etc/ssh/sshd_config.d/99-key-only-admin.conf
sudo chmod 0644 /etc/ssh/sshd_config.d/99-key-only-admin.conf
sudo sshd -t
sudo systemctl reload ssh
```

Expected effective settings:

```bash
sudo sshd -T | egrep '^(port|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|permitrootlogin) '
```

```text
port 22
permitrootlogin no
pubkeyauthentication yes
passwordauthentication no
kbdinteractiveauthentication no
```

Verify from an admin workstation:

```bash
ssh -o BatchMode=yes \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -o PreferredAuthentications=publickey \
  <relay_user>@10.88.8.8 'echo key_auth_ok'
```

Live hardening applied on 2026-07-01:

```text
Drop-in: /etc/ssh/sshd_config.d/99-key-only-admin.conf
Backup:  /etc/ssh/sshd_config.backup-before-key-only-20260701-202624Z
Result:  public-key login verified, password auth disabled, port 22 still open
```

## 6. Verify From Admin Mac

From this repo on the admin Mac:

```bash
./ops/verify-stack.zsh
```

## SD Card Failure Note

The Pi previously dropped into recovery shell after reboot and recovered with:

```bash
e2fsck -f -y /dev/mmcblk0p7
sync
reboot -f
```

If this repeats, replace or reimage the SD card before trusting the Pi as the production relay.
