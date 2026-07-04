# Security Onion Restricted SSH Alert Polling Runbook

## Purpose

This note documents the restricted SSH wrapper polling setup for Security Onion Community Edition.

The goal is to let a Raspberry Pi pull recent alert data from Security Onion without exposing the official SOC API, Elasticsearch, or unrestricted shell access. The Pi can then forward full-fidelity alerts to n8n or a local AI analysis workflow.

## Current Status

- [x] Security Onion host: `192.168.1.7`
- [x] Security Onion version: `3.1.0`
- [x] Dedicated relay user created: `so-ai-relay`
- [x] Export wrapper installed: `/usr/local/sbin/<example_identifier>`
- [x] Sudoers rule installed: `/etc/sudoers.d/<example_identifier>`
- [x] Forced-command SSH key installed: `/home/so-ai-relay/.ssh/authorized_keys`
- [x] Wrapper tested from this Mac using `work/so-ai-relay_ed25519`
- [x] Decided to prototype the relay workflow on this Mac before moving it to a Raspberry Pi
- [x] Built local Mac relay prototype at `work/so-alert-relay/relay.py`
- [x] Tested restricted SSH pull and local batch saving
- [x] Added SQLite dedupe at `work/so-alert-relay/state/seen.sqlite3`
- [x] Added local normalized alert file output at `work/so-alert-relay/state/new-alerts`
- [x] Added optional webhook forwarding
- [x] Tested webhook forwarding against a local mock endpoint
- [x] Tested webhook forwarding against local n8n Phase 1 workflow
- [x] Tested webhook forwarding against Mac Studio n8n at `10.77.7.225`
- [x] Tested webhook forwarding into Mac Studio n8n Phase 2 SQLite backend
- [x] Tested webhook forwarding into Mac Studio n8n Phase 3 triage workflow
- [x] Added Mac Studio n8n Phase 4 Telegram notification routing
- [x] Add Telegram bot token and confirm phone delivery
- [x] Temporarily widened Security Onion wrapper default lookback from `15m` to `90m` for development testing
- [ ] Copy the private key to the Raspberry Pi
- [x] Add `from="10.88.8.8"` restriction after the Pi static IP is assigned
- [ ] Build the Pi relay service that deduplicates and forwards to n8n

## Architecture

```text
Raspberry Pi relay
  -> SSH to Security Onion as so-ai-relay
  -> Security Onion forces /usr/local/sbin/<example_identifier>
  -> Wrapper queries recent alerts with <example_identifier>
  -> Wrapper returns normalized JSON
  -> Pi deduplicates alerts
  -> Pi POSTs full-fidelity alerts to n8n or local AI
```

## Why This Method

Security Onion Community Edition does not provide the supported Pro notification/API workflow needed for clean outbound webhook alerts. This restricted SSH wrapper avoids exposing Elasticsearch directly while still giving the Pi a narrow, read-only alert export path.

## Security Model

The `so-ai-relay` user is intentionally limited:

- It has no password login.
- Its SSH key is forced to run one command.
- It cannot request a PTY.
- It cannot forward ports.
- It cannot forward an SSH agent.
- It cannot run X11 forwarding.
- It can only run one sudo command: `/usr/local/sbin/<example_identifier>`.

The planned Raspberry Pi relay IP is:

```text
10.88.8.8 on SOC_RELAY / VLAN 888 / 10.88.8.0/24
```

Once the Pi is using that IP, the SSH key should also be limited with:

```text
from="10.88.8.8"
```

## Files Created On Security Onion

### `/usr/local/sbin/<example_identifier>`

This script:

- Looks back over recent alerts.
- Queries `logs-suricata.alerts-so` and `logs-detections.alerts-so`.
- Limits output to a safe maximum.
- Full-fidelity mode preserves raw event bodies and packet/payload fields when Security Onion provides them.
- Emits compact JSON for the relay.

### `/etc/sudoers.d/<example_identifier>`

This file allows only:

```text
so-ai-relay ALL=(root) NOPASSWD: /usr/local/sbin/<example_identifier>
```

### `/home/so-ai-relay/.ssh/authorized_keys`

This contains the relay public key with forced-command restrictions:

```text
command="sudo -n /usr/local/sbin/<example_identifier>",no-agent-forwarding,no-X11-forwarding,no-port-forwarding,no-pty,no-user-rc ssh-ed25519 ...
```

## Manual Setup Commands

Run the Security Onion-side commands from a trusted admin workstation that already has SSH access as an administrative user, for example `aj`.

### 1. Confirm Security Onion Access

```bash
ssh aj@192.168.1.7 'hostname; cat /etc/soversion; sudo -n true && echo sudo-ok'
```

What this does:

- Connects to Security Onion.
- Prints the hostname.
- Prints the installed Security Onion version.
- Confirms non-interactive sudo works.

Expected result:

```text
onion
3.1.0
sudo-ok
```

### 2. Generate A Dedicated Relay SSH Key

Run this on the Pi or on your workstation before copying the key to the Pi.

```bash
ssh-keygen -t ed25519 -N '' -C 'so-ai-relay@security-onion' -f ./so-ai-relay_ed25519
chmod 600 ./so-ai-relay_ed25519
```

What this does:

- Creates a dedicated SSH key for the relay.
- Uses Ed25519, which is modern and compact.
- Creates an unencrypted key so a systemd service can use it unattended.
- Restricts local private key permissions.

Files created:

```text
./so-ai-relay_ed25519
./so-ai-relay_ed25519.pub
```

Important:

- Keep `so-ai-relay_ed25519` private.
- Only install `so-ai-relay_ed25519.pub` on Security Onion.

### 3. Install The Alert Export Wrapper

Run this from the machine where you are administering Security Onion:

```bash
ssh aj@192.168.1.7 'sudo tee /usr/local/sbin/<example_identifier> >/dev/null && sudo chmod 0755 /usr/local/sbin/<example_identifier> && sudo chown root:root /usr/local/sbin/<example_identifier>' <<'REMOTE_SCRIPT'
#!/bin/bash
set -euo pipefail

LOOKBACK="${SO_ALERT_LOOKBACK:-15m}"
SIZE="${SO_ALERT_SIZE:-100}"
MAX_SIZE=500

if ! [[ "$SIZE" =~ ^[0-9]+$ ]]; then
  SIZE=100
fi
if (( SIZE > MAX_SIZE )); then
  SIZE=$MAX_SIZE
fi

QUERY_FILE=$(mktemp)
trap 'rm -f "$QUERY_FILE"' EXIT

cat > "$QUERY_FILE" <<JSON
{
  "size": $SIZE,
  "sort": [{"@timestamp": {"order": "asc"}}],
  "_source": [
    "@timestamp",
    "event.dataset",
    "event.category",
    "event.severity",
    "event.severity_label",
    "event.module",
    "rule.name",
    "rule.uuid",
    "rule.category",
    "rule.severity",
    "rule.action",
    "rule.ruleset",
    "rule.reference",
    "rule.metadata",
    "source.ip",
    "source.port",
    "source.as.number",
    "source.as.organization.name",
    "source.geo.country_iso_code",
    "destination.ip",
    "destination.port",
    "destination.as.number",
    "destination.as.organization.name",
    "destination.geo.country_iso_code",
    "network.transport",
    "network.community_id",
    "network.vlan.id",
    "network.public_ip",
    "network.private_ip",
    "observer.name",
    "observer.ingress.interface.name",
    "host.name"
  ],
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-$LOOKBACK"
      }
    }
  }
}
JSON

RAW=$(/usr/sbin/<example_identifier> 'logs-suricata.alerts-so,logs-detections.alerts-so/_search?ignore_unavailable=true' -d @"$QUERY_FILE")

jq -c --arg exported_at "$(date -u '+%Y-%m-%d %H:%M:%SZ')" --arg lookback "$LOOKBACK" '
{
  source: "security-onion",
  exported_at: $exported_at,
  query: {
    lookback: $lookback,
    max_alerts: (.hits.hits | length),
    total: (.hits.total.value // .hits.total // null)
  },
  alerts: [
    .hits.hits[] | ._source as $s | {
      alert_id: (._index + ":" + ._id),
      elastic_id: ._id,
      elastic_index: ._index,
      timestamp: $s["@timestamp"],
      sensor: ($s.observer.name // null),
      host: ($s.host.name // null),
      event_dataset: ($s.event.dataset // null),
      event_category: ($s.event.category // null),
      event_module: ($s.event.module // null),
      severity: ($s.event.severity // $s.rule.severity // null),
      severity_label: ($s.event.severity_label // null),
      rule_name: ($s.rule.name // null),
      rule_id: ($s.rule.uuid // null),
      rule_category: ($s.rule.category // null),
      rule_action: ($s.rule.action // null),
      rule_ruleset: ($s.rule.ruleset // null),
      rule_reference: ($s.rule.reference // null),
      rule_metadata: ($s.rule.metadata // {}),
      source: {
        ip: ($s.source.ip // null),
        port: ($s.source.port // null),
        asn: ($s.source.as.number // null),
        org: ($s.source.as.organization.name // null),
        country: ($s.source.geo.country_iso_code // null)
      },
      destination: {
        ip: ($s.destination.ip // null),
        port: ($s.destination.port // null),
        asn: ($s.destination.as.number // null),
        org: ($s.destination.as.organization.name // null),
        country: ($s.destination.geo.country_iso_code // null)
      },
      network: {
        transport: ($s.network.transport // null),
        community_id: ($s.network.community_id // null),
        vlan: ($s.network.vlan.id // null),
        public_ip: ($s.network.public_ip // []),
        private_ip: ($s.network.private_ip // [])
      },
      observer: {
        name: ($s.observer.name // null),
        ingress_interface: ($s.observer.ingress.interface.name // null)
      }
    }
  ]
}
' <<< "$RAW"
REMOTE_SCRIPT
```

What this does:

- Writes the wrapper script to Security Onion.
- Sets it executable by root and readable/executable by others.
- Ensures root owns the script.
- The script queries Security Onion's local Elasticsearch through Security Onion's own helper.
- The script outputs normalized JSON suitable for relay processing.

### 4. Create The Restricted Relay User

```bash
ssh aj@192.168.1.7 '
set -euo pipefail
if ! id so-ai-relay >/dev/null 2>&1; then
  sudo useradd --create-home --shell /bin/bash so-ai-relay
fi
sudo passwd -l so-ai-relay >/dev/null 2>&1 || true
'
```

What this does:

- Creates the `so-ai-relay` Linux user if it does not already exist.
- Creates a home directory at `/home/so-ai-relay`.
- Locks the password so password login is unavailable.

### 5. Add A Narrow Sudoers Rule

```bash
ssh aj@192.168.1.7 "
printf '%s\n' 'so-ai-relay ALL=(root) NOPASSWD: /usr/local/sbin/<example_identifier>' | sudo tee /etc/sudoers.d/<example_identifier> >/dev/null
sudo chmod 0440 /etc/sudoers.d/<example_identifier>
sudo visudo -cf /etc/sudoers.d/<example_identifier>
"
```

What this does:

- Allows `so-ai-relay` to run only `/usr/local/sbin/<example_identifier>` as root.
- Does not grant general sudo.
- Sets secure sudoers file permissions.
- Validates the sudoers syntax before relying on it.

### 6. Install The Forced-Command SSH Key

Replace `PI_IP` later once the Pi static IP is known. Until then, omit the `from="PI_IP"` portion.

Without source IP restriction:

```bash
PUB="$(cat ./so-ai-relay_ed25519.pub)"
printf '%s %s\n' 'command="sudo -n /usr/local/sbin/<example_identifier>",no-agent-forwarding,no-X11-forwarding,no-port-forwarding,no-pty,no-user-rc' "$PUB" |
ssh aj@192.168.1.7 '
sudo install -d -o so-ai-relay -g so-ai-relay -m 0700 /home/so-ai-relay/.ssh
sudo tee /home/so-ai-relay/.ssh/authorized_keys >/dev/null
sudo chown so-ai-relay:so-ai-relay /home/so-ai-relay/.ssh/authorized_keys
sudo chmod 0600 /home/so-ai-relay/.ssh/authorized_keys
sudo sshd -t
'
```

With source IP restriction:

```bash
PI_IP="10.88.8.8"
PUB="$(cat ./so-ai-relay_ed25519.pub)"
printf '%s %s\n' "from=\"$PI_IP\",command=\"sudo -n /usr/local/sbin/<example_identifier>\",no-agent-forwarding,no-X11-forwarding,no-port-forwarding,no-pty,no-user-rc" "$PUB" |
ssh aj@192.168.1.7 '
sudo install -d -o so-ai-relay -g so-ai-relay -m 0700 /home/so-ai-relay/.ssh
sudo tee /home/so-ai-relay/.ssh/authorized_keys >/dev/null
sudo chown so-ai-relay:so-ai-relay /home/so-ai-relay/.ssh/authorized_keys
sudo chmod 0600 /home/so-ai-relay/.ssh/authorized_keys
sudo sshd -t
'
```

What this does:

- Creates the relay user's `.ssh` directory.
- Installs the public key.
- Forces the key to run only the alert export wrapper.
- Blocks port forwarding, PTY allocation, user rc files, X11 forwarding, and agent forwarding.
- Validates SSH server config.
- The `from="PI_IP"` option restricts the key so it only works from the Raspberry Pi.

### 7. Test The Forced Command

Run:

```bash
ssh -i ./so-ai-relay_ed25519 \
  -o IdentitiesOnly=yes \
  -o BatchMode=yes \
  -T \
  so-ai-relay@192.168.1.7 'id' |
jq '{source, exported_at, query, alert_count:(.alerts|length), first_alert:(.alerts[0] // null)}'
```

What this does:

- Attempts to SSH as `so-ai-relay`.
- Asks the server to run `id`.
- The server should ignore `id` because of the forced command.
- The output should be alert JSON instead of Linux user information.

Expected result shape:

```json
{
  "source": "security-onion",
  "exported_at": "2026-06-30  21:27:18Z",
  "query": {
    "lookback": "15m",
    "max_alerts": 7,
    "total": 7
  },
  "alert_count": 7,
  "first_alert": {
    "rule_name": "<example ssh scan rule>"
  }
}
```

### 8. Test That Arbitrary Commands Are Blocked

```bash
ssh -i ./so-ai-relay_ed25519 \
  -o IdentitiesOnly=yes \
  -o BatchMode=yes \
  -T \
  so-ai-relay@192.168.1.7 'uname -a' |
jq -r '"forced_command_ok source=\(.source) alerts=\(.alerts|length)"'
```

What this does:

- Attempts to run `uname -a`.
- Confirms the forced command still runs instead.

Expected output:

```text
forced_command_ok source=security-onion alerts=<count>
```

## Adjusting The Query Window

The wrapper supports environment variables:

```bash
SO_ALERT_LOOKBACK=30m
SO_ALERT_SIZE=200
```

However, because the SSH key currently forces a fixed command, the client cannot pass environment variables directly unless SSH server environment passing is configured. For production, prefer fixed safe defaults in the script:

```bash
LOOKBACK="${SO_ALERT_LOOKBACK:-15m}"
SIZE="${SO_ALERT_SIZE:-100}"
MAX_SIZE=500
```

If the Pi needs different settings, edit the wrapper on Security Onion and keep the maximum cap.

## Copying The Key To The Raspberry Pi

On the Pi:

```bash
sudo install -d -m 0700 -o soalert -g soalert /opt/so-alert-relay/keys
sudo install -m 0600 -o soalert -g soalert ./so-ai-relay_ed25519 /opt/so-alert-relay/keys/so-ai-relay_ed25519
```

What this does:

- Creates a protected key directory for the relay service.
- Installs the private key with permissions that SSH will accept.
- Makes the key readable only by the relay service user.

Test from the Pi:

```bash
sudo -u soalert ssh \
  -i /opt/so-alert-relay/keys/so-ai-relay_ed25519 \
  -o IdentitiesOnly=yes \
  -o BatchMode=yes \
  -T \
  so-ai-relay@192.168.1.7 'test' |
jq '.query'
```

What this does:

- Runs the test as the relay service account.
- Confirms the Pi can pull alert JSON.

## Pi Relay Responsibilities

The Pi-side relay service should:

- Run every 30 seconds.
- Pull JSON over restricted SSH.
- Deduplicate by `alert_id`.
- Store seen IDs in SQLite.
- Forward new alerts to n8n.
- Mark alerts as seen only after successful forwarding.
- Retry on n8n failure.
- Log metadata, not full raw sensitive payloads.

## Local Mac Prototype

Prototype files:

```text
work/so-alert-relay/config.json
work/so-alert-relay/relay.py
work/so-alert-relay/mock_webhook.py
work/so-ai-relay_ed25519
```

Implemented behavior:

- Pull one alert batch over the restricted SSH wrapper.
- Save each raw pulled batch under `work/so-alert-relay/state/batches`.
- Filter already-seen alerts with SQLite.
- Save new normalized alerts under `work/so-alert-relay/state/new-alerts`.
- Optionally POST new alerts to a webhook URL.
- Mark alerts as seen only after local file output and webhook forwarding succeed.

Local pull test:

```bash
python3 work/so-alert-relay/relay.py --pull-once
```

Test result:

```text
alert_count=8
new_alert_count=8 on first run
<example_identifier>=8 on immediate second run
```

Local webhook mock test:

```bash
python3 work/so-alert-relay/mock_webhook.py
```

In another terminal:

```bash
rm -f work/so-alert-relay/state/seen.sqlite3
rm -rf work/so-alert-relay/state/new-alerts work/so-alert-relay/state/mock-webhook

python3 work/so-alert-relay/relay.py \
  --pull-once \
  --webhook-url http://127.0.0.1:8765/webhook \
  --webhook-token example-dev-token
```

Test result:

```text
new_alert_count=10
<example_identifier>=10
mock_request_count=10
db_rows=10
```

Duplicate repost test:

```bash
python3 work/so-alert-relay/relay.py \
  --pull-once \
  --webhook-url http://127.0.0.1:8765/webhook \
  --webhook-token example-dev-token
```

Test result:

```text
new_alert_count=0
<example_identifier>=0
mock_requests_added=0
```

Local n8n Phase 1 test:

```bash
rm -f work/so-alert-relay/state/seen.sqlite3

python3 work/so-alert-relay/relay.py \
  --pull-once \
  --webhook-url http://127.0.0.1:5678/webhook/<example_identifier> \
  --webhook-token example-dev-token
```

Test result:

```text
alert_count=16
new_alert_count=16
<example_identifier>=16
```

Immediate duplicate suppression test:

```text
alert_count=16
<example_identifier>=16
new_alert_count=0
<example_identifier>=0
```

Mac Studio n8n Phase 1 test:

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
```

Test result:

```text
alert_count=56
new_alert_count=56
<example_identifier>=56
```

Immediate duplicate suppression test:

```text
alert_count=56
<example_identifier>=56
new_alert_count=0
<example_identifier>=0
```

Mac Studio n8n Phase 2 SQLite test:

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

Test result:

```text
First run: alert_count=100, new_alert_count=100, <example_identifier>=100
Second run: alert_count=100, <example_identifier>=100, new_alert_count=0, <example_identifier>=0
Mac Studio SQLite rows after test: 102 total, 100 real Security Onion alerts
```

Mac Studio n8n Phase 3 triage test:

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

Test result:

```text
First run: alert_count=100, new_alert_count=100, <example_identifier>=100
Second run: alert_count=100, <example_identifier>=100, new_alert_count=0, <example_identifier>=0
Security Onion rows with triage populated: 100
Triage summary: 88 medium analyst-review, 12 low store-only
```

Development note:

```text
/usr/local/sbin/<example_identifier>
LOOKBACK="${SO_ALERT_LOOKBACK:-90m}"
```

The lookback was widened from `15m` to `90m` so the development relay could find recent alerts during testing. Before moving to production polling, choose the desired value deliberately.

## Example n8n Webhook POST

```bash
curl -X POST 'http://10.77.7.225:5678/webhook/<example_identifier>' \
  -H 'Content-Type: application/json' \
  -H 'X-Relay-Token: <example_identifier>' \
  -d @alert.json
```

What this does:

- Sends one JSON alert payload to n8n.
- Uses a shared token header so n8n can reject unauthorized requests.

## Cleanup Commands

Use these only if you want to remove the restricted SSH setup.

```bash
ssh aj@192.168.1.7 '
sudo rm -f /etc/sudoers.d/<example_identifier>
sudo rm -f /usr/local/sbin/<example_identifier>
sudo userdel -r so-ai-relay
'
```

What this does:

- Removes the sudoers rule.
- Removes the export wrapper.
- Deletes the relay user and its home directory.

## Current Test Result

Last successful local test:

```text
source=security-onion exported_at=<timestamp> alerts=<count> first_rule=<example_rule>
```

This confirms:

- SSH public key authentication works.
- Arbitrary commands are blocked by forced command.
- The wrapper can query recent Security Onion alerts.
- The returned payload is normalized JSON.

## Next Steps

- [x] Build and test the relay workflow locally on this Mac.
- [x] Create a local Python relay that pulls Security Onion alert JSON over restricted SSH.
- [x] Add SQLite dedupe locally.
- [x] Add a local development output mode that writes normalized alerts to files.
- [x] Add webhook forwarding from the Mac and test with a local mock endpoint.
- [x] Add n8n webhook forwarding from the Mac.
- [x] Test one alert end-to-end from Security Onion to n8n.
- [x] Import and activate Phase 1 workflow on Mac Studio n8n.
- [x] Test Security Onion -> Mac relay -> Mac Studio n8n.
- [x] Add Mac Studio SQLite backend for n8n-side dedupe and storage.
- [x] Test Security Onion -> Mac relay -> Mac Studio n8n -> SQLite.
- [x] Add Mac Studio n8n Phase 3 deterministic triage.
- [x] Test Security Onion -> Mac relay -> Mac Studio n8n -> SQLite triage.
- [x] Add Mac Studio n8n Phase 4 Telegram notification routing.
- [x] Confirm high/critical Telegram alert delivery to phone.
- [x] Add Mac Studio alert review report CLI.
- [x] Generate first Obsidian alert review report.
- [x] Move scoring/tuning into Mac Studio JSON config.
- [x] Add rescore action and complete first tuning pass.
- [x] Change Security Onion wrapper sort order to newest-first for live alert tests.
- [x] Run real nmap validation against `<example_ip>`; current tuning scores it as medium.
- [x] Add Obsidian investigation-note export for high/critical alerts.
- [x] Schedule Mac-side relay polling and report export with launchd.
- [x] Add Mac Studio LaunchAgent to keep Docker n8n stack running after login/reboot.
- [x] Package the working relay so it can be moved to Raspberry Pi later.
- [x] Give the Raspberry Pi a static IP/reservation: `10.88.8.8`.
- [x] Add `from="10.88.8.8"` to the forced key.
- [x] Copy the private relay key to the Pi.
- [x] Build the Pi Python relay.
- [x] Add SQLite dedupe.
- [x] Add n8n webhook forwarding.
- [x] Test one alert end-to-end through n8n.
- [ ] Add local AI summarization.

## Raspberry Pi Relay Deployment Status

Pi host:

```text
Hostname: raspberrypi
SSH: <relay_user>@10.88.8.8
Interface: eth0
Address: 10.88.8.8/24
Gateway: 10.88.8.1
OS: Debian GNU/Linux 13 trixie, aarch64
```

Installed relay paths:

```text
/opt/so-alert-relay/app/relay.py
/opt/so-alert-relay/app/<example_identifier>.py
/opt/so-alert-relay/app/config.json
/opt/so-alert-relay/keys/so-ai-relay_ed25519
/opt/so-alert-relay/state/seen.sqlite3
/opt/so-alert-relay/state/health_state.json
/opt/so-alert-relay/state/batches
/opt/so-alert-relay/state/new-alerts
/etc/so-alert-relay/relay.env
```

Systemd units:

```text
/etc/systemd/system/so-alert-relay.service
/etc/systemd/system/so-alert-relay.timer
```

Timer status:

```text
Enabled: yes
Interval: every 5 minutes
Last scheduled test: fired automatically
Next run: scheduled by systemd
```

Security Onion forced key restriction:

```text
from="10.88.8.8",command="sudo -n /usr/local/sbin/<example_identifier>",no-agent-forwarding,no-X11-forwarding,no-port-forwarding,no-pty,no-user-rc ...
```

Security Onion wrapper production adjustment:

```text
LOOKBACK="${SO_ALERT_LOOKBACK:-10m}"
```

The default lookback was reduced from the temporary development value of `90m` to `10m`.

Relay-side drop filters:

```text
Drop rule names containing: GPL ICMP PING
Drop source 10.88.8.8 -> destination 192.168.1.7 where rule contains <example ssh scan rule>
```

Validation results:

```text
Pi -> Security Onion restricted SSH: works
Pi -> Mac Studio n8n webhook: works
Mac -> Security Onion relay key after from= restriction: denied
Manual Pi service run before filters: posted 100 alerts
Manual Pi service run after filters: dropped 100, posted 0
Scheduled Pi timer run after filters: dropped 100, posted 0
Mac launchd relay job: unloaded
Mac Studio alert-store urgent count: 0
Telegram notifications from Pi migration test: 0
```

## Failure Notification Status

- [x] Added Pi-side relay health wrapper.
- [x] Added first-failure and recovery state tracking.
- [x] Added Mac Studio n8n/alert-store health monitor.
- [x] Tested Mac Studio Telegram notification path: HTTP `200`.
- [x] Tested Pi failure/recovery state logic.
- [x] Allow Pi DNS and outbound TCP/443 so Pi direct Telegram notifications can be delivered.

Pi wrapper:

```text
/opt/so-alert-relay/app/<example_identifier>.py
```

Pi service now calls the wrapper:

```text
ExecStart=/usr/bin/python3 /opt/so-alert-relay/app/<example_identifier>.py
```

Pi notification behavior:

```text
1 failed poll: records transient_failed locally, no Telegram
2 failed polls: records transient_failed locally, no Telegram
3 failed polls: attempts Telegram [FAILURE]
Repeated failures after notification: records state, suppresses repeated Telegram spam
First success after a notified failure: attempts Telegram [RECOVERY]
First success after an unnotified transient failure: no Telegram
Normal success: no Telegram
```

Current threshold setting:

```text
<example_identifier>=3
```

The Pi SSH pull timeout was increased to 45 seconds after intermittent
Security Onion SSH/export timeouts caused single-run failure/recovery pairs.
The timeout lives in:

```text
/opt/so-alert-relay/app/config.json
relay.ssh_timeout_seconds = 45
```

Root cause notes from 2026-07-02:

```text
Webhook HTTP 500 failures: n8n internal runtime SQLite reported SQLITE_NOTADB / SQLITE_CORRUPT.
Current SSH timeout failures: intermittent Security Onion pull timeout, not a permanent wrapper failure.
alert-store SQLite integrity: ok.
```

The n8n runtime database is separate from the SOC alert-store database:

```text
n8n runtime DB:       $HOME/n8n-local/n8n_data/database.sqlite
SOC alert-store DB:  $HOME/n8n-local/alert_store_data/alerts.sqlite3
```

Do not delete or replace the n8n runtime DB casually. Repair it during a short
maintenance window by stopping n8n, backing up `n8n_data`, using `sqlite3
.recover` or a known-good backup, and restarting n8n.

Suggested n8n runtime DB repair procedure:

```bash
ssh <mac_user>@10.77.7.225
cd ~/n8n-local

# Confirm the SOC alert-store DB is healthy before touching n8n runtime data.
sqlite3 alert_store_data/alerts.sqlite3 'PRAGMA integrity_check;'

# Confirm n8n runtime DB corruption.
sqlite3 n8n_data/database.sqlite 'PRAGMA integrity_check;'

# Stop n8n only. Leave alert-store available if you are doing a narrow repair.
/usr/local/bin/docker compose stop n8n

# Back up the whole n8n runtime directory before attempting recovery.
tar -czf "n8n_data-backup-$(date -u +%Y%m%d-%H%M%SZ).tgz" n8n_data

# Attempt SQLite recovery into a new file.
sqlite3 n8n_data/database.sqlite '.recover' | sqlite3 n8n_data/database.recovered.sqlite
sqlite3 n8n_data/database.recovered.sqlite 'PRAGMA integrity_check;'

# If the recovered file checks OK, swap it into place.
mv n8n_data/database.sqlite "n8n_data/database.sqlite.corrupt-$(date -u +%Y%m%d-%H%M%SZ)"
rm -f n8n_data/database.sqlite-wal n8n_data/database.sqlite-shm
mv n8n_data/database.recovered.sqlite n8n_data/database.sqlite

# Start n8n and verify container/API health.
/usr/local/bin/docker compose start n8n
/usr/local/bin/docker compose ps
curl -fsS http://127.0.0.1:5678/healthz
```

What each command does:

| Command | Purpose |
| --- | --- |
| `sqlite3 alert_store_data/alerts.sqlite3 'PRAGMA integrity_check;'` | Confirms the SOC alert database is not the corrupted DB |
| `sqlite3 n8n_data/database.sqlite 'PRAGMA integrity_check;'` | Confirms n8n's own runtime DB needs repair |
| `docker compose stop n8n` | Stops writes to the runtime DB during repair |
| `tar -czf ... n8n_data` | Creates a rollback backup of workflows, credentials, and n8n state |
| `sqlite3 ... '.recover'` | Rebuilds as much valid SQLite content as possible into a fresh DB |
| `rm -f database.sqlite-wal database.sqlite-shm` | Removes stale write-ahead-log files from the corrupt DB |
| `docker compose start n8n` | Brings the workflow engine back online |

Pi direct Telegram status:

```text
api.telegram.org resolves from 10.88.8.8.
api.telegram.org:443 is reachable from 10.88.8.8.
Explicit Pi notification test returned HTTP 200.
Simulated Pi relay failure returned Telegram HTTP 200.
Simulated Pi relay recovery returned Telegram HTTP 200.
```

VLAN 888 rules for Pi direct failure notifications:

```text
10.88.8.8 -> DNS server TCP/UDP 53
10.88.8.8 -> api.telegram.org or Internet TCP/443
```

Mac Studio monitor:

```text
$HOME/n8n-local/bin/monitor-n8n-stack.zsh
$HOME/Library/LaunchAgents/com.arron.n8n.monitor-stack.plist
```

Mac Studio monitor checks:

```text
Docker responds
n8n container is running
alert-store container is running
n8n /healthz returns healthy
alert-store /health returns healthy
```
