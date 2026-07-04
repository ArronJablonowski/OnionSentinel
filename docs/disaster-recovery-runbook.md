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
10.88.8.8 -> NTP UDP/123
10.88.8.8 -> api.telegram.org TCP/443
```

Keep broad Internet access disabled except during update windows.

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

After editing `.env`, recreate `alert-store` so Docker Compose passes the
updated environment into the container:

```bash
cd $HOME/n8n-local
/usr/local/bin/docker compose up -d --force-recreate alert-store
```

Validate the running container without printing secrets:

```bash
/usr/local/bin/docker exec alert-store node -e 'const keys=["TELEGRAM_BOT_TOKEN","TELEGRAM_CHAT_ID","TELEGRAM_ALERT_LEVELS"]; for (const k of keys) { const v=process.env[k]||""; console.log(k+"="+(k.includes("TOKEN")&&v?"set(len="+v.length+")":v?"set":"unset")); }'
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
```

Replace:

```text
REPLACE_WITH_RELAY_TOKEN
```

with the same token that will be placed in `/etc/so-alert-relay/relay.env` on the Pi.

Activate the workflow.

The workflow writes one Obsidian-compatible Markdown report for each newly
accepted alert. Duplicate alerts return `report_written=false` and do not
create repeated files.

Alert filtering and suppression are controlled on Mac Studio in:

```text
$HOME/n8n-local/alert_store/config/scoring_rules.json
```

After changing `scoring_rules.json`, restart alert-store:

```bash
cd $HOME/n8n-local
/usr/local/bin/docker compose restart alert-store
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
python3 $HOME/.hermes/scripts/sync_report_portal.py
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
