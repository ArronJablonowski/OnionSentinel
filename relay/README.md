# Raspberry Pi Relay Node

The relay is intentionally dumb and reliable. It pulls alerts from Security Onion through restricted SSH and POSTs new alerts to the Mac Studio n8n webhook. If a timer run has no new alerts, it sends a small heartbeat payload instead so Onion Sentinel can prove the relay and n8n path are still alive. Filtering, scoring, suppression, AI analysis, reporting, and Telegram notification decisions belong to n8n/alert-store on the Mac Studio.

## Files

| File | Destination | Purpose |
| --- | --- | --- |
| `app/relay.py` | `/opt/so-alert-relay/app/relay.py` | Pulls alert JSON and posts new alerts or quiet-cycle heartbeats. |
| `app/relay_health_wrapper.py` | `/opt/so-alert-relay/app/relay_health_wrapper.py` | Adds failure/recovery notification thresholding. |
| `config/config.example.json` | `/opt/so-alert-relay/app/config.json` | Non-secret relay config. |
| `config/relay.example.env` | `/etc/so-alert-relay/relay.env` | Secret-bearing env template. Do not commit live copy. |
| `systemd/so-alert-relay.service` | `/etc/systemd/system/so-alert-relay.service` | One relay execution. |
| `systemd/so-alert-relay.timer` | `/etc/systemd/system/so-alert-relay.timer` | Runs relay every 5 minutes. |
| `ssh/99-key-only-admin.conf` | `/etc/ssh/sshd_config.d/99-key-only-admin.conf` | Optional SSH hardening after deployment is confirmed. |

## Install

```bash
cd /path/to/OnionSentinel
sudo relay/bin/install-pi-relay.sh
```

Then install the Security Onion private key:

```bash
sudo install -o soalert -g soalert -m 0600 /path/to/so-ai-relay_ed25519 /opt/so-alert-relay/keys/so-ai-relay_ed25519
```

If PCAP fulfillment is enabled later, install a separate forced-command key for
that path:

```bash
sudo install -o soalert -g soalert -m 0600 /path/to/so-ai-relay-pcap_ed25519 /opt/so-alert-relay/keys/so-ai-relay-pcap_ed25519
```

Edit the live env file:

```bash
sudo nano /etc/so-alert-relay/relay.env
sudo chmod 0640 /etc/so-alert-relay/relay.env
sudo chown root:soalert /etc/so-alert-relay/relay.env
```

Required live values:

- `RELAY_WEBHOOK_URL`
- `RELAY_WEBHOOK_TOKEN`
- `TELEGRAM_BOT_TOKEN` for relay health notifications
- `TELEGRAM_CHAT_ID` for relay health notifications

## Validate

```bash
sudo -u soalert /usr/bin/python3 /opt/so-alert-relay/app/relay.py --config /opt/so-alert-relay/app/config.json --pull-once
sudo systemctl start so-alert-relay.service
sudo journalctl -u so-alert-relay.service -n 50 --no-pager
sudo systemctl enable --now so-alert-relay.timer
```

Quiet timer cycles should log `posted_webhook_heartbeat: true`. Alert cycles
should log `posted_webhook_alerts` greater than zero. Either path updates the
Mac Studio `n8n-beacon.json` used by dashboard health.

## Webhook Retry Behavior

The relay retries transient webhook failures before giving the timer run back to
systemd. Defaults live in `config/config.example.json`:

```json
"retry_attempts": 3,
"retry_backoff_seconds": 1.5,
"retry_max_backoff_seconds": 10
```

HTTP `408`, `409`, `425`, `429`, and `5xx` responses are retried. Client/auth
errors such as `400`, `401`, and `403` fail immediately because another retry
would repeat the same bad request. Each alert is marked seen only after its own
successful POST, so a partial-batch failure resumes with the remaining unposted
alerts on the next timer run.

## PCAP Broker

PCAP fulfillment is disabled by default in `config/config.example.json`:

```json
"pcap_broker": {
  "enabled": false,
  "url": "http://10.77.7.225:5678/webhook",
  "requests_method": "POST",
  "paths": {
    "requests": "/pcap-requests",
    "claim": "/pcap-claim",
    "complete": "/pcap-complete"
  }
}
```

When enabled, the relay polls a relay-safe n8n broker/proxy endpoint for pending
requests, claims one request at a time, sends the bounded JSON request to the
Security Onion forced-command PCAP key, and reports only artifact metadata back
to the broker. Packet artifacts stay on Security Onion under
`/nsm/pcapout/onion-sentinel`; they are runtime evidence, not repo content.
Use a separate broker token from the alert ingestion token and store it only in
the live relay config and live n8n workflow.

## Firewall Needs

From relay `10.88.8.8`:

- to Security Onion `192.168.1.7:22/tcp`
- to Mac Studio `10.77.7.225:5678/tcp`
- to DNS `53/tcp,udp`
- to `api.telegram.org:443/tcp` if relay health notifications are enabled
