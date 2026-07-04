# Relay-Facing n8n Docker Endpoint

The Raspberry Pi relay posts to the n8n webhook on the Mac Studio. The Docker Compose stack, alert-store code, workflow export, and launchd jobs are stored in the top-level `n8n/` directory.

Relay-side config points to:

```bash
RELAY_WEBHOOK_URL=http://10.77.7.225:5678/webhook/security-onion-alert
RELAY_WEBHOOK_TOKEN=<same value configured inside the n8n workflow validation node>
```

During restore, deploy `n8n/` on the Mac Studio before enabling the relay timer. Then confirm from the Pi:

```bash
nc -vz -w 3 10.77.7.225 5678
sudo systemctl start so-alert-relay.service
```
