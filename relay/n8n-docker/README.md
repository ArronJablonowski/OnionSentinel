# Relay-Facing Mac Studio Endpoints

The Raspberry Pi commits alerts through the Mac Studio's restricted SSH intake,
not through n8n. The dedicated key is forced to
`onion-sentinel-alert-intake batch`; it cannot open a shell or forward ports.
The Docker Compose stack, alert-store code, workflow export, and launchd jobs
are stored in the top-level `n8n/` directory.

n8n remains relay-facing only for PCAP control metadata and emergency HTTP
rollback. During restore, deploy `n8n/` and the host-native alert-store before
enabling the relay timers. Then confirm both narrow paths from the Pi:

```bash
nc -vz -w 3 10.77.7.225 22
nc -vz -w 3 10.77.7.225 5678
sudo systemctl start so-alert-poll.service
sudo systemctl start so-pcap-broker.service
```

Do not configure `RELAY_WEBHOOK_TOKEN` on the Pi unless emergency HTTP rollback
is explicitly enabled. The production post-commit token remains on the Mac and
inside the n8n variable store only.
