# Security Onion Node

This directory contains the Security Onion-side pieces for Onion Sentinel.

## Files

| File | Destination | Purpose |
| --- | --- | --- |
| `bin/export-recent-alerts` | `/usr/local/sbin/export-recent-alerts` | Restricted wrapper that exports recent alerts as JSON. |
| `bin/export-pcap-window` | `/usr/local/sbin/export-pcap-window` | Restricted wrapper that exports bounded PCAP artifacts from validated JSON requests. |
| `sudoers/90-so-ai-relay-export` | `/etc/sudoers.d/90-so-ai-relay-export` | Allows only the wrapper to run passwordless for `so-ai-relay`. |
| `ssh/authorized_keys.example` | `/home/so-ai-relay/.ssh/authorized_keys` | Forced-command SSH template restricted to the relay source IP. |
| `ssh/authorized_keys.pcap.example` | `/home/so-ai-relay/.ssh/authorized_keys` | Separate forced-command SSH template for PCAP fulfillment. |
| `bin/install-security-onion-wrapper.sh` | run with `sudo` on Security Onion | Installs wrapper, sudoers, and service account scaffolding. |

## Install

```bash
cd /path/to/OnionSentinel
sudo security-onion/bin/install-security-onion-wrapper.sh
```

Then create the forced-command authorized key:

```bash
sudo install -o so-ai-relay -g so-ai-relay -m 0700 -d /home/so-ai-relay/.ssh
sudo cp security-onion/ssh/authorized_keys.example /home/so-ai-relay/.ssh/authorized_keys
sudo nano /home/so-ai-relay/.ssh/authorized_keys
sudo chown so-ai-relay:so-ai-relay /home/so-ai-relay/.ssh/authorized_keys
sudo chmod 0600 /home/so-ai-relay/.ssh/authorized_keys
```

Replace `REPLACE_WITH_PUBLIC_KEY` with the Raspberry Pi relay public key. Keep the `from="10.88.8.8"` restriction unless the relay address changes.

PCAP fulfillment should use a separate key entry based on
`security-onion/ssh/authorized_keys.pcap.example`. The wrapper reads a bounded
JSON request from stdin and writes artifacts only under
`/nsm/pcapout/onion-sentinel`.

`export-pcap-window` searches Security Onion PCAP files by modification time
and evaluates the newest bounded candidate set first. This keeps short,
recent detection windows from missing packets when `/nsm/suripcap` contains
older captures mixed with current files. The wrapper defaults to using the
destination service port as the BPF port discriminator; request JSON may set
`require_source_port: true` for controlled validation or rare cases where an
ephemeral source port is the only safe discriminator.

## Validate

```bash
sudo visudo -cf /etc/sudoers.d/90-so-ai-relay-export
sudo -u so-ai-relay sudo -n /usr/local/sbin/export-recent-alerts | jq '.alerts | length'
```

Expected result: JSON prints without prompting for a password.
