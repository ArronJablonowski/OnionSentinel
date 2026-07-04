# Security Onion Node

This directory contains the Security Onion-side pieces for Onion Sentinel.

## Files

| File | Destination | Purpose |
| --- | --- | --- |
| `bin/export-recent-alerts` | `/usr/local/sbin/export-recent-alerts` | Restricted wrapper that exports recent alerts as JSON. |
| `sudoers/90-so-ai-relay-export` | `/etc/sudoers.d/90-so-ai-relay-export` | Allows only the wrapper to run passwordless for `so-ai-relay`. |
| `ssh/authorized_keys.example` | `/home/so-ai-relay/.ssh/authorized_keys` | Forced-command SSH template restricted to the relay source IP. |
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

## Validate

```bash
sudo visudo -cf /etc/sudoers.d/90-so-ai-relay-export
sudo -u so-ai-relay sudo -n /usr/local/sbin/export-recent-alerts | jq '.alerts | length'
```

Expected result: JSON prints without prompting for a password.
