#!/bin/zsh
set -euo pipefail

# One-command smoke test from the admin Mac. Override these env vars if hosts
# change during a rebuild.
: "${PI_HOST:?Set PI_HOST to the relay SSH target, for example relay_user@10.88.8.8}"
: "${SO_HOST:?Set SO_HOST to the Security Onion SSH target, for example so-ai-relay@192.168.1.7}"
: "${MAC_HOST:?Set MAC_HOST to the Mac Studio SSH target, for example mac_user@10.77.7.225}"
N8N_URL="${N8N_URL:-http://10.77.7.225:5678/healthz}"

echo "== Pi reachability =="
# Confirms SSH admin access plus timer status after boot/reboot.
ssh -o BatchMode=yes -o ConnectTimeout=5 "$PI_HOST" 'hostname; uptime; systemctl is-enabled so-alert-relay.timer; systemctl is-active so-alert-relay.timer; systemctl list-timers --all so-alert-relay.timer --no-pager --plain'

echo
echo "== Pi firewall paths =="
# These match the minimum pfSense rules for the relay VLAN.
ssh "$PI_HOST" 'nc -vz -w 3 192.168.1.7 22; nc -vz -w 3 10.77.7.225 5678; getent hosts api.telegram.org | head -n 1; nc -vz -w 3 api.telegram.org 443'

echo
echo "== Security Onion wrapper =="
# Checks that the export wrapper exists and sudoers still parses.
ssh "$SO_HOST" 'sudo test -x /usr/local/sbin/export-recent-alerts && sudo visudo -cf /etc/sudoers.d/90-so-ai-relay-export'

echo
echo "== Mac Studio n8n =="
# n8n health and compose status prove the webhook endpoint can receive alerts.
curl -fsS --max-time 5 "$N8N_URL"
echo
ssh "$MAC_HOST" 'cd $HOME/n8n-local && /usr/local/bin/docker compose ps'

echo
echo "== Mac Studio alert-store SQLite =="
# Confirms the alert-store DB is readable and the maintenance LaunchAgent exists.
ssh "$MAC_HOST" 'sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "PRAGMA quick_check; SELECT COUNT(*) FROM alerts; SELECT COUNT(*) FROM alert_group_summary;"'
ssh "$MAC_HOST" 'launchctl print gui/$(id -u)/com.arron.soc.alert-store-maintenance | grep -E "state =|last exit code|run interval|path ="'

echo
echo "== Pi relay recent logs =="
# Recent relay logs show counts for pulled/dropped/new/posted alerts.
ssh "$PI_HOST" 'sudo journalctl -u so-alert-relay.service -n 20 --no-pager'
