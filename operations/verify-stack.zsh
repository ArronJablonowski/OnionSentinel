#!/bin/zsh
set -euo pipefail

# One-command smoke test from the admin Mac. Override these env vars if hosts
# change during a rebuild.
: "${PI_HOST:?Set PI_HOST to the relay SSH target, for example relay_user@10.88.8.8}"
: "${SO_HOST:?Set SO_HOST to the Security Onion SSH target, for example so-ai-relay@192.168.1.7}"
: "${MAC_HOST:?Set MAC_HOST to the Mac Studio SSH target, for example mac_user@10.77.7.225}"
N8N_URL="${N8N_URL:-http://10.77.7.225:5678/healthz}"
PCAP_TIMER_EXPECTED_STATE="${PCAP_TIMER_EXPECTED_STATE:-active}"

if [[ "$PCAP_TIMER_EXPECTED_STATE" != "active" && "$PCAP_TIMER_EXPECTED_STATE" != "safety-hold" ]]; then
  print -u2 "PCAP_TIMER_EXPECTED_STATE must be active or safety-hold"
  exit 2
fi

echo "== Pi reachability =="
# Confirms SSH admin access plus timer status after boot/reboot.
ssh -o BatchMode=yes -o ConnectTimeout=5 "$PI_HOST" 'hostname; uptime; systemctl is-enabled so-alert-poll.timer so-storage-health.timer; systemctl is-active so-alert-poll.timer so-storage-health.timer; systemctl list-timers --all so-alert-poll.timer so-pcap-broker.timer so-storage-health.timer --no-pager --plain; findmnt /mnt/onion-sentinel-pcap-spool; sudo -n systemctl start so-storage-health.service; test "$(systemctl show so-storage-health.service -p ExecMainStatus --value)" = 0; sudo -n /usr/sbin/smartctl -a -j /dev/sda | python3 -c '"'"'import json,sys; d=json.load(sys.stdin); n=d.get("nvme_smart_health_information_log",{}); print("smart_passed="+str((d.get("smart_status") or {}).get("passed"))); print("temperature_c="+str((d.get("temperature") or {}).get("current"))); print("media_errors="+str(n.get("media_errors"))); print("unsafe_shutdowns="+str(n.get("unsafe_shutdowns")))'"'"''
if [[ "$PCAP_TIMER_EXPECTED_STATE" == "active" ]]; then
  ssh "$PI_HOST" 'test "$(systemctl is-enabled so-pcap-broker.timer)" = enabled; test "$(systemctl is-active so-pcap-broker.timer)" = active'
else
  # A capture-loss safety hold must survive reboot and must not be mistaken for a failed alert relay.
  ssh "$PI_HOST" 'test "$(systemctl is-enabled so-pcap-broker.timer)" = disabled; test "$(systemctl is-active so-pcap-broker.timer)" = inactive'
fi

echo
echo "== Pi firewall paths =="
# These match the minimum pfSense rules for the relay VLAN.
ssh "$PI_HOST" 'nc -vz -w 3 192.168.1.7 22; nc -vz -w 3 10.77.7.225 22; nc -vz -w 3 10.77.7.225 5678; getent hosts api.telegram.org | head -n 1; nc -vz -w 3 api.telegram.org 443'

echo
echo "== Security Onion wrapper =="
# Checks that the export wrapper exists and sudoers still parses.
ssh "$SO_HOST" 'sudo test -x /usr/local/sbin/export-recent-alerts; sudo test -x /usr/local/sbin/export-pcap-window; sudo visudo -cf /etc/sudoers.d/90-so-ai-relay-export; ! systemctl is-active --quiet onion-sentinel-pcap-retention.timer; ! systemctl is-active --quiet onion-sentinel-pcapout-retention.timer; sudo test ! -e /usr/local/sbin/prune-onion-sentinel-pcapout; sudo test ! -e /nsm/pcapout/onion-sentinel; printf "%s" "{\"mode\":\"storage_status\"}" | sudo -u so-ai-relay sudo /usr/local/sbin/export-pcap-window | python3 -c '"'"'import json,sys; d=json.load(sys.stdin); print("pcap_root_used_percent="+str(d.get("pcap_root_used_percent"))); print("read_only_export="+str(d.get("read_only_export"))); print("disk_read_gate_enabled="+str(d.get("disk_read_gate_enabled"))); print("zeek_capture_loss_max_percent="+str(d.get("zeek_capture_loss_max_percent"))); raise SystemExit(0 if d.get("read_only_export") is True and d.get("disk_read_gate_enabled") is False and d.get("zeek_capture_loss_available") is True else 1)'"'"''

echo
echo "== Mac Studio n8n =="
# n8n health and compose status prove the webhook endpoint can receive alerts.
curl -fsS --max-time 5 "$N8N_URL"
echo
ssh "$MAC_HOST" 'cd $HOME/n8n-local && /usr/local/bin/docker compose ps'
ssh "$MAC_HOST" 'curl -fsS http://127.0.0.1:8787/health | python3 -c '"'"'import json,sys; d=json.load(sys.stdin).get("disk_capacity") or {}; print("disk_used_percent="+str(d.get("used_percent"))); print("disk_start_limit="+str(d.get("start_max_used_percent"))); print("disk_hard_limit="+str(d.get("hard_max_used_percent"))); raise SystemExit(0 if float(d.get("start_max_used_percent") or 100) <= 75 and float(d.get("hard_max_used_percent") or 100) <= 80 else 1)'"'"''

echo
echo "== Mac Studio alert-store SQLite =="
# Confirms the alert-store DB is readable and the maintenance LaunchAgent exists.
# The live alert-store writes continuously. A read-only verification must wait
# through short writer/schema locks instead of reporting a healthy WAL DB as
# failed merely because the probe landed on a commit boundary.
ssh "$MAC_HOST" 'sqlite3 -readonly -cmd ".timeout 60000" "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "PRAGMA quick_check; SELECT COUNT(*) FROM alerts; SELECT COUNT(*) FROM alert_group_summary;"'
ssh "$MAC_HOST" 'launchctl print gui/$(id -u)/com.arron.soc.alert-store-maintenance | grep -E "state =|last exit code|run interval|path ="'

echo
echo "== Mac Studio PCAP broker and parser =="
# PCAP evidence is optional, but when enabled it should not degrade alert relay.
if [[ "$PCAP_TIMER_EXPECTED_STATE" == "active" ]]; then
  ssh "$MAC_HOST" 'curl -fsS "http://127.0.0.1:8765/api/system-health/beacons?hours=24" | python3 -c '"'"'import json,sys; data=json.load(sys.stdin); p=data.get("pcap",{}); counts=p.get("request_counts",{}); print("pcap_warning_count="+str(p.get("warning_count"))); print("pcap_pending="+str(counts.get("pending",0))); print("pcap_claimed="+str(counts.get("claimed",0))); print("pcap_fulfilled="+str(counts.get("fulfilled",0))); print("pcap_failed="+str(counts.get("failed",0))); print("pcap_no_packet_failures="+str(p.get("no_packet_failures"))); print("pcap_oversize_failures="+str(p.get("oversize_failures"))); raise SystemExit(0 if int(p.get("warning_count") or 0)==0 else 1)'"'"''
else
  # Pending work is expected while admission is intentionally closed. An active
  # claim would mean the safety hold is not actually containing transfer work.
  ssh "$MAC_HOST" 'curl -fsS "http://127.0.0.1:8765/api/system-health/beacons?hours=24" | python3 -c '"'"'import json,sys; data=json.load(sys.stdin); p=data.get("pcap",{}); counts=p.get("request_counts",{}); print("pcap_safety_hold=true"); print("pcap_warning_count="+str(p.get("warning_count"))); print("pcap_pending="+str(counts.get("pending",0))); print("pcap_claimed="+str(counts.get("claimed",0))); print("pcap_fulfilled="+str(counts.get("fulfilled",0))); print("pcap_failed="+str(counts.get("failed",0))); raise SystemExit(0 if int(counts.get("claimed") or 0)==0 else 1)'"'"''
fi
ssh "$MAC_HOST" 'launchctl print gui/$(id -u)/com.arron.soc.pcap-analysis | grep -E "state =|last exit code|run interval|path ="'
ssh "$MAC_HOST" 'launchctl print gui/$(id -u)/com.arron.soc.pcap-retention | grep -E "state =|last exit code|run interval|path ="'

echo
echo "== Pi relay recent logs =="
# Recent relay logs show counts for pulled/dropped/new/posted alerts.
ssh "$PI_HOST" 'sudo journalctl -u so-alert-poll.service -u so-pcap-broker.service -u so-storage-health.service -n 60 --no-pager'
