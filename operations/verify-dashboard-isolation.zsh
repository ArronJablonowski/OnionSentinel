#!/bin/zsh
set -euo pipefail

# Verify that Onion Sentinel and the Hermes LAN Portal have a one-way link-only
# relationship. Set MAC_HOST to include live Mac Studio checks.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

fail() {
  print -u2 "dashboard isolation failed: $*"
  exit 1
}

for file_path in \
  "$ROOT/n8n/bin/refresh-soc-dashboard.py" \
  "$ROOT/n8n/bin/run-alert-store-host.zsh" \
  "$ROOT/n8n/bin/maintain-alert-store-sqlite.zsh" \
  "$ROOT/onion-sentinel-dashboard/scripts/build_soc_alerts_dashboard.py" \
  "$ROOT/n8n/launchd/com.arron.onion-sentinel.web.plist"
do
  [[ -f "$file_path" ]] || fail "missing $file_path"
  if grep -Eq '(\.hermes|report_portal)' "$file_path"; then
    fail "active Onion Sentinel source references a Hermes-owned path: $file_path"
  fi
done

if grep -R -Eq 'com\.arron\.reportportal' "$ROOT/n8n/bin"; then
  fail "an Onion Sentinel runtime script controls the Hermes portal service"
fi

[[ ! -e "$ROOT/n8n/bin/sync-soc-alerts-portal.py" ]] || \
  fail "obsolete portal publisher remains in the repo"

grep -q 'com.arron.onion-sentinel.web' \
  "$ROOT/n8n/launchd/com.arron.onion-sentinel.web.plist" || \
  fail "dedicated web LaunchAgent label is missing"
grep -q '<string>8766</string>' \
  "$ROOT/n8n/launchd/com.arron.onion-sentinel.web.plist" || \
  fail "dedicated web LaunchAgent is not pinned to port 8766"

if [[ -n "${MAC_HOST:-}" ]]; then
  ssh -o BatchMode=yes -o ConnectTimeout=8 "$MAC_HOST" 'set -eu
    curl -fsS http://127.0.0.1:8766/healthz | python3 -c '"'"'import json,sys; d=json.load(sys.stdin); raise SystemExit(0 if d.get("ok") is True and d.get("service") == "onion-sentinel" else 1)'"'"'
    curl -fsS -o /dev/null http://127.0.0.1:8765/
    launchctl print "gui/$(id -u)/com.arron.onion-sentinel.web" | grep -q "state = running"
    launchctl print "gui/$(id -u)/com.arron.reportportal" | grep -q "state = running"
    test ! -e "$HOME/n8n-local/bin/sync-soc-alerts-portal.py"
    ! grep -Eq "(\\.hermes|report_portal)" \
      "$HOME/n8n-local/bin/refresh-soc-dashboard.py" \
      "$HOME/n8n-local/bin/run-alert-store-host.zsh" \
      "$HOME/n8n-local/onion-sentinel-dashboard/scripts/build_soc_alerts_dashboard.py"
    ! grep -Eq "(SOC Alerts Web|build_soc_alerts_dashboard|Cybersecurity.*/SOC Alerts)" \
      "$HOME/.hermes/scripts/sync_report_portal.py"
    grep -q "http://10.77.7.225:8766/" "$HOME/report_portal/report_portal.py"
    test "$(grep -Fc "http://10.77.7.225:8766/" "$HOME/report_portal/report_portal.py")" -eq 1
    ! grep -Eq "(n8n-local|SOC Alerts Web|alert_store_data|/api/soc-alerts|/api/system-health|/api/llm-analysis|/api/soc-settings)" \
      "$HOME/report_portal/report_portal.py"
    test ! -e "$HOME/.hermes/scripts/build_soc_alerts_dashboard.py"
    test ! -e "$HOME/report_portal/soc_alert_api.py"
    test ! -e "$HOME/report_portal/.soc_alert_status.json"
    test ! -e "$HOME/report_portal/library/Cybersecurity/SOC Alerts"
    while IFS= read -r hermes_script; do
      ! grep -Eq "(n8n-local|SOC Alerts Web|alert_store_data|build_soc_alerts_dashboard|/api/soc-alerts|com.arron.onion-sentinel)" "$hermes_script"
    done < <(find "$HOME/.hermes/scripts" -type f \( -name "*.py" -o -name "*.sh" -o -name "*.zsh" -o -name "*.plist" \) -print)
    test "$(curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:8765/api/soc-alerts)" = 404
    test "$(curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:8765/api/system-health/beacons)" = 404
  ' || fail "live Mac Studio boundary check failed"
fi

print "dashboard isolation verified"
