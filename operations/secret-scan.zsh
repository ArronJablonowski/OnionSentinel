#!/bin/zsh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RG_BIN="$(command -v rg 2>/dev/null || true)"
if [[ -z "$RG_BIN" ]]; then
  for candidate in /opt/homebrew/bin/rg /usr/local/bin/rg; do
    if [[ -x "$candidate" ]]; then
      RG_BIN="$candidate"
      break
    fi
  done
fi
if [[ -z "$RG_BIN" || ! -x "$RG_BIN" ]]; then
  echo "Secret scan cannot run: ripgrep (rg) was not found." >&2
  exit 2
fi

echo "== high-confidence secret scan =="

set +e
"$RG_BIN" -n --hidden -i \
  --glob '!.git/**' \
  --glob '!.venv/**' \
  --glob '!**/node_modules/**' \
  --glob '!**/__pycache__/**' \
  --glob '!**/.pytest_cache/**' \
  --glob '!**/.playwright-artifacts/**' \
  --glob '!**/playwright-report/**' \
  --glob '!**/test-results/**' \
  --glob '!n8n_data/**' \
  --glob '!alert_store_data/**' \
  --glob '!soc-alerts/**' \
  --glob '!operations/secret-scan.zsh' \
  --glob '!*.png' --glob '!*.jpg' --glob '!*.jpeg' \
  --glob '!*.gif' --glob '!*.ico' \
  '(BEGIN OPENSSH PRIVATE KEY|BEGIN RSA PRIVATE KEY|BEGIN EC PRIVATE KEY|xox[baprs]-[A-Za-z0-9-]{20,}|gh[pousr]_[A-Za-z0-9_]{30,}|[0-9]{8,12}:AA[A-Za-z0-9_-]{30,})' .
scan_status=$?
set -e
if (( scan_status == 0 )); then
  echo
  echo "High-confidence secret-like content found. Review before committing." >&2
  exit 1
fi
if (( scan_status != 1 )); then
  echo "High-confidence secret scan failed with status ${scan_status}." >&2
  exit 2
fi

echo "No high-confidence secret patterns found."

echo "== forbidden runtime file scan =="
forbidden_files="$(find . \
  -path './.git' -prune -o \
  -path './.venv' -prune -o \
  -path '*/node_modules' -prune -o \
  -path '*/__pycache__' -prune -o \
  -path '*/.pytest_cache' -prune -o \
  -path '*/.playwright-artifacts' -prune -o \
  -path '*/playwright-report' -prune -o \
  -path '*/test-results' -prune -o \
  \( -path '*/.hermes/*' -o -path '*/.openclaw/*' -o -path '*/.codex/*' \
     -o -name '.env' -o -name 'auth.json' -o -name 'auth-profiles.json' \
     -o -name 'credentials.json' -o -name '*.token' \
     -o -name '*.sqlite' -o -name '*.sqlite3' -o -name '*.db' \
     -o -name 'id_*' -o -name '*.pem' -o -name '*.key' \) \
  -type f -print)"
if [[ -n "$forbidden_files" ]]; then
  print -r -- "$forbidden_files"
  echo
  echo "Forbidden runtime or credential file found. Remove it or add a safe example suffix." >&2
  exit 1
fi

echo "No forbidden runtime credential/data files found."
