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

SECRET_PATTERN='(BEGIN OPENSSH PRIVATE KEY|BEGIN RSA PRIVATE KEY|BEGIN EC PRIVATE KEY|xox[baprs]-[A-Za-z0-9-]{20,}|gh[pousr]_[A-Za-z0-9_]{30,}|[0-9]{8,12}:AA[A-Za-z0-9_-]{30,})'

set +e
"$RG_BIN" -l --hidden -i \
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
  "$SECRET_PATTERN" .
tree_scan_status=$?
local_config_scan_status=1
if [[ -f ./.codex/config.toml && ! -L ./.codex/config.toml ]] \
    && git check-ignore -q -- ./.codex/config.toml; then
  "$RG_BIN" -l -i "$SECRET_PATTERN" -- ./.codex/config.toml
  local_config_scan_status=$?
fi
set -e
if (( tree_scan_status == 0 || local_config_scan_status == 0 )); then
  echo
  echo "High-confidence secret-like content found. Review before committing." >&2
  exit 1
fi
if (( tree_scan_status != 1 )); then
  echo "High-confidence repository scan failed with status ${tree_scan_status}." >&2
  exit 2
fi
if (( local_config_scan_status != 1 )); then
  echo "High-confidence local-config scan failed with status ${local_config_scan_status}." >&2
  exit 2
fi

echo "No high-confidence secret patterns found."

echo "== forbidden runtime file scan =="

approved_local_codex_config() {
  local candidate="$1"
  local mode=""
  [[ "$candidate" == "./.codex/config.toml" ]] || return 1
  [[ -f "$candidate" && ! -L "$candidate" ]] || return 1
  if git ls-files --error-unmatch -- "$candidate" >/dev/null 2>&1; then
    return 1
  fi
  git check-ignore -q -- "$candidate" || return 1
  mode="$(stat -f '%Lp' "$candidate" 2>/dev/null || stat -c '%a' "$candidate" 2>/dev/null || true)"
  [[ "$mode" == "600" ]]
}

typeset -a forbidden_files
forbidden_files=()
while IFS= read -r -d '' candidate; do
  if approved_local_codex_config "$candidate"; then
    continue
  fi
  forbidden_files+=("$candidate")
done < <(find . \
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
  \( -type f -o -type l \) -print0)
if (( ${#forbidden_files[@]} )); then
  print -rl -- "${forbidden_files[@]}"
  echo
  echo "Forbidden runtime or credential file found. Remove it or add a safe example suffix." >&2
  exit 1
fi

echo "No forbidden runtime credential/data files found."
