#!/bin/zsh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== high-confidence secret scan =="

if find . \
  -path './.git' -prune -o \
  -path './.venv' -prune -o \
  -path '*/node_modules' -prune -o \
  -path '*/__pycache__' -prune -o \
  -path '*/.pytest_cache' -prune -o \
  -path '*/.playwright-artifacts' -prune -o \
  -path '*/playwright-report' -prune -o \
  -path '*/test-results' -prune -o \
  -path './n8n_data' -prune -o \
  -path './alert_store_data' -prune -o \
  -path './soc-alerts' -prune -o \
  -path './operations/secret-scan.zsh' -prune -o \
  -type f \
  \( -name '*.png' -o -name '*.jpg' -o -name '*.jpeg' -o -name '*.gif' -o -name '*.ico' \) -prune -o \
  -type f -print | xargs rg -n --hidden -i \
    '(BEGIN OPENSSH PRIVATE KEY|BEGIN RSA PRIVATE KEY|BEGIN EC PRIVATE KEY|xox[baprs]-[A-Za-z0-9-]{20,}|gh[pousr]_[A-Za-z0-9_]{30,}|[0-9]{8,12}:AA[A-Za-z0-9_-]{30,})' ; then
  echo
  echo "High-confidence secret-like content found. Review before committing." >&2
  exit 1
fi

echo "No high-confidence secret patterns found."

echo "== forbidden runtime file scan =="
if find . \
  -path './.git' -prune -o \
  -path './.venv' -prune -o \
  -path '*/node_modules' -prune -o \
  -path '*/__pycache__' -prune -o \
  -path '*/.pytest_cache' -prune -o \
  -path '*/.playwright-artifacts' -prune -o \
  -path '*/playwright-report' -prune -o \
  -path '*/test-results' -prune -o \
  \( -name '.env' -o -name '*.sqlite' -o -name '*.sqlite3' -o -name '*.db' -o -name 'id_*' -o -name '*.pem' -o -name '*.key' \) \
  -type f -print | rg . ; then
  echo
  echo "Forbidden runtime or credential file found. Remove it or add a safe example suffix." >&2
  exit 1
fi

echo "No forbidden runtime credential/data files found."
