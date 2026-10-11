#!/bin/zsh
set -euo pipefail

# Source-only checks: no runtime, database, SSH, or deployment operations.
SOURCE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 "$SOURCE_ROOT/operations/check-code-size.py" --root "$SOURCE_ROOT"
python3 "$SOURCE_ROOT/operations/check-module-quality.py" --root "$SOURCE_ROOT"
