#!/usr/bin/env python3
"""Enforce physical source-line limits, including tests, comments and blanks."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
            ".sh", ".zsh", ".bash", ".css", ".html", ".sql"}


def repository_files(root: Path) -> list[Path]:
    """Include new source files before staging, but never ignored runtime data."""
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others",
         "--exclude-standard", "-z"], check=True, capture_output=True,
    )
    return sorted({root / value.decode() for value in result.stdout.split(b"\0") if value})


def is_code(path: Path) -> bool:
    if path.suffix.lower() in SUFFIXES:
        return True
    if path.suffix or not path.is_file():
        return False
    with path.open("rb") as handle:
        return handle.read(2) == b"#!"


def validated_policy(policy: dict) -> tuple[int, dict]:
    if policy.get("schema") != "onion-sentinel-code-size-v1":
        raise ValueError("unsupported source-size policy")
    maximum = policy.get("maximum_lines")
    if type(maximum) is not int or not 0 < maximum <= 1000:
        raise ValueError("source-size ceiling must be between 1 and 1000")
    exceptions = policy.get("frozen_exceptions", {})
    if not isinstance(exceptions, dict):
        raise ValueError("frozen exceptions must be an object")
    return maximum, exceptions


def frozen_identity_valid(exception: object, data: bytes) -> bool:
    return (isinstance(exception, dict) and bool(exception.get("reason"))
            and exception.get("sha256") == hashlib.sha256(data).hexdigest())


def check(root: Path, policy: dict) -> dict:
    """Frozen exceptions are exact byte identities, not growing file allowances."""
    maximum, exceptions = validated_policy(policy)
    violations, frozen, measured = [], [], []
    for path in repository_files(root):
        if not path.exists() or not is_code(path):
            continue
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            violations.append({"path": name, "reason": "source symlink is not allowed"})
            continue
        data = path.read_bytes()
        lines = len(data.decode("utf-8").splitlines())
        record = {"path": name, "lines": lines}
        measured.append(record)
        exception = exceptions.get(name)
        if exception is not None:
            if not frozen_identity_valid(exception, data):
                violations.append({**record, "reason": "frozen exception identity changed"})
            else:
                frozen.append({**record, "reason": exception["reason"]})
        elif lines > maximum:
            violations.append({**record, "reason": "source exceeds physical line ceiling"})
    for name in exceptions:
        if name not in {item["path"] for item in measured}:
            violations.append({"path": name, "reason": "frozen exception is unavailable"})
    current = [item for item in measured if item["path"] not in exceptions]
    return {"ok": not violations, "maximum_lines": maximum,
            "source_files": len(measured), "violations": violations,
            "frozen_exceptions": frozen,
            "largest_maintained_file": max(current, key=lambda item: item["lines"], default=None)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--policy", type=Path)
    args = parser.parse_args()
    policy_path = args.policy or args.root / "operations/quality/code-size-policy.json"
    try:
        report = check(args.root.resolve(), json.loads(policy_path.read_text()))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
