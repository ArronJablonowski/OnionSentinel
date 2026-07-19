#!/usr/bin/env python3
"""Send one bounded Telegram notification using runtime-only .env credentials."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import sys
import time
import urllib.error
import urllib.request


ALLOWED_KEYS = {"TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"}


def read_credentials(env_path: Path) -> tuple[str, str]:
    """Parse only Telegram fields as inert data; never source the environment file."""

    values: dict[str, str] = {}
    for raw in env_path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key not in ALLOWED_KEYS:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key] = value
    return values.get("TELEGRAM_BOT_TOKEN", ""), values.get("TELEGRAM_CHAT_ID", "")


def send_message(
    bot_token: str,
    chat_id: str,
    message: str,
    *,
    attempts: int = 3,
    timeout: float = 10,
) -> tuple[bool, str]:
    payload = json.dumps(
        {"chat_id": chat_id, "text": message, "disable_web_page_preview": True}
    ).encode("utf-8")
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{bot_token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    last_failure = "network_error"
    for attempt in range(max(1, attempts)):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return True, f"http_{response.status}"
        except urllib.error.HTTPError as exc:
            last_failure = f"http_{exc.code}"
            if 400 <= exc.code < 500 and exc.code != 429:
                break
        except (urllib.error.URLError, TimeoutError, socket.timeout):
            last_failure = "network_timeout"
        if attempt + 1 < attempts:
            time.sleep(attempt + 1)
    return False, last_failure


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--message", required=True)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()
    try:
        bot_token, chat_id = read_credentials(args.env_file)
    except OSError:
        print("telegram_send_failed=env_unavailable", file=sys.stderr)
        return 1
    if not bot_token or not chat_id:
        print("telegram_send_failed=credentials_missing", file=sys.stderr)
        return 1
    ok, detail = send_message(
        bot_token,
        chat_id,
        args.message,
        attempts=args.attempts,
        timeout=args.timeout,
    )
    stream = sys.stdout if ok else sys.stderr
    print(f"telegram_send_{'ok' if ok else 'failed'}={detail}", file=stream)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
