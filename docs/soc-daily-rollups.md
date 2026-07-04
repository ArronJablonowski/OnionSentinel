# SOC Daily Rollups

Date added: 2026-07-02

Purpose:

```text
Create a compact daily Markdown memory file for the local AI analyst and for
human SOC review.
```

The daily rollup reads alert-store SQLite directly and writes an
Obsidian-friendly Markdown file into the same SOC Alerts corpus used by the LAN
Portal and local LLM.

## Live Paths

Mac Studio script:

```text
$HOME/n8n-local/bin/write-daily-soc-rollup.py
```

DR repo copy:

```text
n8n/bin/write-daily-soc-rollup.py
```

LaunchAgent:

```text
$HOME/Library/LaunchAgents/com.arron.soc.daily-rollup.plist
```

DR repo LaunchAgent copy:

```text
n8n/launchd/com.arron.soc.daily-rollup.plist
```

Output directory:

```text
$HOME/n8n-local/soc-alerts/daily-rollups
```

Visible through the user-facing symlink:

```text
$HOME/Documents/SOC Alerts/daily-rollups
```

Current example:

```text
$HOME/n8n-local/soc-alerts/daily-rollups/2026-07-02-soc-daily-rollup.md
```

## Schedule

The LaunchAgent runs daily at:

```text
23:55 Mac Studio local time
```

It runs:

```bash
/usr/bin/python3 $HOME/n8n-local/bin/write-daily-soc-rollup.py --hours 24 --limit 30
```

LaunchAgent logs:

```text
$HOME/n8n-local/logs/daily-rollup.out.log
$HOME/n8n-local/logs/daily-rollup.err.log
```

## What The Rollup Contains

Each rollup includes:

- Executive summary.
- Raw row count and total seen count.
- Critical/high urgent row count.
- Accepted, suppressed, and duplicate counts.
- Filter status by triage level.
- Top grouped detections using the same Count semantics as the dashboard.
- Urgent alert queue.
- Suppression activity.
- New source/destination pairs.
- Telegram notification summary.
- Analyst follow-up checklist.
- Local AI context notes.

## Count Semantics

The daily rollup mirrors the dashboard grouping model:

```text
Count = max(total seen events, raw grouped rows)
```

The grouping key is:

```text
COALESCE(
  suppression_key,
  triage_level | rule_name | source_ip | destination_ip | filter_status
)
```

Source port is intentionally excluded because it is usually ephemeral.

## Test Alerts

Validation/test alerts are excluded by default. Excluded prefixes:

```text
phase%
config-%
internal-test-%
sqlite-%
policy-%
codex-e2e-%
```

To include test alerts during troubleshooting:

```bash
$HOME/n8n-local/bin/write-daily-soc-rollup.py --hours 24 --limit 30 --include-tests
```

## Manual Run

Run manually on Mac Studio:

```bash
ssh <mac_user>@10.77.7.225 \
  '$HOME/n8n-local/bin/write-daily-soc-rollup.py --hours 24 --limit 30'
```

Check the output:

```bash
ssh <mac_user>@10.77.7.225 \
  'ls -lh $HOME/n8n-local/soc-alerts/daily-rollups &&
   sed -n "1,80p" $HOME/n8n-local/soc-alerts/daily-rollups/$(date +%F)-soc-daily-rollup.md'
```

## LaunchAgent Operations

Check loaded state:

```bash
ssh <mac_user>@10.77.7.225 \
  'launchctl print gui/$(id -u)/com.arron.soc.daily-rollup'
```

Reload after changing the plist:

```bash
ssh <mac_user>@10.77.7.225 '
launchctl bootout gui/$(id -u) "$HOME/Library/LaunchAgents/com.arron.soc.daily-rollup.plist" 2>/dev/null || true
launchctl bootstrap gui/$(id -u) "$HOME/Library/LaunchAgents/com.arron.soc.daily-rollup.plist"
'
```

Run immediately through launchd:

```bash
ssh <mac_user>@10.77.7.225 \
  'launchctl kickstart -k gui/$(id -u)/com.arron.soc.daily-rollup'
```

## Validation

Initial deployment validation on 2026-07-02:

```text
script compiled: yes
LaunchAgent plist lint: OK
LaunchAgent loaded: yes
LaunchAgent kickstart run: exit 0
manual rollup generated: yes
output file: 2026-07-02-soc-daily-rollup.md
```

The first generated rollup reported:

```text
raw alert rows: <count>
total seen events: 814
urgent rows: 100
suppressed rows: 87
```

These values are expected to change as new alerts arrive.
