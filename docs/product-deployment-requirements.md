# Onion Sentinel Product And Deployment Requirements

This document records the operating contract for Onion Sentinel. Treat it as
the product and deployment bar for future changes.

## Product Bar

Onion Sentinel is a serious SOC analyst tool. The dashboard should feel like a
polished SaaS product for fast triage, repeated analyst workflows, and
high-volume alert review. Favor dense, scannable, reliable operational UI over
decorative dashboard filler.

## Source Of Truth

This repository is the disaster recovery and rapid redeployment source of
truth. The live Mac Studio deployment is operational runtime. Keep meaningful
live changes reflected in sanitized source, deployment scripts, node READMEs,
architecture docs, runbooks, and validation steps.

Do not copy these into Git:

- Secrets, tokens, credentials, cookies, or SSH private keys.
- SQLite databases, packet captures, event logs, generated reports, n8n runtime
  data, admin state, or live alert payloads.
- Local runtime-only paths that hardcode a specific user. Use `$HOME`,
  `Path.home()`, environment variables, placeholders, or installer-rendered
  templates.

## Dashboard Requirements

The default page is SOC Alerts. The table must stay SQLite/API backed so the
browser requests only the active result slice. Server-side filtering, sorting,
pagination, and shared analyst state are required for high-volume and
multi-analyst use.

SOC Alerts table requirements:

- Default rows per page is 25.
- Analysts can select rows per page.
- Pagination grows and shrinks with the result count.
- Useful column headers sort server-side across the matching set.
- Sorting defaults are `Newest Alerts First` and `Highest Severity First`.
- Last Seen filtering is server-side and uses newest grouped detection time.
- Count appears left of Severity and is centered.
- Log Source appears right of AI and has enough width to avoid ugly wrapping.
- Project timestamps use ISO 8601 style with `T` replaced by two spaces.

Analyst workflow requirements:

- Acknowledge hides a grouped detection from the default view.
- Acknowledged detections reappear when a new matching detection increases the
  count.
- Suppress hides current and future matching detections until exposed.
- Suppression requires a modal reason, max 140 characters.
- Suppressed buttons become `Expose`.
- Acknowledge, suppress, expose, and reason state must persist in SQLite.
- `Show acknowledged` and `Show suppressed` toggles control visibility.

Detail and duplicate-timeline requirements:

- Detailed Alert Reports must wrap inside the visible viewport with right-side
  padding.
- Raw Alert, Complete Alert JSON, and Complete AI Response JSON are collapsed by
  default near the bottom.
- AI Model Used must show provider, model, artifact path, and generated time
  when available.
- Duplicate Alert Timeline is expanded by default, compact, scrollable for many
  observations, and includes chronological timestamp, source IP, destination IP,
  and destination port.

## AI Analysis Requirements

Every unique grouped detection should be analyzed unless skipped for a clear,
documented reason. AI statuses should distinguish not queued, queued,
analyzing, analyzed, and skipped.

The scheduler priority order is:

1. Critical, newest first.
2. High, newest first.
3. Medium, newest first.
4. Low, newest first.
5. Informational, newest first.

Every scheduler loop must re-check this priority before selecting the next
alert. New critical/high alerts should preempt lower severity backlog at the
next scheduling decision.

The AI analysis should consider duplicate count, first seen, last seen, all
timeline observations, isolated/bursty/recurring/escalating behavior, evidence
gaps, false-positive possibilities, investigation steps, tuning/suppression
recommendations, and whether hosted/cloud second opinion is justified.

Runtime prompt path:

```text
$HOME/n8n-local/config/soc_analyst_system_prompt.md
```

Repo template:

```text
n8n/config/soc_analyst_system_prompt.md
```

## Model Settings Requirements

The Settings page should expose a collapsed-by-default `AI Analysis Model
Selection` panel. Order the controls as Analysis Mode, Ollama settings, then
Cloud/Frontier provider settings.

Ollama model selection should be a dropdown refreshed from `ollama ls`. Cloud
or frontier integrations must keep API keys and credentials in runtime-local
configuration only.

## Runtime Architecture

Keep the Raspberry Pi relay dumb and reliable: restricted SSH pull, exact
alert-id retry dedupe, local evidence/state files, health notifications, and
webhook transport. Filtering, scoring, suppression, routing, notification
decisions, and dashboard state belong in n8n, alert-store, and SQLite.
Webhook transport must retry transient downstream errors with bounded backoff
and preserve partial-batch progress by marking each alert delivered only after
that alert receives a successful webhook response.

The alert-store SQLite database must be treated as an operational source of
truth. Runtime must include recurring `PRAGMA quick_check` validation,
verified SQLite backups, recoverable corruption artifacts, and documented
manual recovery. Alert-store should tolerate short write-contention windows
with an explicit SQLite busy timeout and conservative, runtime-validated
journal settings.

Security Onion access must remain restricted through a forced-command SSH key,
no forwarding/no pty restrictions, and sudoers limited to the alert export
wrapper. Full-fidelity export should retain packet, payload, PCAP, HTTP body,
and raw event fields when Security Onion provides them.

SOC Analyst packet-capture needs must go through a brokered request path, not
direct AI access to Security Onion. Alert-store may queue bounded PCAP requests
in SQLite, but fulfillment must be performed by the relay/Security Onion
forced-command path with strict validation, small time windows, output size
limits, audit metadata, and runtime-only artifact storage.

## Notification Requirements

High and critical alerts should go to Telegram. Notifications should dedupe and
group to avoid repeated spam. Relay and stack monitor failure/recovery messages
should be meaningful and transition-based.

If Telegram stops firing for new detections, inspect alert-store notification
logic, cooldown windows, suppression state, Telegram runtime environment,
n8n webhook path, alert-store logs, and the SQLite `notification_log` table.

## Validation

Before commit and push, run:

```bash
./operations/secret-scan.zsh
git diff --check
zsh -n n8n/bin/*.zsh operations/*.zsh
bash -n relay/bin/*.sh security-onion/bin/*.sh security-onion/bin/export-recent-alerts
python3 -m py_compile $(find n8n/bin relay/app onion-sentinel-dashboard -name '*.py' -type f)
for file in $(find n8n/alert_store -name '*.js' -type f); do node --check "$file"; done
```

Run `pytest` when available. If it is unavailable, state that explicitly.

Live Mac Studio validation examples:

```bash
ssh <mac_user>@10.77.7.225 'cd "$HOME/n8n-local" && /usr/local/bin/docker compose ps'
ssh <mac_user>@10.77.7.225 'curl -fsS http://127.0.0.1:5678/healthz'
ssh <mac_user>@10.77.7.225 'python3 "$HOME/.hermes/scripts/build_soc_alerts_dashboard.py"'
ssh <mac_user>@10.77.7.225 'python3 "$HOME/.hermes/scripts/sync_report_portal.py"'
```

Relay validation examples:

```bash
ssh <relay_user>@10.88.8.8 'systemctl is-enabled so-alert-relay.timer; systemctl is-active so-alert-relay.timer'
ssh <relay_user>@10.88.8.8 'sudo journalctl -u so-alert-relay.service -n 40 --no-pager'
```
