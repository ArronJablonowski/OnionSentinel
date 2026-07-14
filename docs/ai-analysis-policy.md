# AI Analysis Policy

Date added: 2026-07-02

Purpose:

```text
Use local AI by default for Security Onion alert analysis, while keeping a
controlled hosted/frontier-model escalation path for selected high-value cases.
```

## Recommendation

Use a hybrid model:

```text
medium alerts: local LLM only
high alerts: local LLM first, hosted second opinion allowed
critical alerts: local LLM first, hosted second opinion allowed
low alerts: no per-alert AI by default; summarize in daily rollups
suppressed duplicates: no per-alert AI; summarize in daily rollups
```

The default model path should be local:

```text
Hermes local agents, Ollama, or another local LLM runtime
```

The hosted model path should be an escalation analyst, not the default
processor.

Hermes Agent, OpenClaw, and a thin Onion Sentinel Investigation Runtime are
future adapter options, not current production dependencies. Their trust
boundaries, phased evaluation, typed-tool policy, and acceptance gates are
defined in `llm-harness-and-investigation-runtime-roadmap.md`. Direct Ollama
remains the production baseline and rollback path until those gates pass.

## Why Local First

Local AI should handle routine SOC work because it keeps the following data on
the LAN:

- Internal IP addresses.
- Network topology hints.
- Alert history.
- Tuning notes.
- Suppression patterns.
- Daily rollups.
- Investigation notes.

Local AI is also better for high-volume repetitive work because it avoids API
cost, rate limits, and unnecessary data movement.

## When Hosted Analysis Is Allowed

Hosted/frontier model analysis may be used when:

- The alert is critical.
- The alert is high.
- The local model explicitly requests a second opinion.
- The analyst manually requests escalation.
- The alert pattern is unfamiliar and could affect important infrastructure.

Hosted analysis should receive only the curated prompt package, not raw packet
payloads, credentials, secrets, or broad filesystem access.

## Current Prompt Builder

Live Mac Studio path:

```text
$HOME/n8n-local/bin/build-ai-investigation-prompt.py
```

DR repo copy:

```text
n8n/bin/build-ai-investigation-prompt.py
```

Prompt package output:

```text
$HOME/n8n-local/soc-alerts/ai-prompts
```

Parsed PCAP evidence output:

```text
$HOME/n8n-local/soc-alerts/pcap-analysis
```

Manual run:

```bash
ssh <mac_user>@10.77.7.225 \
  '$HOME/n8n-local/bin/build-ai-investigation-prompt.py --levels critical,high,medium --hours 24 --related-limit 8'
```

The script does not call an LLM. It creates a bounded JSON evidence package
that can be passed to Hermes, Ollama, or a hosted model.

If matching PCAP analysis artifacts exist, the prompt package includes a compact
`pcap_evidence` block. The PCAP parser runs on the Mac Studio with Zeek and
TShark, never inside the LLM runner. Zeek is treated as the primary structured
source for conversations, DNS, TLS, HTTP, notices, and weird logs. TShark is
used as corroborating packet-level context for protocol hierarchy, conversations,
and bounded packet-field samples.

When a parsed PCAP evidence artifact is newer than the matching local AI
analysis artifact, the scheduled AI runner treats that analysis as stale. The
alert group becomes eligible for another local Ollama run so the Detailed Alert
Report can include packet-informed findings. Negative broker states, such as
`No Packets`, are shown in the dashboard but do not by themselves force
reanalysis because there is no parsed packet summary to reason over.

## Prompt Package Inputs

The prompt package includes:

As of 2026-07-02, prompt packages also include `grouped_alert_context` with the dashboard duplicate-group key, raw alert row count, total observations, first seen, last seen, and a bounded timeline sample. The local model must use this frequency context when deciding urgency, analyst next actions, and tuning recommendations.

- Selected alert from alert-store SQLite.
- Deterministic triage score, level, routing, and reasons.
- Curated raw alert subset.
- Compact public enrichment evidence from `enrichment_json`, including source,
  indicator, type, verdict, confidence, tags, first/last seen, cache time,
  skipped sources, and provider errors. Raw provider API responses are not
  included in prompt packages.
- Related alerts from SQLite.
- Recent Telegram notification context.
- Latest daily SOC rollup excerpt.
- Parsed PCAP evidence summaries when available.
- Local-first/hosted-escalation policy.
- Strict JSON response schema.

## Response Contract

The model must return valid JSON with these fields:

```json
{
  "detection_outcome": "true_positive_malicious|true_positive_suspicious|true_positive_authorized_benign|false_positive_logic_rule|false_positive_data_parser|false_positive_bad_intel_ioc|duplicate|informational_no_action|inconclusive",
  "bluf": "Bottom-line sentence that starts with the classification and briefly states why.",
  "summary": "string",
  "likely_meaning": "string",
  "severity_reasoning": "string",
  "alert_frequency_assessment": "string",
  "public_enrichment_findings": ["string"],
  "pcap_analysis_findings": ["string"],
  "false_positive_possibilities": ["string"],
  "recommended_next_steps": ["string"],
  "evidence_used": ["string"],
  "evidence_gaps": ["string"],
  "confidence": "low|medium|high",
  "escalation_needed": true,
  "hosted_second_opinion_recommended": false,
  "tuning_recommendation": "none|suppress|drop|raise_score|lower_score|needs_more_data",
  "tuning_reason": "string",
  "recommended_tuning_actions": ["string"]
}
```

The BLUF fields use SOC detection outcome taxonomy:

- `true_positive_malicious`: detection correctly identified actual attacker,
  malware, or unauthorized activity.
- `true_positive_suspicious`: detection correctly identified real concerning
  behavior that needs action, but maliciousness is not fully proven.
- `true_positive_authorized_benign`: detection correctly identified real
  behavior that appears approved, expected, or business/lab justified.
- `false_positive_logic_rule`, `false_positive_data_parser`, or
  `false_positive_bad_intel_ioc`: detection fired incorrectly because the
  activity did not match the intended behavior, data/parser quality was wrong,
  or threat intelligence was bad/noisy.
- `duplicate`, `informational_no_action`, or `inconclusive`: repeated,
  low-action, or insufficient-evidence outcomes.

## Guardrails

The model instructions are:

```text
Use only the provided evidence.
Do not invent packet contents, hostnames, users, process names, files, commands, or malware family names.
If evidence is missing, say what is missing.
Separate facts from hypotheses.
Return valid JSON only using the response_schema.
```

## Initial Validation

Initial validation generated a prompt package for a real critical alert:

```text
alert: <example scan rule>
level: critical
score: 100
related alerts included: 8
recent notifications included: 2
daily rollup included: yes
hosted second opinion allowed: yes
```

## Local Analysis Runner

Implemented runner:

```text
$HOME/n8n-local/bin/run-local-ai-analysis.py
```

DR repo copy:

```text
n8n/bin/run-local-ai-analysis.py
```

Default local model:

```text
devstral:latest via local Ollama at http://127.0.0.1:11434
```

Editable AI model routing:

```text
$HOME/n8n-local/config/ai_model_settings.json
```

The Settings page can choose:

- `ollama`: local Ollama only.
- `cloud`: a configured frontier/cloud CLI only. The CLI must read the bounded
  prompt package JSON from stdin and return one valid analysis JSON object on
  stdout.
- `hybrid`: local-first analysis. Ollama runs first; the cloud CLI is called
  only for Critical/High alerts or when the local model recommends a hosted
  second opinion, unless the hybrid policy is changed to cloud-on-recommendation
  only.

The Settings page orders these controls as Analysis Mode, Ollama Settings, then
Cloud Provider Settings. The Ollama model selector is a dropdown populated from
`ollama ls` through `/api/soc-settings/ollama-models`; if the saved model is not
currently returned by Ollama, the UI preserves it as the selected configured
value so an offline model is not silently replaced.

Editable SOC Analyst system prompt:

```text
$HOME/n8n-local/config/soc_analyst_system_prompt.md
```

Editable SIEM Engineer system prompt:

```text
$HOME/n8n-local/config/siem_engineer_system_prompt.md
```

Editable Threat Hunter system prompt:

```text
$HOME/n8n-local/config/threat_hunter_system_prompt.md
```

Editable Cyber Threat Intel Analyst system prompt:

```text
$HOME/n8n-local/config/cyber_threat_intel_system_prompt.md
```

Editable Incident Responder system prompt:

```text
$HOME/n8n-local/config/incident_responder_system_prompt.md
```

The SOC Alerts Settings page exposes model routing controls in a collapsed
`AI Analysis Model Selection` panel plus collapsed editable prompt sections for
the SOC Analyst, Incident Responder, SIEM Engineer, Cyber Threat Intel Analyst,
and Threat Hunter roles under `Cyber Security Agents`:

```text
http://10.77.7.225:8765/view/b68c5a48b9778061/settings.html
```

Save behavior:

- The web UI calls `/api/soc-settings/ai-model` for model routing.
- The web UI calls `/api/soc-settings/analyst-prompt` for the SOC Analyst system prompt.
- The web UI calls `/api/soc-settings/incident-responder-prompt` for the Incident Responder system prompt.
- The web UI calls `/api/soc-settings/siem-engineer-prompt` for the SIEM Engineer system prompt.
- The web UI calls `/api/soc-settings/cyber-threat-intel-prompt` for the Cyber Threat Intel Analyst system prompt.
- The web UI calls `/api/soc-settings/threat-hunter-prompt` for the Threat Hunter system prompt.
- Saving requires a LAN Portal Administration session.
- The portal writes settings files atomically and rejects empty prompts or prompts larger than 20 KB.
- The next AI analysis run uses the saved model routing and prompt automatically because `run-local-ai-analysis.py` reads both files immediately before each model request.
- `build-ai-investigation-prompt.py` also includes the same prompt in each prompt package so analyst-visible prompt artifacts match the actual system message.

The SIEM Engineer prompt is reserved for a periodic engineering review every
6 hours. That review must run only when all eligible alerts/detections have
finished analysis, and it should recommend current-rule tuning and new
detection creation separately.

The Threat Hunter prompt is reserved for senior hunt recommendations. It should
produce Security Onion, Elastic/Kibana KQL, OQL Security Union Hunt, and OSQuery
examples only when the supplied alert evidence supports those pivots.

The Cyber Threat Intel Analyst prompt is reserved for concise intelligence
briefs, indicator review, enrichment pivot recommendations, confidence scoring,
watchlist ideas, and cross-agent context. It must not invent attribution,
geolocation, malware names, reputation, or enrichment results that were not
supplied.

The Incident Responder prompt is reserved for senior response planning and case
execution guidance. It may recommend external tooling such as custom host
artifact collection scripts, but direct execution is a TODO until a dedicated
incident response host is connected, authenticated, logged, and approved.

The Settings page shows collapsed trigger summaries for each Cyber Security
Agent so operators can distinguish live triggers from planned/manual workflows:
SOC Analyst runs from new eligible alerts through the scheduled AI worker,
Incident Responder is manual until the IR host integration exists, SIEM Engineer
is planned for a 6 hour cron review after analysis backlog clears, Cyber Threat
Intel is manual until scheduled intelligence briefs are built, and Threat Hunter
is manual until automated hunts are built.

SOC Alerts table rows also provide a manual `Analyze` action. The action posts
only the dashboard group id to the Mac Studio portal, which resolves the newest
matching alert in SQLite and creates a fresh SOC Analyst prompt package locally.
The prompt package uses the same bounded evidence model as scheduled analysis:
all grouped alert observations, public enrichment, parsed PCAP evidence when
available, prior reports/comments, notification context, and agent memory. A
newer prompt package intentionally makes the previous JSON analysis stale, so
the next scheduled AI worker run reanalyzes that grouped detection even when it
was already analyzed before.

Cyber Security Agent Markdown memory files:

```text
$HOME/n8n-local/soc-alerts/agent-memory/soc-analyst-memory.md
$HOME/n8n-local/soc-alerts/agent-memory/incident-responder-memory.md
$HOME/n8n-local/soc-alerts/agent-memory/siem-engineer-memory.md
$HOME/n8n-local/soc-alerts/agent-memory/cyber-threat-intel-memory.md
$HOME/n8n-local/soc-alerts/agent-memory/threat-hunter-memory.md
$HOME/n8n-local/soc-alerts/agent-memory/shared-agent-memory.md
```

The Settings page shows each role memory path plus the shared memory path in
the collapsed agent row. These files are durable Markdown storage for previous
findings, known patterns, learned information, and future agent workflow writes.
SOC Analyst prompt packages include both the SOC Analyst role memory and shared
memory as bounded model evidence. Current automation does not yet append agent
findings to these files automatically.

Manual run using the newest prompt package:

```bash
ssh <mac_user>@10.77.7.225 \
  '$HOME/n8n-local/bin/run-local-ai-analysis.py --model devstral:latest --timeout 240'
```

Manual run that generates a fresh prompt package first:

```bash
ssh <mac_user>@10.77.7.225 \
  '$HOME/n8n-local/bin/run-local-ai-analysis.py --generate-prompt --levels critical,high,medium --hours 24 --related-limit 8 --model devstral:latest --timeout 240'
```

Output:

```text
$HOME/n8n-local/soc-alerts/ai-analysis/*-local-ai-analysis.md
$HOME/n8n-local/soc-alerts/ai-analysis/*-local-ai-analysis.json
$HOME/n8n-local/soc-alerts/llm-analysis-logs/llm-analysis-log.jsonl
$HOME/n8n-local/soc-alerts/llm-analysis-logs/current-analysis.json
```

The runner validates required response keys before writing output. It can also
accept a saved response via `--response-json`, which is useful for Hermes/manual
testing without calling Ollama.

Each run also appends one operational audit row to `llm-analysis-log.jsonl` and
updates `current-analysis.json`. The log records the alert/group being analyzed,
model route and model name, start and finish timestamps, runtime in seconds,
number of grouped alert rows/observations, success or failure, output artifact
paths, maximum GPU temperature, maximum GPU utilization percentage, maximum CPU
temperature, maximum SoC package temperature, maximum system memory percentage,
maximum total power draw in watts, and maximum CPU usage percentage seen during
the run. On the Mac Studio, the runner samples these values with
`mactop --headless --format json --count 1`; it looks in Homebrew paths first so
launchd jobs do not depend on an interactive shell `PATH`. If `mactop` or a
metric is unavailable, the log stores `null` plus a short reason instead of
inventing a value.

Validated 2026-07-02:

```text
prompt JSON -> devstral:latest local Ollama -> validated JSON response -> Markdown AI analysis note
alert: <example scan rule>
output directory: $HOME/n8n-local/soc-alerts/ai-analysis
```

## Automatic Trigger

Implemented scheduler:

```text
$HOME/n8n-local/bin/auto-run-ai-analysis.py
```

DR repo copy:

```text
n8n/bin/auto-run-ai-analysis.py
```

LaunchAgent:

```text
$HOME/Library/LaunchAgents/com.arron.soc.ai-analysis.plist
```

Schedule:

```text
StartInterval: 300 seconds
RunAtLoad: false
```

Default behavior:

- Analyze eligible unique alert groups continuously until the queue is empty.
- `--max-per-run 0` means unlimited queue drain. Any positive value can be used
  as a temporary maintenance cap.
- The 5-minute LaunchAgent interval is a safety wakeup for new alerts or missed
  runs; it should not create a pause while queued alerts remain.
- Queue priority is explicit severity-rank drain order: all eligible `critical`
  grouped detections must be analyzed before any `high` group, all `high`
  groups before any `medium`, all `medium` groups before any `low`, and all
  `low` groups before any `informational`. Inside each severity bucket, the
  scheduler analyzes newest alerts first, followed by the next newest. The
  timestamp sort uses `last_seen`, falling back to `timestamp` and then
  `first_seen` if needed. Triage score is only a final tiebreaker after
  severity and time.
- The scheduler must re-query SQLite and re-apply this priority order before
  every analysis handoff. A new critical alert should be selected before any
  remaining high/medium/low/informational backlog once the current model job
  completes.
- The queue lookup is intentionally SQLite-first for performance. The scheduler
  ranks eligible rows in SQLite, collapses each duplicate group to its newest
  representative with a window function, orders those grouped candidates by the
  strict severity drain, and only then applies the final analyzed/skipped group
  checks in Python.
- Eligible levels are `critical`, `high`, `medium`, `low`, and
  `informational`.
- Eligible filter statuses are `accepted`, `escalated`, `unknown`, and
  `suppressed`. Suppressed alerts are still analyzed so the model can recommend
  investigation and tuning actions.
- Look back 87600 hours so historical unique groups are not skipped after
  downtime or migration.
- Skip alert IDs that look like test/validation events.
- Skip grouped detections that already have a matching
  `*-local-ai-analysis.json` artifact for any member alert.
- Requeue a grouped detection for analysis when matching
  `$HOME/n8n-local/soc-alerts/pcap-analysis/*-pcap-analysis.json` evidence is
  newer than the latest local AI artifact.
- Hold `$HOME/n8n-local/run/ai-analysis.lock` so two Ollama jobs do
  not overlap.
- Rebuild and sync the SOC dashboard once while analysis is active and again
  after successful analysis. The first refresh lets the SOC Alerts metrics show
  the animated `Analyzing` indicator during the local Ollama run.
- Repair minor local model response schema drift with explicit defaults. For
  example, if the model omits `tuning_reason`, the runner fills a safe default
  and records `_schema_repair` in the analysis JSON instead of failing the job
  and blocking the queue.

Manual dry run:

```bash
ssh <mac_user>@10.77.7.225 \
  '$HOME/n8n-local/bin/auto-run-ai-analysis.py --dry-run'
```

Operational logs:

```text
$HOME/n8n-local/logs/ai-analysis.out.log
$HOME/n8n-local/logs/ai-analysis.err.log
$HOME/n8n-local/soc-alerts/llm-analysis-logs/llm-analysis-log.jsonl
$HOME/n8n-local/soc-alerts/llm-analysis-logs/current-analysis.json
```

Validated 2026-07-02:

```text
launchd label: com.arron.soc.ai-analysis
launchd policy after correction: all severities, max 3 unique groups per run
known backlog at correction time: 63 unique real groups, 8 analyzed, 55 remaining
interval: 300 seconds
stuck-alert cause fixed: missing tuning_reason no longer fails the analysis job
```

As of 2026-07-13, prompt packages also include current grouped analyst state
and bounded prior local analyses. Acknowledgement or suppression state, repeat
count, analyst reason, and state-change time are evidence inputs, not identity
fields. `$HOME/n8n-local/config/ai_model_settings.json` is the runtime model
routing authority; the LaunchAgent intentionally does not hardcode `--model`.

## Next Implementation Step

Then add optional hosted escalation:

```text
local response says hosted_second_opinion_recommended=true
or triage_level in critical/high and analyst enables hosted escalation
-> hosted model receives curated prompt package
-> hosted response saved as second-opinion Markdown
```
