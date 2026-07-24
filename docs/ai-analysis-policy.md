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
and bounded packet-field samples. Its single streaming field pass also records
bounded summaries of all observed DNS activity, HTTP/1 and HTTP/2 User-Agent
values, TLS handshake/supported/record versions, and abnormal-size ICMP/ICMPv6
frames. The default abnormal ICMP threshold is 256 frame bytes and can be
changed with `ICMP_ABNORMAL_MIN_FRAME_BYTES`.

Parsing covers every local PCAP artifact for the request. Zeek consumes every
generated JSON log row using bounded heavy-hitter aggregation. TShark consumes
every packet through a streaming field export and keeps a deterministic sample
distributed across the full capture instead of a first-packet sample. Coverage
metadata records files processed, records or packets decoded, observed bytes,
capture time bounds, malformed rows, sample size, and whether both parser passes
completed. These metrics are evidence-quality facts and must be considered when
the model identifies evidence gaps.

When local MaxMind ASN, City, and Country `.mmdb` databases are configured, the
parser adds bounded, offline network-ownership and geographic context for
globally routable IP addresses. It never submits an indicator to MaxMind or
another network service. The three lookup results are merged into one compact
record per IP; raw database records are not placed in prompts or reports.
Missing databases, unavailable reader support, and unmatched addresses are
explicit nonfatal evidence gaps. GeoIP is approximate and abnormal ICMP size is
only a behavioral lead; neither may independently establish maliciousness,
attribution, severity, or a block recommendation.

Packet-derived values are untrusted, attacker-controlled evidence. A hostname,
URI, filename, protocol field, or message from a capture must never override the
system prompt or cause a command, URL, path, filter, or parser option to run.
Parsers run offline with a stripped environment and bounded process resources;
macOS deployments also deny parser network access with `sandbox-exec`.

The local model can request at most one follow-up evidence round. The runtime
supports only fixed, read-only operations over a sanitized derived-evidence
index and returns at most four queries with 20 rows each under a 32 KiB result
budget. The allowlist includes coverage, connection, protocol, packet-sample,
DNS, HTTP, TLS, file, notice, weird, ICMP-anomaly, User-Agent, TLS-version, and
GeoIP summaries. It does not retain raw PCAPs for interactive model access and does not
translate model text into shell, Zeek, or TShark syntax. Hosted second-opinion
requests exclude packet samples, follow-up query results, local tool/path
metadata, the private query index, and raw payload fields.

Incident Response uses a separate trusted evidence path. Before the assigned
Incident Responder model runs, the worker gathers five fixed Elastic packs and
seven fixed local OSquery packs through two dedicated forced-command SSH keys.
For this baseline layer, the caller and model cannot provide an index, field,
KQL expression, Query DSL object, OSquery SQL, target, filesystem path, parser
option, or command. The exact datasets and seven SQL statements are pinned in
`docs/incident-response-query-and-model-routing.md`.

Every returned pack includes an analyst-readable KQL equivalent and the exact
Elasticsearch Query DSL executed by the Security Onion wrapper. The Incident
Response report must display both under **Security Onion Query Audit**. The DSL
is the authoritative execution record; KQL communicates intent and must not be
represented as a separately executed search. Missing, partial, malformed, or
failed packs are explicit evidence gaps and must not be silently omitted or
filled by model inference.

Every OSquery result must retain the reviewed pack name, exact SQL, local
target, execution status, query digest, bounded result metadata, and explicit
error state. The report shows those values under **OSquery Command Audit**.
These fixed packs inspect Security Onion itself.

The Incident Responder may request one optional live endpoint OSQuery round.
This is a separate, disabled-by-default contract: exact operator aliases map to
exact Fleet agent IDs only on Security Onion, and the Mac, relay, and Security
Onion independently enforce the same SELECT-only table allowlist, query count,
row, response-byte, and runtime ceilings. Wildcards, all-endpoint targets,
mutations, comments, CTEs, compound queries, subqueries, and unknown tables are
rejected. A failed or unavailable live query is an explicit evidence gap, not a
license to infer missing facts.

All Ollama/local-model invocations share one host-wide inference lock. Codex
CLI and GPT CLI use an independent provider lane and may run concurrently with
one local analysis. Exact Codex routes enter that lane only when the matching
model/reasoning pair is enabled in `codex_cli_models`; malformed, disabled, or
unknown routes fail closed to the local lane. The scheduler passes the same
settings-file path to the analysis child that it used for lane selection, so
selection and execution cannot read different assignments. Jobs never silently
cross providers.

Running-analysis logs resolve their provider, model, and route from the
assigned agent before inference starts, then replace those values with stamped
response provenance when the run completes. The dashboard AI Activity, Reports,
and Flow views use that same SOC Analyst assignment instead of the compatibility
`ollama_model` field. A configured Ollama second opinion is reported separately
and does not change the primary model provenance.

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
- Deterministic cross-alert correlation candidates from indexed observables and
  persisted correlation history.
- Recent Telegram notification context.
- Latest daily SOC rollup excerpt.
- Parsed PCAP evidence summaries when available.
- Local-first/hosted-escalation policy.
- Strict JSON response schema.

## Cross-Alert Correlation Context

The SOC Analyst does not search every historical report or send the entire
alert corpus to the model. Alert-store maintains a bounded observable index for
IP addresses, domains, URLs, hashes, CVEs, ports, rules, datasets, protocols,
hosts, and users. The prompt builder retrieves candidates that share indexed
facts with the selected stable alert group, adds a bounded temporal-proximity
score, and returns only the highest-scoring candidates.

High-specificity evidence such as hashes, URLs, domains, hosts, users, and IPs
receives more weight than common ports, protocols, datasets, or rule names.
Port/protocol-only overlap does not meet the default candidate threshold. This
reduces false correlation between unrelated HTTPS, DNS, and other common
traffic. Default controls are:

```text
--correlation-limit 8
--correlation-min-score 15
```

Each candidate can include its latest prior AI assessment. Prior model output
is explicitly labeled as a hypothesis, not evidence. The current model must
confirm or contradict it using the current alert, timeline, enrichment, PCAP,
analyst state, notes, and shared deterministic observables. A common ASN, CDN,
public resolver, rule, port, or protocol alone is never sufficient evidence of
an attack chain.

After a successful model run, `run-local-ai-analysis.py` writes the normal
Markdown/JSON artifacts and posts a compact result to alert-store:

```text
POST http://127.0.0.1:8787/analysis/result
```

Alert-store is the sole SQLite writer. It upserts analysis history by
`analysis_id` and records deterministic candidate edges plus the model's
assessment. If alert-store is temporarily unavailable after inference, the
runner writes a bounded pending payload under:

```text
$HOME/n8n-local/soc-alerts/llm-analysis-logs/analysis-index-pending
```

The runner retries those payloads before the next inference. This avoids
repeating an expensive model call merely because the durable index endpoint was
temporarily unavailable.

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
  "recommended_tuning_actions": ["string"],
  "correlation_assessment": {
    "correlation_found": false,
    "confidence": "low|medium|high",
    "related_groups": [{"group_id": "stable group id", "reason": "string"}],
    "shared_evidence": ["string"],
    "contradicting_evidence": ["string"],
    "attack_chain_hypothesis": "string",
    "recommended_pivots": ["string"]
  }
}
```

The dashboard renders this object as `Correlation Assessment` inside the
existing `AI Analysis Output` section. It does not add or reorder a Detailed
Alert Report top-level section.

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

Current primary local model:

```text
devstral-small-2:24b-instruct-2512-q4_K_M via local Ollama at http://127.0.0.1:11434
```

All five Cyber Security Agent roles use `gemma4:31b` as their configured
second-opinion model. The reviewer is conditional: it runs only when the
primary result has low confidence, is inconclusive, or explicitly requests an
independent opinion.

Editable AI model routing:

```text
$HOME/n8n-local/config/ai_model_settings.json
```

The Settings page exposes independent provider controls:

- `Ollama` is a collapsed-by-default section containing the live local model
  inventory. Operators can enable one or more models for the approved global
  roster.
- `GPT CLI` is a separate collapsed-by-default section with an independent
  enable toggle. The CLI must read the bounded prompt package JSON from stdin
  and return one valid analysis JSON object on stdout.
- Every Cyber Security Agent has one primary assignment and may have one
  optional second-opinion assignment selected from that enabled roster. Both
  selectors live in the agent's expanded Settings panel, with the reviewer
  directly below `Assigned model`. The reviewer must differ from the primary
  model, and `Not assigned` is the safe default.
- The active SOC Analyst worker executes only the model assigned to
  `soc-analyst`; it does not silently switch models or privacy boundaries after
  a failure. Other role assignments are persisted for their manual or planned
  workflows.
- If an assigned route is later disabled, normalization assigns that role to
  the first still-enabled Ollama model, or GPT CLI when it is the only enabled
  route. At least one route must remain enabled.

For the active SOC Analyst, the configured second-opinion route runs only when
the validated primary result reports low confidence, classifies the detection
as inconclusive, or explicitly requests another opinion. The reviewer receives
the same bounded evidence and relevant memory but never receives the primary
conclusion. This independent pass prevents anchoring and returns a complete
structured response. Deterministic code then compares material and advisory
fields, records `agreement`, `partial_disagreement`, or
`material_disagreement`, and names every disputed field. The primary result
remains authoritative, a reviewer cannot recursively request another model,
and reviewer failure is recorded without failing or re-queuing the successful
primary analysis.
Other agent roles persist the same routing contract for their manual or
planned execution paths.

Reviewer lessons are not written directly to memory. A reviewer candidate must
come from a complete high-confidence response, agree with the primary on all
material fields, and pass the existing grounding, redaction, deduplication,
expiry, and size gates. Reviewer effectiveness is recorded independently in
SQLite table `ai_second_opinion_runs`, including both routes, outcomes,
confidence values, trigger, comparison status, disputed fields, runtime, and
promoted-memory count.

The Ollama inventory is populated from `ollama ls` through
`/api/soc-settings/ollama-models`, refreshes every 60 seconds while Settings is
open, and can be refreshed manually. A configured model that is temporarily
absent remains visible as unavailable instead of being silently disabled.
Onion Sentinel also reads bounded `/api/show` metadata and places an amber
warning beside models that cannot satisfy the current chat-based JSON analysis
exchange. The assessment requires text completion, a chat template, and at
least a 32,768-token context window; tool calling is not required because PCAP
follow-up operations are executed by the fixed local query broker. Hovering or
focusing the warning explains the failed requirement. Assessments are cached
for five minutes, while a manual model refresh invalidates the cache.
Compatibility fields `mode` and `ollama_model` remain in the JSON file for
older tooling, but they are derived from `enabled_ollama_models` and the
individually enabled entries in `codex_cli_models`; `gpt_cli_enabled` remains a
derived rolling-deploy compatibility field. Primary assignments are stored in
`agent_models`; optional
reviewers are stored in `agent_second_opinion_models`. Both maps use stable
route identifiers such as
`ollama:devstral-small-2:24b-instruct-2512-q4_K_M`, `ollama:gemma4:31b`, and
`codex-cli:gpt-5.6-sol:high`. The Codex catalog is fixed to `gpt-5.5`,
`gpt-5.6-sol`, `gpt-5.6-terra`, and `gpt-5.6-luna`. Settings renders one
immutable row per model with a reasoning-effort selector and enable switch.
Missing catalog rows are added disabled during migration; unknown or duplicate
model rows are rejected. Disabled Codex routes cannot appear in or be accepted
from an agent assignment.

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

Each role also has an independent reviewer prompt beside its primary prompt:

```text
$HOME/n8n-local/config/soc_analyst_second_opinion_prompt.md
$HOME/n8n-local/config/incident_responder_second_opinion_prompt.md
$HOME/n8n-local/config/siem_engineer_second_opinion_prompt.md
$HOME/n8n-local/config/cyber_threat_intel_second_opinion_prompt.md
$HOME/n8n-local/config/threat_hunter_second_opinion_prompt.md
```

The SOC Alerts Settings page exposes model routing controls in a collapsed
`AI Analysis Model Selection` panel plus editable prompt sections for
the SOC Analyst, Incident Responder, SIEM Engineer, Cyber Threat Intel Analyst,
and Threat Hunter roles under `Cyber Security Agents`:

```text
http://10.77.7.225:8766/settings.html
```

Save behavior:

- The web UI calls `/api/soc-settings/ai-model` for model routing.
- The web UI calls `/api/soc-settings/agent-model` with one allowlisted role and
  one enabled route to change a single agent assignment without overwriting
  unrelated settings.
- Each role exposes a primary prompt endpoint and a fixed
  `<role>-second-opinion-prompt` endpoint. Both are allowlisted; arbitrary file
  paths are never accepted.
- In every expanded agent panel, `Main system prompt` appears first and
  `Second-opinion system prompt` directly below it. Both editors are collapsed
  by default, and their path controls open only the matching editor.
- Saving requires an Onion Sentinel Administration session.
- The Onion Sentinel service writes settings files atomically and rejects empty prompts or prompts larger than 20 KB.
- The next SOC Analyst run uses its exact saved assignment and prompt
  automatically because `run-local-ai-analysis.py` reads both files immediately
  before each model request.
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
execution guidance. A dashboard escalation creates or reopens one durable case
for the stable alert group and queues an `incident_response_analysis` job. The
prompt includes the full grouped timeline and frequency, prior model analyses,
public enrichment, parsed PCAP evidence, analyst notes, correlation context,
and bounded role/shared memory. It may recommend external tooling such as
custom host artifact collection scripts, but direct execution remains a TODO
until a dedicated incident response host is connected, authenticated, logged,
and approved.

The Settings page shows collapsed trigger summaries for each Cyber Security
Agent so operators can distinguish live triggers from planned/manual workflows:
SOC Analyst runs from new eligible alerts through the scheduled AI worker,
Incident Responder runs when an operator escalates a grouped detection, SIEM
Engineer is planned for a 6 hour cron review after analysis backlog clears,
Cyber Threat Intel is manual until scheduled intelligence briefs are built, and
Threat Hunter is manual until automated hunts are built. Incident Responder
analysis is role-isolated in `ai_analysis_runs.agent_role`; it cannot replace
the SOC Analyst outcome shown in the SOC Alerts table.

SOC Alerts table rows also provide a manual `Analyze` action. The action posts
only the dashboard group id to the Mac Studio Onion Sentinel API, which resolves the newest
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

The Settings page makes each displayed Prompt path open and focus its matching
editable agent prompt panel. It shows each role memory path plus the shared memory path in
the collapsed agent row. Selecting `Memory` or `Shared` opens the current live
Markdown in a non-editable viewer. The Onion Sentinel API accepts only a logical allowlisted
memory key, rejects path input and symlink escapes, and limits a displayed file
to 256 KiB. There is intentionally no memory write API in Settings; managed
agent-memory tooling remains the only write boundary. These files are durable
Markdown storage for previous findings, known patterns, and learned information.
They do not replace the full SQLite analysis history or Markdown report corpus.

SOC Analyst prompt packages use relevance retrieval rather than copying the
first bytes of each file. Current alert, grouped timeline, enrichment, parsed
PCAP, analyst state, and bounded correlation evidence supply retrieval terms.
The package includes at most a small bounded set of matching role/shared records
plus bounded operator-authored notes. Memory remains context, not proof, and
current evidence wins when they conflict.

After a successful SOC Analyst run, the model may return `memory_candidates`.
Deterministic code rejects malformed, low-confidence, secret-like, ungrounded,
or oversized candidates before writing. Role memory accepts reusable medium or
high-confidence lessons. Shared memory requires high confidence and explicit
cross-role value. Accepted records are labeled `model-observed`, include
evidence basis, retrieval conditions, provenance, confidence, reinforcement
count, and expiry, and are written atomically under a file lock. Equivalent
records reinforce one entry instead of growing the file with duplicates.

Operator notes remain outside the delimited managed section and are preserved
on every write. Managed role files retain at most 200 records and shared memory
at most 300; expired model observations are removed during later writes.
Secrets, credentials, raw packet payloads, live alert IDs, and report
transcripts must never be stored in memory.

`$HOME/n8n-local/bin/manage-agent-memory.py` provides the same query and
writeback contract for Incident Responder, SIEM Engineer, Cyber Threat Intel,
and Threat Hunter workflows. Those workflows are still manual/planned; the
adapter is the required memory boundary when they become executable.

Agent harnesses must call `manage-agent-memory.py <role> prepare` before model
reasoning. That operation returns the role system prompt, bounded relevant role
memory, bounded relevant shared memory, canonical paths, and writeback contract
as one execution package. Keeping those inputs together prevents an execution
path from silently omitting memory. After reasoning, the harness passes the
response through the adapter's `writeback` operation.

All five roles are defined in one canonical registry consumed by the query,
writeback, tests, and deployment verification paths. Run the following read-only
check after deployment or prompt maintenance:

```bash
$HOME/n8n-local/bin/verify-agent-memory.py
```

The command exits nonzero if any agent prompt, individual memory file, shared
memory file, managed Markdown section, permission, or retrieval contract is
missing. This prevents a newly added or renamed agent from silently bypassing
memory.

The Mac Studio installer invokes the verifier with `--initialize`. Initialization
preserves all operator-authored Markdown and only adds the bounded managed
section required for deterministic writeback. It is idempotent and refuses to
rewrite a partially malformed managed section.

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
