# LLM Harness And Investigation Runtime Roadmap

## Purpose

This roadmap defines how Onion Sentinel may evaluate Hermes Agent, OpenClaw,
and a purpose-built investigation runtime without weakening the current local,
deterministic alert-analysis path. The repository remains the source of truth;
runtime credentials, conversation history, live evidence, and generated agent
artifacts remain on their designated hosts and out of Git.

This document remains the long-term roadmap. A narrowly scoped production
adapter exception is recorded below; it does not authorize general-purpose
agent tools or direct Security Onion access.

## 2026-07-25 Bounded Adapter Decision

Hermes Agent and OpenClaw may be enabled independently as model harnesses for
any Onion Sentinel agent role, subject to all of these controls:

- Both integrations remain disabled by default and appear in role selectors
  only while their individual Settings toggle is enabled.
- Hermes runs as an ephemeral `--oneshot --safe-mode` invocation with an
  explicit `openai-codex` provider and model, isolated temporary state, and
  only the empty `context_engine` toolset selected. The installed one-shot
  runtime is restricted to its observed `medium` reasoning behavior; Onion
  Sentinel does not claim that a configured turn limit or another reasoning
  effort is enforced.
- OpenClaw runs through stateless `infer model run` simple completion. The
  production adapter admits only explicit `ollama/<model>` routes against
  loopback Ollama; it does not load an operator profile, hosted-provider
  credentials, tools, memory, session history, skills, or MCP.
- Neither harness receives Security Onion credentials, shell access, or direct
  evidence-collection authority. A harness may receive bounded, redacted
  evidence, query text, and broker-returned query results, and may propose
  follow-up queries. All Elastic, OQL, OSQuery, PCAP, Zeek, and Suricata
  execution continues through Onion Sentinel's bounded, audited, read-only
  investigation broker.
- Missing executables, authentication failures, output overflow, timeouts,
  malformed JSON, schema failures, and observed-model mismatches fail closed
  without silent provider fallback.
- OpenClaw routes backed by Ollama use the same host-wide inference lock and
  unload control as direct local-model routes.

This exception authorizes the bounded adapters only. Interactive autonomy,
general terminal/filesystem tools, direct Security Onion connections, and
state-changing actions remain outside the production boundary.

### One-time Hermes authentication provisioning

Onion Sentinel never imports credentials from `~/.hermes/auth.json` or
`~/.codex/auth.json`. Authenticate the dedicated Hermes profile once with the
following exact commands on the Mac Studio:

```bash
install -d -m 700 \
  "$HOME/n8n-local/private/hermes-agent" \
  "$HOME/n8n-local/private/hermes-agent/home" \
  "$HOME/n8n-local/private/hermes-agent/home/.codex"

env \
  HOME="$HOME/n8n-local/private/hermes-agent/home" \
  HERMES_HOME="$HOME/n8n-local/private/hermes-agent" \
  HERMES_REAL_HOME="$HOME/n8n-local/private/hermes-agent/home" \
  CODEX_HOME="$HOME/n8n-local/private/hermes-agent/home/.codex" \
  hermes auth add openai-codex --type oauth

chmod 600 "$HOME/n8n-local/private/hermes-agent/auth.json"
```

The OAuth flow writes credentials only to the dedicated
`~/n8n-local/private/hermes-agent/auth.json` rather than either user-level
store; do not copy an existing Hermes or Codex auth file into this location.
The runtime holds an owner-only outer lock, extracts only the `openai-codex`
provider and credential-pool entries into an ephemeral profile, and atomically
writes rotated credentials back to this dedicated store. Prompts, sessions,
memory, user profile data, and the temporary Codex home are discarded after
every invocation.

OpenClaw is always treated as a third-party hosted-harness trust boundary for
evidence redaction. Each invocation receives fresh owner-only `HOME`,
`CODEX_HOME`, `OPENCLAW_HOME`, state, config, OAuth, agent, workspace, XDG, and
temporary directories. The config is the empty JSON object and no operator
OpenClaw state is copied. An explicit `ollama/` model prefix and a loopback-only
Ollama endpoint control use of the host-wide GPU lock and post-run unload; they
never relax redaction. `OPENCLAW_OFFLINE=1` disables optional helper downloads
in the installed CLI but is not an operating-system network sandbox or a
general egress control.

Hermes receives fresh owner-only `HOME`, `HERMES_HOME`, `HERMES_REAL_HOME`,
`CODEX_HOME`, XDG, and temporary directories. Only the filtered dedicated
`openai-codex` authentication data is copied into that profile.
`PYTHON_DOTENV_DISABLED=1` prevents the installed Hermes CLI from importing
values from either user or source-tree `.env` files. The isolated baseline
config records `context.engine: compressor`, disables memory/profile features,
and is owner-only; the adapter's security boundary depends on `--safe-mode`,
the explicit provider/model flags, the empty toolset, and the verified usage
artifact rather than on user-config loading.

### Installed CLI prompt-transport limitation

The supported installed CLIs do not expose a stdin or text prompt-file
transport. Hermes Agent 0.18.2 requires `--oneshot PROMPT`; OpenClaw 2026.6.8
requires `--prompt TEXT`, and its `--file` option accepts images rather than a
text prompt. Onion Sentinel therefore passes only its size-bounded,
hosted-redacted payload in argv and never substitutes raw unredacted evidence
or credentials. While either process is running, that payload may be visible
to another process running as the same operating-system user and to process or
crash telemetry. Run Onion Sentinel under a dedicated service account where
possible, and re-evaluate this accepted residual exposure when either CLI adds
a documented stdin or prompt-file interface.

## Current Promotion Gate

The dated bounded-adapter decision above is the sole exception to this gate. It
supersedes the gate only for those disabled-by-default, model-transport
adapters under their stated evidence, credential, tool, and isolation
controls. It does not authorize interactive autonomy, direct evidence access,
or general-purpose harness tools.

Every broader harness, direct-tool adapter, expanded policy broker, or
investigation-runtime phase remains gated until the existing direct-Ollama
deployment has completed its current qualification cycle. The gate requires a
clear protected PCAP backlog, green operational SLO evaluation, a successful
recovery drill, and a continuous 48-hour production soak with no unresolved
ingestion, analysis, notification, disk-capacity, or PCAP-flow warning. Work
beyond the bounded exception must remain synthetic, isolated, disabled by
default, unable to reach live evidence, and unable to mutate production state.

## Current Production Boundary

- The scheduled SOC Analyst pipeline uses its exact enabled assigned route
  (Ollama, Codex CLI, Hermes Agent, or OpenClaw) and bounded prompt packages
  generated by Onion Sentinel.
- Onion Sentinel owns alert identity, grouping, priority, state transitions,
  evidence collection, durable scheduling, output validation, and audit logs.
- Zeek and TShark parse PCAP before evidence is supplied to an LLM. A model does
  not receive unrestricted packet files, shell access, or filesystem access.
- Cyber Security Agent memory is bounded Markdown evidence. Automated writes to
  individual or shared memory are not enabled until provenance, review, and
  rollback controls exist.
- General-purpose agent harnesses must not receive direct SQLite writes, n8n
  administration, raw provider credentials, unrestricted SSH, unrestricted
  OSQuery, or arbitrary command execution.
- The existing `$HOME/.hermes` dashboard deployment paths do not imply that
  Hermes Agent is part of the production SOC analysis path.

## Target Architecture

Onion Sentinel should expose one versioned model-runner contract while keeping
the alert workflow independent from any individual harness.

```mermaid
flowchart LR
  Q["Durable analysis job"] --> E["Bounded evidence package"]
  E --> P["Investigation policy broker"]
  P --> A["Runner adapter"]
  A --> O["Direct Ollama adapter"]
  A --> H["Hermes Agent adapter"]
  A --> C["OpenClaw adapter"]
  A --> X["Optional hosted-model adapter"]
  O --> V["Schema validation and evidence citations"]
  H --> V
  C --> V
  X --> V
  V --> R["Immutable run record and report artifact"]
  R --> S["Onion Sentinel state transition"]
```

The adapter input must contain a bounded, versioned evidence package, role
prompt, model route, tool policy, deadline, and correlation ID. The adapter
output must use the same validated response schema regardless of the selected
harness. Harnesses may propose actions; Onion Sentinel decides whether an
action is allowed, requires approval, or is denied.

## Evaluation Tracks

### Direct Ollama

Keep direct Ollama as the production baseline and rollback path. It has the
smallest attack surface and the fewest moving parts, and it provides a stable
control against which every harness experiment can be measured.

### Hermes Agent

Evaluate Hermes first as a local, optional runner for multi-step investigations
and typed tool use. Begin in shadow mode with tools disabled, then permit only
read-only Onion Sentinel tools through the policy broker. Do not grant Hermes a
general shell, direct database mutation, or access to runtime secret files.

Potential value:

- Better orchestration of bounded, multi-step investigation tasks.
- A reusable local-agent interface for Threat Hunter, Cyber Threat Intel, and
  Incident Responder workflows.
- Faster experimentation than building every orchestration feature internally.

Primary risks:

- A larger dependency and prompt-injection surface than direct model calls.
- Tool and memory behavior may change between releases.
- General agent features can blur Onion Sentinel's ownership of state and audit.

### OpenClaw

Evaluate OpenClaw only as an optional, isolated analyst interaction surface or
shadow runner after the common adapter and policy broker are proven. It must not
become a required component of ingestion, alert state, PCAP transfer, or the
automatic analysis queue.

Potential value:

- An interactive analyst experience for guided investigations.
- A second harness implementation for validating adapter portability.

Primary risks:

- Additional operational, session, authorization, and supply-chain surface.
- Interactive autonomy can produce less deterministic runs.
- A failure or upgrade must never interrupt core Onion Sentinel processing.

Before implementation, verify the security model, licensing, local deployment
behavior, and tool controls of the exact OpenClaw release selected for testing.

### Onion Sentinel Investigation Runtime

Build a thin domain-specific runtime rather than another general autonomous
agent framework. Its responsibilities should be limited to:

- Versioned evidence and response contracts.
- Model and harness routing with deadlines, cancellation, and retry policy.
- Typed, least-privilege investigation tools.
- Human approval gates for consequential actions.
- Evidence provenance, citations, redaction, and output validation.
- Durable run state, idempotency, audit records, metrics, and replay.
- Per-role and shared-memory read/write policy with review and rollback.

The runtime should reuse the existing durable analysis queue and alert-store
contracts. It must not fork a second source of truth for alerts, suppressions,
acknowledgements, reports, or PCAP state.

## Typed Tool Boundary

Initial tools should be read-only and return bounded structured data:

| Tool | Allowed behavior | Explicitly prohibited |
| --- | --- | --- |
| Alert evidence | Read one normalized alert group and its timeline | Arbitrary SQL or database writes |
| Enrichment evidence | Read normalized cached provider findings | Raw API keys or unbounded provider responses |
| PCAP evidence | Read parsed Zeek/TShark summaries | Raw packet export to external models |
| Report history | Read bounded prior analyses and analyst notes | Editing or deleting prior reports |
| Security Onion search | Execute reviewed query templates through a broker | Arbitrary SSH, shell, or unbounded searches |
| OSQuery | Execute versioned read-only query packs after policy checks | Arbitrary SQL, shell expansion, or unrestricted targets |

Mutation tools, including acknowledgement, suppression, notification, memory
updates, or response actions, require separate schemas, authorization checks,
idempotency keys, and immutable audit records. High-impact actions require
explicit analyst approval.

## Phased Deployment Plan

1. Define and test a versioned `AnalysisRequest` and `AnalysisResult` contract
   around the existing direct Ollama runner.
2. Extract the current Ollama invocation behind a runner adapter without
   changing scheduling, evidence, reports, or alert state behavior.
3. Add conformance tests that every adapter must pass using synthetic evidence.
4. Implement the policy broker and a minimal read-only tool registry. Default
   deny all tools not explicitly assigned to an agent role.
5. Add a Hermes adapter in shadow mode with tools disabled. Compare output
   quality, runtime, resource use, failure rate, and schema compliance against
   direct Ollama.
6. Enable one low-risk read-only tool at a time for Hermes after threat modeling
   and authorization tests pass.
7. Evaluate OpenClaw in an isolated development environment as an optional
   analyst interface and adapter-portability test. Keep it off the production
   ingestion and automatic-analysis paths.
8. Introduce the thin Onion Sentinel Investigation Runtime for routing, policy,
   approvals, audit, and memory governance only where existing components do
   not already provide those capabilities.
9. Run production shadow comparisons with no state mutation, then conduct a
   limited analyst-approved pilot.
10. Promote an adapter only after failure isolation, rollback, disaster
    recovery, security review, and operator runbooks are validated.

## Acceptance Gates

- Direct Ollama remains available as a tested fallback.
- Harness failure, timeout, or upgrade cannot block alert ingestion, heartbeat
  processing, PCAP transfer, dashboard reads, or another analysis adapter.
- Every run has a correlation ID, bounded evidence manifest, model and harness
  identity, tool-call log, runtime metrics, result status, and artifact hashes.
- Synthetic prompt-injection tests cannot obtain secrets, arbitrary shell
  execution, unrestricted filesystem access, or unauthorized state mutation.
- Tool authorization is server-side and default-deny; model text cannot expand
  permissions.
- Outputs pass the existing response schema and clearly distinguish supplied
  evidence, inference, uncertainty, and recommended action.
- Replayed jobs are idempotent unless an analyst explicitly requests a new
  analysis generation.
- Agent memory writes include source, timestamp, role, evidence references,
  confidence, and approval state, and can be reverted without editing history.
- Secrets and live evidence do not enter Git, generated client JavaScript,
  dashboard HTML, or unprotected logs.
- Backup and restore procedures recover adapter configuration disabled by
  default and do not restore stale sessions or access tokens into service.

## Decision Record

The preferred direction is incremental:

1. Preserve direct Ollama as the dependable automatic-analysis path.
2. Add a common adapter and policy boundary.
3. Evaluate Hermes first in shadow mode.
4. Treat OpenClaw as an optional isolated analyst interface, not core plumbing.
5. Build only the Onion Sentinel-specific investigation controls that a general
   harness should not own.

This approach captures the benefits of agent harnesses without coupling the
SOC pipeline to their release cycles or granting them authority over Onion
Sentinel's durable state.
