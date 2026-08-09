# Onion Sentinel Modularization Module Map

This map applies the decision in `modularization-adr.md` to the synchronized
`3eec576a59b51b74badcc042de2e3418fca9c867` baseline. It is the extraction
checklist for ARR-74 through ARR-84. It does not authorize a production change.
Every investigation-query boundary continues to treat Security Onion and the
Relay evidence path as read-only.

## Reading the Map

- **Current owner** identifies the file/range that owns behavior today.
- **Target boundary** names the cohesive destination responsibility.
- **Port/contract** is the seam that characterization tests freeze first.
- **Side effects** must move into the named adapter rather than leak into domain
  or rendering code.
- **Compatibility** records what must remain callable during migration.

Line ranges are navigation aids for the baseline release. They are not stable
API identifiers and will change as extractions land.

## AI Analysis Runner

Baseline owner: `n8n/bin/run-local-ai-analysis.py` (19,462 lines). At the
ARR-79 composition checkpoint the compatibility file is 10,497 lines and its
`main()` entry point is the enforced 250-line composition root. The baseline
line ranges below remain historical navigation aids for the extraction ledger.

| Baseline area | Current lines | Target boundary | Contract to freeze | Side effects |
| --- | ---: | --- | --- | --- |
| CLI, prompt identity, resource monitoring | 597–1,176 | `analysis.entrypoint`, `analysis.runtime` | CLI arguments, exit codes, prompt identity, resource sample schema | clock, process/GPU metrics |
| Analysis index and memory journal | 1,177–1,769 | `analysis.persistence.index`, `analysis.persistence.memory` | queue record, staged/committed state, retry/idempotency | filesystem, alert-store HTTP |
| Prompt generation and controlled evaluation | 1,779–2,335 | `analysis.controlled_evaluation` | route requirements, frozen result identity | temporary workspace, process environment |
| Settings, route normalization, harness selection | 2,458–3,131 | `analysis.routing` | canonical route and harness eligibility | configuration read only |
| Hosted evidence sanitization/projection | 3,372–3,965 | `analysis.evidence.projection` | bounded hosted evidence envelope | none after extraction |
| Evidence-reference and reviewer catalogs | 4,078–4,983 | `analysis.evidence.references` | reference schema and resolvability | none after extraction |
| Query request normalization and live OSQuery binding | 5,043–6,405 | `analysis.queries.contracts`, `analysis.queries.osquery` | request, authorization, audit, failure schema | approved broker calls |
| Query batch execution | 6,428–7,015 | `analysis.queries.executor` | batch result and receipt binding | Security Onion/Relay/PCAP queries |
| Prompt admission and query result projection | 7,030–8,688 | `analysis.queries.prompt_projection` | admitted rows, provenance, byte budgets | none after extraction |
| Repair and deterministic pivot planning | 8,709–9,553 | `analysis.queries.planning` | repair scope and deterministic request set | none after extraction |
| Multi-round query loop | 9,556–10,522 | `analysis.queries.loop` | state transition, budgets, stop reason | provider and query ports only |
| Ollama/Codex transports | 10,525–11,214 | `analysis.providers.ollama`, `analysis.providers.codex` | observed route receipt and structured result | HTTP/subprocess |
| Hermes/OpenClaw transports | 11,235–11,992 | `analysis.providers.hermes`, `analysis.providers.openclaw` | isolated auth/env and structured result | private auth staging/subprocess |
| Provider dispatch | 11,906–11,992 | `analysis.providers.registry` | provider lookup and no-silent-fallback error | adapter invocation |
| Independent review and disagreement | 12,047–13,851 | `analysis.review` | blind package, reviewer validation, disagreement state | provider and optional query ports |
| Review/automation/memory gates | 13,854–14,862 | `analysis.review.gates` | authorization and review-required decisions | none; memory plan only |
| Verdict, confidence, and evidence guards | 14,873–17,481 | `analysis.conclusions` | factored verdict, confidence, gaps, reconciliation | none after extraction |
| Query/OSQuery audit and follow-up | 17,484–18,023 | `analysis.reporting.audit` | audit schemas and bound references | optional governed follow-up |
| Validation and report rendering | 18,056–18,490 | `analysis.reporting` | structured result and Markdown fields | none after extraction |

### Extraction ledger

- Controlled-evaluation discovery, exact memory-freeze enforcement, output and
  harness-database confinement, one-time token consumption, deferred-result
  reconciliation, prompt loading, role attestation, settings resolution, live
  OSQuery preparation, enrichment preparation, and evidence-contract binding
  now live in `onion_sentinel.startup` behind typed policy and port records.
- Route resolution, harness eligibility/start/bypass behavior, controlled-mode
  enforcement, shadow-mode failure isolation, running-record publication,
  phase observation, and resource-monitor startup now live in
  `onion_sentinel.preparation`.
- The ordered load, attest, prepare, primary analysis, governed pivots,
  independent review, adjudication, deterministic guards, validation, commit,
  post-commit, completion, and failure ledger now lives in
  `onion_sentinel.pipeline.RuntimeContext`. Analysis/review orchestration uses
  explicit ports and does not own provider or persistence side effects.
- Best-effort terminal harness failure, monitor shutdown, final telemetry
  publication, and stale active-record cleanup now live in
  `onion_sentinel.telemetry`; telemetry failure cannot change a committed
  analysis outcome.
- `n8n/bin/local_ai_pipeline_adapters.py` owns concrete binding of legacy
  callables to package ports. It contains no investigation or persistence
  policy. `run-local-ai-analysis.py::main` is limited to stage composition,
  state handoff, terminal error classification, and the compatibility CLI.
- Model roster normalization, exact route construction/parsing, assigned/live
  metadata, external-harness route handling, and reviewer model identity now
  live in `onion_sentinel.analysis.providers.routing`. The legacy runner keeps
  thin symbol delegates for dynamic-import compatibility.
- The bounded Ollama HTTP request, task selection, host-wide inference lock,
  best-effort unload, ordered enabled-model failover, and observed-model
  mismatch guard now live in `onion_sentinel.analysis.providers.ollama`.
- Codex prompt admission, canonical prompt-file validation, strict reviewer
  schema generation, fixed read-only/ephemeral argv, bounded subprocess result,
  and secret-safe failure classification now live in
  `onion_sentinel.analysis.providers.codex`. Shared minimal CLI environment and
  third-party harness error classification live in `providers.cli_common`.
- OpenClaw loopback-route admission, isolated ephemeral profile construction,
  fixed inference argv, bounded execution, response-envelope parsing, exact
  provider/model attestation, serialized Ollama use, and guaranteed unload now
  live in `onion_sentinel.analysis.providers.openclaw`.
- Hermes dedicated-auth filtering and bounded loading, atomic credential
  rotation, exclusive auth locking, ephemeral profile construction, tool-empty
  fixed argv, bounded execution, and usage-sidecar identity attestation now
  live in `onion_sentinel.analysis.providers.hermes`.
- Exact enabled-route admission, hosted-contract synchronization, single
  adapter selection, no-silent-fallback errors, and final observed-identity
  attestation now live in `onion_sentinel.analysis.providers.registry`.
- Pure Incident Response narrative, Security Onion query audit, appliance and
  live endpoint OSQuery audit rendering now live in
  `onion_sentinel.analysis.reporting.incident`. Deterministic top-level SOC/IR
  Markdown composition now lives in `analysis.reporting.markdown`; the legacy
  runner retains only symbol-compatible delegates.
- Side-effect-free output metadata/path planning and owner-private,
  path-confined atomic JSON/Markdown publication now live in
  `analysis.reporting.publication`. A failed pair publication removes only
  artifacts created by that attempt and existing destinations fail closed.
- Receipt-bound alert-store submission, collision-safe durable spooling,
  deterministic-rejection quarantine, and ordered crash replay now live in
  `analysis.persistence.analysis_index`. Memory-journal promotion remains an
  injected post-commit adapter so evidence indexing is authoritative and
  memory reinforcement remains recoverable and supplemental.
- Commit-gated memory planning, immutable pending/committed journal records,
  response-digest binding, privacy-preserving receipts, and idempotent
  post-crash replay now live in `analysis.persistence.memory_journal`.
- Pure legacy-outcome canonicalization, orthogonal verdict derivation,
  model-field admission, contradiction detection, and compatibility audit
  records now live in `analysis.conclusions.verdict`.
- Evidence-reference validity, corroborating-source diversity, schema repair,
  contradictions, deterministic guard caps, incident-completeness caps, and
  confidence audit records now live in `analysis.conclusions.confidence`.
- Ordered second-opinion triggers and deterministic primary/reviewer field
  comparison now live in `analysis.review.comparison`. Consequential verdict,
  handling, escalation, and control-tuning differences remain material;
  non-escalatory context differences remain visible but advisory.
- Reviewer case precedence, blind-package evidence hashing, bounded validation
  telemetry, field-specific repair guidance, and rejected-observable-safe error
  categories now live in `analysis.review.contracts`.
- Blind package copying, anti-anchoring sanitization, operator-confirmed memory
  admission, transport-before-catalog ordering, review schema/contracts, and
  supplemental-context re-binding now live in `analysis.review.package`.
- Material-disagreement publication policy now lives in
  `analysis.review.disagreement`; validated shadow adjudication projection
  lives in `analysis.review.projection`; and required/completed review
  fail-closed automation controls live in `analysis.review.gates`.
- Canonical, digest-bound operator authorization validation now lives in
  `analysis.conclusions.authorization_evidence`; the runner retains private
  compatibility delegates used by characterization tests.
- Bounded evidence-reference normalization, source-class grouping, and
  immutable query/result digest binding now live in
  `analysis.evidence.references` as the first ARR-78 query-engine boundary.
- Model citation admission, corroborating-source classification, invalid-ref
  removal, and evidence-gap audit projection now live in
  `analysis.evidence.validation`.
- Bounded reference admission, canonical returned-count handling,
  corroboration upgrades, evidence digests, and deterministic contract output
  now live in `analysis.evidence.registry`.
- Exact top-level compact-column provenance validation, decoding, read-only
  enforcement, and result-bound registration now live in
  `analysis.evidence.columnar`; malformed claimed envelopes are consumed as
  inert evidence and never recursively reinterpreted.
- Bounded ordinary evidence-tree traversal and discovery of query, pack,
  query-id, evidence, and PCAP references now live in
  `analysis.evidence.traversal`; nested compact-column lookalikes remain inert.
- Top-level section admission, canonical authorization references, compact vs
  ordinary routing, and contract attachment now live in
  `analysis.evidence.contract` behind injected evidence ports.
- Canonical query scalar/timestamp parsing and trusted-envelope 24-hour
  clamping now live in `analysis.query.primitives` and
  `analysis.query.window`, preserving explicit adjustment audit metadata.
- Role-aware event-tuple normalization, trusted provenance matching, and
  pack-field projection now live in `analysis.query.event_tuple`; projection
  audit exposes only field names and cryptographic provenance digests.
- Elastic/OQL purpose, pack, aggregation, bounded-observable, size, window,
  and event-tuple request normalization now live in
  `analysis.query.security_onion` behind explicit policy and dependency ports.
- Exact public-enrichment indicators and their trusted original/discovered
  evidence authorization now live in `analysis.query.enrichment`.
- Operation allowlisting, exact scalar filter bounds, provider filter
  normalization, and result limits for PCAP/Zeek-derived evidence now live in
  `analysis.query.derived`.
- Bounded target selection and read-only SELECT validation for live endpoint
  OSQuery requests now live in `analysis.query.endpoint`.
- Exact request envelopes, backend identity, deterministic query-ID fallback,
  backend parameter projection, and cross-backend drop audit now live in
  `analysis.query.request`.
- Independent public-enrichment execution, evidence contract admission, result
  binding, and terminal error projection now live in
  `analysis.query.execution.enrichment`.
- Capped PCAP/Zeek-derived execution, provider evidence validation,
  source/query/result digest binding, canonical evidence references, and
  terminal batch errors now live in `analysis.query.execution.derived`.
- Live OSQuery target authorization, dispatch, artifact validation, exact
  request/result coverage binding, support-evidence accumulation, and failure
  custody now live in `analysis.query.execution.endpoint`.
- Security Onion local-context projection, isolated authorization preflight,
  per-round query/observable budgets, broker proposal construction, evidence
  admission, and response audit binding now live in
  `analysis.query.execution.security_onion`.
- Stable backend partitioning, transition ordering, and canonical round result
  assembly now live in `analysis.query.execution.batch`.
- Override clamping, evaluation-retry limits, per-round admission, remaining
  capacity, and ignored/terminal request accounting now live in
  `analysis.query.state`.
- Trusted-catalog observable recovery, immutable repair scopes, non-widening
  validation, broker contract-failure classification, and value-safe repair
  prompt projection now live in `analysis.query.repair` behind explicit
  normalization, tuple, and digest ports.
- Fixed model-visible query error categories and bounded raw-error digest
  binding now live in `analysis.query.prompt_errors`; broker, validator, and
  attacker-controlled raw error text remains outside follow-up prompts.
- Canonical prompt serialization, complete bounded facts, exact count
  admission, most-specific provenance counts, query semantics, and result
  summaries now live in `analysis.query.prompt_facts`.
- Exact scalar/grouped query-ID coverage, per-query status/fact binding, and
  complete result-bound columnar fallback now live in
  `analysis.query.prompt_provenance`; partial, extra, duplicate, or malformed
  collector batches fail closed.
- Recursive cumulative row projection, query-error sanitization, and
  digest-bound trusted audit compaction now live in
  `analysis.query.prompt_compaction`; executable query renderings remain only
  in durable audit, outside size-constrained follow-up prompts.
- Exact cumulative byte-budget orchestration, ordered audit/evidence/metadata
  omission, self-size convergence, and fail-closed columnar fallback now live
  in `analysis.query.prompt_budget`.
- Structural projection-state enumeration, exact whole-package measurement,
  refreshed citation-contract binding, hosted projection synchronization, and
  mutation-after-stable-admission now live in `analysis.query.prompt_admission`.
| Output write and orchestration | 18,493–19,458 | `analysis.persistence.unit_of_work`, `analysis.orchestration` | prepare/validate/commit/post-commit and terminal status | filesystem, alert store, harness repository |

### Required AI runner ports

```text
AnalysisWorkflow.run(RuntimeContext, PromptPackage) -> TerminalAnalysis
ProviderAdapter.invoke(ModelRequest) -> ModelReceipt
QueryEngine.advance(InvestigationState, ProposedQueries) -> QueryTransition
ReviewPipeline.review(PrimaryAnalysis, ReviewEvidence) -> ReviewDecision
ConclusionPipeline.reconcile(EvidenceState, ReviewDecision) -> ValidatedConclusion
ResultUnitOfWork.commit(ValidatedAnalysis, ArtifactPlan) -> CommitReceipt
```

`RuntimeContext` supplies clocks, ID factories, bounded HTTP/process runners,
configuration snapshots, release identity, and repositories. Workflow/domain
modules do not resolve global paths or environment variables directly.

The wrapper must continue to re-export symbols used by the existing model
routing, investigation loop, controlled evaluation, PCAP, memory writeback,
reviewer, and resource-monitor test modules until those tests migrate.

## Scheduler and Harness

### `auto-run-ai-analysis.py`

| Responsibility | Target boundary | Durable owner |
| --- | --- | --- |
| Argument/config parsing and lane selection | `scheduler.entrypoint` | none |
| Controlled-evaluation recovery | `scheduler.controlled_recovery` | controlled result repository |
| Alert/job selection and priority | `scheduler.selection` | alert-store query service |
| Claim and lease validation | `scheduler.leases` | durable job repository |
| Evidence/prompt preparation | `scheduler.preparation` | prompt builder port |
| Runner command and bounded execution | `scheduler.execution` | bounded process adapter |
| Result reporting and wake behavior | `scheduler.reporting` | alert-store job service |
| Terminal-success reconciliation | `scheduler.reconciliation` | durable job repository |

The launchd-facing wrapper keeps the current filename, arguments, lock files,
wake files, provider lanes, and exit semantics.

`scheduler_cli.py` now owns the launchd-facing argument schema, runtime path
options, lane and queue controls, numeric bounds, and fail-closed controlled-
evaluation identity validation. `auto-run-ai-analysis.py` retains a thin
compatibility facade that resolves its existing mutable defaults and injects
the alert-ID, dispatch-ID, and stable-group-key policies at parse time, so
tests and operators keep the exact CLI and environment behavior.

`scheduler_claim.py` owns compare-and-set processing acquisition,
server-authoritative job/alert/group replacement, controlled claim identity,
IR reanalysis-attempt binding, contention projection, and automatic-threshold
retirement. Its mutable claim receipt is populated immediately after a server
transition so any later validation error still exposes only the exact owned
lease to the outer retry/release handler.

`scheduler_job_reporting.py` owns the bounded `/jobs/status` mutation contract,
terminal status projection, exact controlled-claim validation, indeterminate-
request retry policy, rolling-deployment 404 behavior, conflict rejection, and
server-authoritative lease snapshot. Its source bundle exposes HTTP creation,
transport, bounded JSON decoding, mutation headers, sleep, and controlled-route
policy. The launchd wrapper retains a stable `report_ai_job_status` facade and
binds its existing transport globals at call time for compatibility.

`scheduler_indexed_state.py` owns the schema capability check for indexed
scheduling and the read-only reconciliation query for pending jobs already
satisfied by a same-attempt committed analysis or orphaned by alert removal.
Fresh jobs, stale analysis rows, and explicit rerun requests remain eligible
for scheduler execution. The launchd wrapper keeps stable compatibility
delegates while later priority-selection extraction consumes this repository.

`scheduler_indexed_selection.py` owns the indexed durable-job selection query
and the pure provider-lane predicate. Its request and source bundles make the
clock, age window, test policy, severity policy, exact-group target, eligible
statuses, fairness threshold, and lane parameters explicit. Manual reruns
preempt unattended work; severity remains strict across roles; bounded age
fairness applies within a severity; subsecond due times and prior SOC results
remain authoritative. The launchd wrapper resolves settings and binds these
inputs at call time, preserving its public selection function.

`scheduler_legacy_selection.py` preserves the pre-indexed fallback as a
separate compatibility boundary. It combines artifact freshness, pending
durable rerun intent, duplicate-group reduction, manual prompt overrides,
strict severity order, per-drain exclusions, and exact-group targeting through
an explicit request and injected artifact/query sources. Indexed deployments
do not depend on this filesystem-backed path, allowing it to be retired safely
after the supported upgrade window.

`scheduler_startup.py` owns pre-lock preflight and lock-owning runtime
initialization. Maintenance drain remains the first check; controlled runtime
and token validation precede capacity and database checks; controlled spools
recover before inference; legacy CLI lanes fail closed; and production-only
deferred indexing plus terminal-success recovery complete before initial queue
reconciliation. Filesystem locking itself remains in the thin entrypoint so
the lock lifetime still encloses the full drain and settlement sequence.

`scheduler_settlement.py` owns post-drain dashboard signaling, the mandatory
second reconciliation pass for intent arriving during inference, and the
distinct bounded controlled-job failure payload/exit code. Runs with no
completed analysis skip the dashboard wake but still reconcile late durable
intent before returning.

`scheduler_terminal_recovery.py` owns the read-only proof that a stranded
processing lease already produced an exact, committed terminal result. It
requires matching provider lane, group, alert, role, attempt window, harness
run, analysis row, and—when applicable—the Incident Response case pointer
before its injected reporting port may complete the lease. This prevents crash
recovery from issuing duplicate inference or adopting an unrelated artifact.
The launchd wrapper retains compatibility delegates and binds its read-only
SQLite connector and status reporter at call time.

### `onion_sentinel_harness.py`

| Current responsibility | Target boundary | Notes |
| --- | --- | --- |
| Policy and binding resolution | `harness.policy` | pure validation and capability decisions |
| Job envelope and ledger manifests | `harness.contracts` | versioned immutable data contracts |
| Schema initialization/migration | `harness.schema` | transactionally versioned |
| 1,724-line `HarnessStore` | `harness.repositories.*` | split run, ledger, event, query, model, memory repositories |
| 857-line `HarnessRun` | `harness.run` and stage services | state transitions use repository ports |
| Memory promotion decision | `harness.memory` | decision only; promotion remains post-commit |
| Maintenance/reconciliation | `harness.maintenance` | separate supervised operation |

Existing SQLite files, schema versions, hash-chain calculations, terminal
digests, skill attestations, and controlled-evaluation behavior are contracts.

## Prompt and Evaluation Tooling

| Current owner | Target boundaries |
| --- | --- |
| `build-ai-investigation-prompt.py` | evidence loader, correlation projector, skill/policy selector, prompt view model, budget compactor, package validator, CLI wrapper |
| `run-incident-harness-cohort.py` | cohort freeze, manifest, dispatch, monitor, execution proof, artifact seal, CLI wrapper |
| `evaluate-investigation-cohort.py` | proof validation, sealed-input loader, case grader, aggregate grader, report renderer |
| `evaluate-harness-traces.py` | trace loader, model-route proof, skill attestation, query audit, stage evaluator, summary renderer |

Ground truth, frozen evidence, model results, and unblinded comparison remain
separate inputs. Shared contracts have one implementation; CLI wrappers do not
copy validation logic.

## Portal Runtime

Current owner: `onion-sentinel-dashboard/report_portal.py` (14,366 lines).

`portal_request_routes.py` is the first extracted HTTP boundary. It owns the
pure GET/HEAD/POST method-path allowlist, typed GET/POST responsibility and
resource-target classification, request-size class, and advertised content
type. `PortalHandler` continues to
own headers, authentication, same-origin enforcement, body parsing, service
calls, and responses; mutable runtime policy is passed into the classifier
explicitly so tests and deployed prompt routes cannot drift.

`portal_soc_write_dispatch.py` owns the bounded callback selection for SOC
alert actions, analyst adjudications, incident status changes, and incident
reanalysis. Route metadata decodes the target identifier once; the handler
still owns authorization, JSON validation, cache invalidation, and HTTP
responses, while the dispatcher has no database or process-state access.

`portal_json_body.py` owns decoded-body JSON parsing and explicitly preserves
the portal's strict, nullable, and lenient fallback modes. It distinguishes
malformed JSON from valid JSON `null` and does not silently coerce valid arrays
or scalar values, allowing each endpoint to retain its existing validation
policy while removing repeated decoder exception blocks.

`portal_ai_settings_normalizer.py` owns pure orchestration for editable SOC AI
settings. It stages legacy migration, Ollama and CLI provider validation,
provider enablement, primary/reviewer/adjudicator assignment normalization,
automation thresholds, capture-loss policy, MaxMind paths, and safe rolling-
deployment compatibility fields. `report_portal.py` retains the public facade
and injects an immutable policy containing the existing model-roster, route-
identity, executable, and assignment helpers. The normalizer has no persistence,
HTTP, filesystem reads or writes, process execution, or network access.

`portal_ai_settings_store.py` owns locked settings reads, atomic owner-only JSON
writes, normalized full-roster saves, and per-agent primary/reviewer/adjudicator
assignment transactions. It enforces enabled-route membership and distinct
provider/model identities before mutation and projects the stable settings and
GeoIP response schema. Its source bundle exposes normalization, CLI readiness,
route composition/identity, GeoIP projection, roles, the settings path, and
lock; HTTP authorization and response serialization remain outside the module.

`portal_agent_content_store.py` owns trusted prompt reads, normalized and
atomic owner-only prompt writes, fixed-map route selection, and read-only agent
memory viewing. Memory reads require an allowlisted key, resolved containment
beneath the configured root, a regular file, and the configured size bound;
responses expose content and safe metadata but no write capability. The portal
retains runtime path maps, limits, HTTP authorization, and compatibility facades.

`portal_ai_model_policy.py` owns the model catalog and reusable route policy
injected into the settings normalizer: safe defaults, bounded Ollama rosters,
literal boolean parsing, executable and provider-model validation, Codex roster
completion, enabled-route composition, stale-route migration, effort-independent
provider/model identity, and primary/reviewer/adjudicator independence. The
portal re-exports the legacy names for compatibility while holding only the
settings lock and public normalization facade. This policy module reads only
the two documented default environment variables and performs no persistence,
HTTP, filesystem reads or writes, process execution, or network access.

`portal_cli_provider_readiness.py` owns fixed-order Hermes/OpenClaw executable
resolution and the safe Hermes credential-readiness boundary: exact owner-only
mode, regular non-symlink identity, bounded no-follow reads, strict JSON, and
dedicated `openai-codex` provider/pool validation. It returns only safe
operator-facing readiness errors and never exposes credential contents. The
portal retains runtime paths, executable discovery, provider-enable policy
callbacks, and compatibility facades.

`portal_ollama_catalog.py` owns fixed-order local model discovery, deduplicated
CLI output parsing, bounded cached `/api/show` metadata retrieval, capability/
chat-template/context-window compatibility classification, configured-but-
uninstalled model projection, cache refresh, and bounded concurrent assessment.
Its source bundles expose process execution, environment, settings/defaults,
normalization, URL transport, bounded JSON reading, cache operations, and worker
limits. The portal retains runtime constants and stable compatibility facades.

`portal_admin_dashboard.py` owns the Administration dashboard view model and
escaped rendering. Its explicit source boundary collects service health,
running/latest actions, update and reboot state, version/availability details,
bounded state-file metadata, log tails, and trusted cron fragments before pure
rendering. `portal_admin_dashboard_assets.py` owns the stable page CSS and
browser-side service-start/reboot-confirmation behavior. `report_portal.py`
retains a small facade that supplies existing host, process, filesystem, and
shell callbacks; the renderer itself cannot invoke an undeclared system action.

`portal_admin_versions.py` owns bounded current/latest version discovery for
the macOS, Homebrew, and Hermes Administration cards. Its explicit source
bundle exposes only command execution, cached macOS update status, and Hermes
paths. Provider-specific parsing and presentation are split into small
collectors, while `report_portal.py` retains process environment construction
and the public compatibility facade.

`portal_admin_availability.py` owns the decision policy that enables or blocks
Administration update actions. It evaluates cached macOS update state and
bounded Homebrew/Hermes command outcomes supplied by the portal. The module
cannot construct a process environment or execute a command itself; the portal
retains that host adapter and returns only a typed, bounded command outcome.

`portal_admin_action_state.py` owns durable Administration action status,
newest-outcome projection, stale-process reconciliation, and atomic singleton
lock ownership. Its source bundle declares the state/lock roots, approved
action catalog, process-liveness probe, clock, and timestamp codecs. The portal
retains compatibility facades; shell construction and process launch remain
outside this persistence module.

`portal_admin_action_runner.py` owns approved-action validation, typed
confirmation, availability gating, audit-log initialization, completion
wrapper construction, detached-launch orchestration, and launch-failure
rollback. All state operations and process launch are explicit callbacks. The
portal retains the trusted action catalog, environment, working directory,
subprocess constants, and actual `Popen` adapter.

`portal_admin_service_probes.py` owns process matching and health
classification for Macs Fan Control, the Codex app/CLI, and Docker. Its source
bundle exposes only a bounded process snapshot and Docker-info outcome;
subprocess execution and executable resolution stay in the portal.
`portal_admin_services.py` owns service-card projection and allowlisted startup
orchestration, including idempotent already-running behavior and post-launch
re-probing. The portal retains the start-command catalog and `Popen` adapter.

`portal_disk_inventory.py` owns local-disk usage projection, `du`/`stat`
parsing, largest-item ranking, independent scan warnings, and the bounded
inventory cache. Its source bundle exposes the home root, clock, cache, and two
scan callbacks. The portal retains exact macOS commands, shell quoting,
subprocess constants, and the 30-second process adapters.

`portal_hermes_backup_health.py` owns Hermes disaster-recovery archive
discovery, companion-file validation, scheduled-log correlation, newest
successful-set selection, incomplete-artifact and unfinished-attempt warnings,
newest-first inventory projection, success ratings, and redacted log-tail
projection. Its source bundle exposes backup locations plus timestamp, size,
relative-age, and redaction callbacks. The portal retains environment-derived
paths and presentation rendering through compatibility facades.

`portal_update_health.py` owns cached macOS-update projection, bounded Homebrew
and Hermes check classification, live/stale update-action classification,
newest-failure selection, and homepage update-source precedence. Its source
bundle exposes command outcomes, action-state readers, process liveness,
labels, and timestamp codecs. The portal retains executable paths, subprocess
limits/environment, admin-state storage, and detail-page presentation through
compatibility facades.

`portal_llm_activity.py` owns agent/job identity, immutable observed-model
provenance decoration, idle and stale-current projection, concurrent-run
aggregation, and live dashboard overlays. It composes the narrower
`portal_llm_runtime_state.py` route/phase policy and accepts the process-liveness
decision as a callback. The portal retains bounded status-file discovery,
process snapshots, queue reads, and compatibility facades.

`portal_llm_active_store.py` owns nonnegative queue projection, size-bounded
status-record parsing, non-symlink newest-file discovery, exact runner-PID and
legacy prompt-path process matching, single-snapshot liveness filtering, and
deterministic active-run ordering. Its source bundle exposes only the active
directory, byte/record limits, and a bounded process-command snapshot callback.
The portal retains the static dashboard read, actual `ps` subprocess, runtime
paths, and compatibility facades.

`portal_llm_history.py` owns committed primary-run projection, exact and
five-second legacy identity reconciliation, second-opinion and disagreement
adjudication shaping, exact-parent collector telemetry hydration, reviewer
start-time derivation, chronological ordering, per-role totals, and history
truncation metadata. The portal retains schema-adaptive read-only SQLite and
JSONL queries, cache lifetime, pagination, and compatibility facades.

`portal_llm_history_store.py` owns schema-adaptive, read-only SQLite table and
column discovery; bounded primary, reviewer, and adjudicator queries; optional
legacy-column projection; and alert-context joins. Its source bundle exposes
only the connection context and history limit. The portal retains the database
path/connection policy and delegates record interpretation to
`portal_llm_history.py`.

`portal_llm_history_api.py` owns bounded page and page-size parsing,
role-complete snapshot orchestration, short-lived cache composition, public
history counters, and first-page-only live-run projection. Its source bundle
keeps JSONL access, database readers, reconciliation policy, live discovery,
record decoration, and the concrete cache lifetime independently replaceable.
The portal retains runtime wiring and compatibility facades.

`portal_soc_alert_status_write.py` owns single-alert analyst-status input
validation, stale legacy bulk-payload rejection-by-no-op, acknowledgement count
inheritance, bounded reasons, production alert-store delegation, explicit
offline-DR write authorization, and independent-review suppression gates. Its
source bundle keeps clocks, database reads/writes, alert-store transport, and
current status rendering outside the policy. The portal retains those runtime
resources and a compatibility facade.

`portal_soc_alert_status_store.py` owns analyst-status normalization, legacy
and current SQLite schema creation, additive adjudication-column migration,
merge-safe group-state upsert/delete operations, grouped repeat-count reads,
manual-escalation alias recovery, active-group visibility, and stale-
acknowledgement reopening while durable suppressions remain active. Fast
summary reads retain legacy-alert fallbacks, and stable-group alias expansion is
bounded in 500-ID chunks. Its source bundle exposes table discovery, canonical
group-key SQL/identity, and the clock; database location, connection and retry
policy, production alert-store delegation, and JSON mirror persistence remain
outside this repository boundary.

`portal_soc_alert_status_service.py` owns database-authoritative status reads,
absence-only JSON disaster-recovery fallback, offline batch transaction
orchestration, bounded transient-SQLite retries, and post-commit atomic JSON
mirroring inside the status write lock. Its source bundle exposes paths,
connection contexts, repository operations, the clock, UUID generation, lock,
sleep, and retry settings. The portal retains runtime construction and its
stable compatibility facade; production mutation authorization remains in
`portal_soc_alert_status_write.py`.

`portal_soc_adjudication_policy.py` owns canonical analyst outcome and factored
verdict enumerations, legacy verdict projection and derivation, impossible
factor-combination detection, bounded human-review fields, duplicate-reference
validation, and incident-resolution requirements. It is pure policy shared by
the alert and incident write facades; HTTP routing, case lookup, database state,
and append-only alert-store transport remain outside the module.

`portal_soc_adjudication_history.py` owns bounded read-only adjudication history,
dashboard-to-stable group resolution through alias and representative-alert
metadata, newest-first ordering, and alert-versus-incident review composition.
Its source bundle exposes the connection/schema adapters and existing review
models, leaving database location, connection policy, and public route wiring in
the portal.

`portal_soc_pcap_request_policy.py` owns deterministic PCAP request identities,
candidate-plus-analyst override semantics, required endpoint/time validation,
bounded ports and capture windows, protocol normalization, and bounded request
metadata. Its only injected dependency is canonical timestamp normalization;
database candidate lookup, queue persistence, and alert-store dispatch remain
separate runtime concerns.

`portal_soc_pcap_request_store.py` owns schema-adaptive grouped-alert candidate
lookup, optional representative-alert enrichment, bounded capture-file recovery
from raw event JSON, and idempotent pending-queue insertion/requeue behavior.
Its source bundle exposes schema inspection and the clock; connection ownership,
request policy, and production alert-store dispatch remain outside the store.

`portal_soc_pcap_request_service.py` owns PCAP request group validation,
production alert-store delegation, queued response metadata, and the explicit
API-disabled fallback that composes candidate lookup, normalization, and durable
queue insertion. Its callback bundle keeps connection ownership, transport,
policy, and repository implementations independently replaceable.

`portal_soc_action_service.py` owns manual SOC analysis queueing and Incident
Response escalation orchestration. It validates dashboard group identities,
bounds analyst-supplied limits and descriptions, preserves exact controlled-
dispatch identity and route fields for authoritative alert-store validation,
maps transport conflicts and availability failures, and projects queued public
status metadata. Its source bundle keeps transport, API error rendering, the
clock, and concrete alert-store exception types outside the service boundary;
the portal retains stable compatibility facades for existing callers.

`portal_cron_failures.py` owns bounded Hermes cron-failure collection and
escaped Administration rendering. It treats run-level Markdown output as
authoritative evidence, uses `jobs.json` only as a latest-error fallback,
deduplicates matching runs within five seconds, redacts collected detail, and
bounds both discovery and rendered output. An explicit source bundle supplies
the two storage roots plus timestamp, formatting, and redaction callbacks.

`portal_n8n_container_status.py` owns the bounded n8n Administration health
record. An explicit source bundle exposes Docker and curl execution, time,
formatting, environment, container identity, and health URL. The service
projects only state, healthz, restart policy, start time, and bounded errors;
Docker configuration and environment values are never returned. The portal
retains executable/path selection and the public compatibility function.

`portal_pcap_health.py` owns the PCAP workflow System Health read model. It
aggregates request and outcome counts, artifact storage, active-transfer
heartbeats, bounded serial-queue grace, relay capture-protection state, recent
failures, stale-work warnings, and generated analysis metadata through an
explicit source bundle. `report_portal.py` retains the public response facade
and supplies its existing database, timestamp, JSON, filesystem, and transfer-
duration callbacks, preserving API compatibility while isolating health policy
from HTTP routing.

`portal_beacon_history.py` owns the System Health beacon window, timestamp and
status normalization, relay-recovery failure projection, chronological order,
success counts, and closed/open heartbeat-gap derivation. The portal facade
retains bounded source selection and JSON reads, current time, Alert Store
pipeline collection, PCAP health composition, and timestamp callback binding.

`portal_home_dashboard.py` owns the Mac Studio LAN Portal home-page view model,
explicit report-card discovery, metric severity presentation, escaping, and
HTML rendering. `portal_home_dashboard_assets.py` owns its stable CSS and
automatic/manual metric-refresh JavaScript. `report_portal.py` retains the
legacy `render_home` signature as a thin facade and injects the existing uptime,
update, backup, disk, timestamp, and report-discovery callbacks; the renderer
cannot scan reports, read host state, or execute refresh actions server-side.

`portal_dhcp_discovery.py` owns the pure reconciliation of bounded passive DHCP
observations against current authoritative Asset Inventory identities. It
normalizes IP, hostname, MAC, time, lease and collection metadata; classifies
exact, stable-identity, ambiguous, conflicting, candidate and stale evidence;
bounds every public field; and preserves the distinction between passive
observations and authoritative facts. `report_portal.py` retains state and
inventory loading and injects the shared asset-state, public-record, timestamp,
formatting and MAC-scope policies through a thin response facade.

`portal_soc_review_metadata.py` owns the SOC-alert review read model. It selects
the latest SOC-only analysis for stable or legacy alert identities, merges the
persisted or embedded second opinion, applies the latest matching human
adjudication, and derives evidence freshness, coverage, disagreement,
authorization, and final-review status. `report_portal.py` retains the
read-only SQLite lifecycle and public compatibility facade while injecting
schema, identity, outcome-label, and timestamp policies explicitly.

`portal_soc_evidence_metadata.py` owns the page-bounded SOC evidence summary.
It initializes explicit empty states, projects retained-artifact fallbacks,
de-duplicates durable PCAP artifacts, selects the latest SOC-only detection
outcome, and invokes the review and incident metadata ports once per page.
`report_portal.py` retains the public facade and injects table discovery,
identity, labeling, defaults, and downstream metadata callbacks; the composer
does not open databases, scan artifact directories, or perform network access.

`portal_soc_incident_metadata.py` owns SOC-to-Incident-Response routing state.
It resolves legacy and alert-derived stable identities, performs one bounded,
schema-tolerant case query, selects the newest case per dashboard group, and
projects explicit linked-case and agent status fields. `report_portal.py`
retains its compatibility signature (including the historical unused rows
argument) and injects table-discovery policy without opening additional
connections or introducing per-row queries.

`portal_soc_alert_presenter.py` owns the pure public API projection for one SOC
summary row. It normalizes occurrence counts, optional payload/enrichment
fields, analyst status, and precomputed AI, PCAP, review, and incident metadata
through explicit callback ports. `report_portal.py` retains the public function
signature and binds existing status policies; the presenter performs no
database, filesystem, process, or network access.

`portal_soc_ai_status.py` owns SOC AI-status precedence and reconciliation. It
gives pending reanalysis prompts and actual analysis artifacts priority over
retained UI state, preserves historical analyses below a newly raised severity
threshold, requeues stale eligible states, and emits explicit test, filter, and
threshold skip reasons. `report_portal.py` retains filesystem/database-backed
artifact discovery and static report loading as injected ports; the policy
module performs no direct I/O.

`portal_soc_pcap_status.py` owns page-bounded PCAP request-state aggregation
and analyst-facing status precedence. It indexes the newest durable request by
group, alert, and request identity; recognizes capture-file-aware no-packet
results; distinguishes retryable legacy requests, parser-pending work, hard
failures, and parsed Zeek/TShark evidence. `report_portal.py` retains the public
facades and injects table discovery and group identity policy.

`portal_soc_pcap_artifacts.py` owns parsed-artifact admission, de-duplicated
capture identity and byte indexing, and newest group-record selection. Its
filesystem operations are injected through `PcapArtifactSources`, malformed or
unparsed historical artifacts remain isolated, and the shared admission rule
requires capture files plus Zeek or TShark output. `report_portal.py` retains
the cache boundary and concrete runtime-directory adapters.

`portal_soc_pcap_renderer.py` owns bounded, escaped HTML presentation of parsed
PCAP evidence. It renders summary identity, record counts, at most ten values
per Zeek category, at most two TShark samples, and size-bounded JSON while
explicitly excluding raw packet payloads. Runtime paths are reduced to a
basename and all evidence-controlled text is escaped before rendering.

`portal_soc_enrichment_status.py` owns pure public-enrichment status and count
projection. Its explicit precedence is completed records, errors, skipped
sources, pending documented indicators, then no evidence; malformed envelopes
degrade to an explicit empty state. The module accepts stored JSON or mappings
and performs no database, filesystem, process, or network access.

`portal_soc_ai_artifact_context.py` owns page-scoped correlation of durable SOC
AI artifacts to dashboard groups and selects the newest detection outcome across
each representative alert and its grouped members. `report_portal.py` retains
artifact-index caching and injects one bounded member lookup plus dashboard
identity policy; the correlator performs no database, filesystem, process, or
network access and degrades malformed artifact metadata to explicit empty state.

`portal_soc_ai_artifacts.py` owns compact prompt and analysis artifact indexing.
It records only newest modification times and detection outcomes, accepts all
filesystem operations through `AiArtifactSources`, preserves the last known
outcome when a newer incomplete artifact has none, and isolates malformed or
missing files. The same repository owns single-alert newest-time fallback and
deterministic representative/member analysis resolution through injected group
and modification-time ports. `report_portal.py` retains the shared cache,
bounded SQLite member lookup, and runtime-directory policy, including the
legacy same-parent requirement for prompt discovery.

`portal_soc_group_query.py` owns the grouped SOC page snapshot model, page-level
AI/PCAP/evidence orchestration, per-row presenter invocation, and stable public
response envelope. It also normalizes request aliases once and builds the
parameterized summary-table and legacy window-function query plans, preserving
their intentional filter differences. The module owns analyst/backend status
matching, stable cursor filtering, exclusions, full-query active/severity and
endpoint metrics, page clamping, enrichment invocation, and next-cursor
construction. Its explicit dependency ports ensure each metadata source is
loaded once per page and shared across all rows.
`report_portal.py` retains allowlisted sort/severity parsing, concrete caches,
settings, status/enrichment readers, metric adapters, read-only SQLite execution
and the compatibility facade; the service performs no direct database,
filesystem, process, or network access.

`portal_soc_group_enrichment.py` owns normalized bounded group-key selection,
the parameterized best-enrichment window query, repository-row projection, and
page merge policy. Quality precedence remains completed records, errors,
skipped sources, then other data before newest-event and alert identity ties;
embedded representative enrichment is never overwritten. `report_portal.py`
retains read-only SQLite execution and returns unchanged rows if the enrichment
repository is unavailable.

`portal_soc_metrics.py` owns the grouped SOC metrics query plan, manual-
escalation exclusion, observation-volume projection, public metrics envelope,
and analyst-status count envelope. The query plan keeps both the summary-table
hot path and raw-alert fallback parameterized and explicit, while status
composition preserves the database-unavailable JSON fallback. `report_portal.py`
retains timestamp parsing, read-only SQLite execution, PCAP directory sizing,
status loading, and group-identity adapters.

`portal_live_revisions.py` owns opaque deterministic revision hashing, bounded
file identity signals, schema-tolerant revision-row reads, and the Incident
Responder live-state repository across cases, groups, alerts, analyses,
reviews, adjudications, and the newest reanalysis run. It returns only a digest
to the browser. `report_portal.py` retains runtime path policy, database
connection creation, schema introspection adapters, and composition of the
cross-page revision envelope.

`portal_soc_read_dispatch.py` owns transport-neutral dispatch for classified
SOC Analyst and Incident Responder JSON reads. It preserves query aliases,
encoded grouped-alert responses, settings readiness status, model refresh
flags, resource identifiers, adjudication limits, and incident-to-group error
translation through explicit callbacks. `PortalHandler` retains route
classification, SSE streaming, JSON serialization, security headers, and
socket writes.

`portal_soc_write_request.py` owns same-origin authorization and JSON-shape
policy for classified SOC Analyst and Incident Responder writes before calling
the bounded operation dispatcher. It intentionally preserves strict review
JSON errors, the reanalysis object requirement, lenient legacy alert-action
fallback, and success-only cache invalidation signals. `PortalHandler` retains
header/origin evaluation, request-size enforcement, response serialization,
cache mutation, and socket writes.

`portal_software_inventory_service.py` owns bounded pagination of the complete
public Asset Inventory used for identity labels, the allowlisted PostgreSQL
query projection, incomplete-inventory warnings, and enrichment of visible
software rows with unambiguous labels and endpoint OS associations. The portal
retains PostgreSQL transport, collector snapshot path/size policy, current-time
selection, and the existing validated evidence functions from
`software_inventory`.

`portal_asset_inventory_service.py` owns time-aware authoritative record
projection, public-field filtering, allowlisted PostgreSQL query parameters,
display-only overlay application, and local disaster-recovery response
composition. `portal_asset_dhcp_overlay.py` separately owns passive DHCP
observation parsing, lease-aware freshness, exact-IP MAC evidence annotation,
stable-identity matching, and conflict-safe provisional asset policy. Passive
DHCP evidence remains distinct from authoritative identifiers: an unambiguous
hostname or MAC may update the displayed current address, while IP-only or
conflicting claims remain review-only. `report_portal.py` retains bounded
file/database loading, runtime clocks, timestamp compatibility, and the public
facade functions used by existing integrations.

`portal_asset_repository.py` owns PostgreSQL snapshot caching and validation,
bounded disaster-recovery file reads, explicit missing/invalid/unavailable
states, and bounded DHCP state validation. Production database failures remain
fail-closed and never fall back to a competing file source. Event-time IP
resolution lives in `portal_asset_inventory_service.py` and performs input
validation before invoking its injected repository port, so malformed or
non-IP observables cannot trigger storage work. `report_portal.py` retains
dynamic validator discovery and concrete runtime paths, locks, clocks, and
alert-store transport.

`portal_asset_store_client.py` owns the allowlisted loopback mutation routes,
owner/mode/symlink/size checks for the runtime environment file, selection of
only the Asset Store write token, authenticated request construction, bounded
response parsing, and downstream HTTP-status preservation. Route rejection
occurs before credential loading or network access. `report_portal.py` retains
the concrete base URL, response-size setting, environment path, and public
compatibility functions.

`portal_asset_mutation_service.py` owns bounded DHCP review, authoritative edit,
and demotion payloads; IP/MAC/hostname normalization; exact edit/demotion
confirmations; downstream status preservation; and success-only cache
invalidation. `portal_asset_write_request.py` owns same-origin enforcement,
optional Administration authentication, JSON parsing, and transport-neutral
Asset write dispatch. Same-origin rejection deliberately precedes the lazy
Administration check. `report_portal.py` retains owner-controlled credential
loading, loopback HTTP transport, concrete cache state, and compatibility
response facades.

`portal_cti_program_service.py` owns CTI workspace request orchestration:
route acceptance, same-origin-before-Administration authorization ordering,
JSON parsing, conflict/validation/storage error mapping, success-only audit
triggering, and public response projection. `cti_program.py` remains the sole
owner of workspace schema validation, optimistic revisions, credential-reference
policy, atomic persistence, and public redaction. `report_portal.py` retains the
concrete browser-origin and Administration-session checks, runtime storage
configuration, HTTP serialization, security headers, and socket writes.

`portal_soc_settings_write.py` owns the classified prompt, AI-model, and
agent-model settings write families; legacy empty-object JSON fallback;
Administration authorization; existing saver dispatch; and uniform 200/400/403
response mapping. Prompt content validation, provider/model normalization,
agent-route policy, and atomic configuration persistence remain with the
existing settings functions. `report_portal.py` retains the concrete
Administration-session check and HTTP response serialization.

`portal_admin_service_write.py` owns the service-start request shape,
Administration-before-token authorization order, action-token validation,
service identifier normalization, existing start-service dispatch, and
200/400/403 response projection. Concrete session lookup, token storage, app
launching, and live service-status checks remain in `report_portal.py`.

`portal_resource_library_write.py` owns payload normalization and dispatch for
the four classified remove, tag, rename, and favorite mutations, including
their existing 200/400 result mapping. Filesystem resolution, metadata writes,
Hermes queueing, worker triggering, and dashboard refresh remain in
`report_portal.py`. The current compatibility contract applies route
allowlisting but no Administration or same-origin authorization to these four
writes; this module makes that policy boundary visible without changing it.

`portal_soc_status_write.py` owns the compatibility `/api/soc-alerts/status`
request boundary: legacy empty-object JSON fallback, downstream mutation
dispatch, explicit error-status preservation, 400 fallback, and success-only
cache invalidation signaling. The existing `update_soc_alert_status` function
retains identifier/status validation, stale-browser safeguards, review gates,
alert-store transport, and disaster-recovery persistence policy.

`portal_admin_form_service.py` owns Administration form parsing, action-token
ordering, login/password decision flow, session creation/destruction ports,
action authorization and dispatch, cookie-header projection, and encoded
post-action redirects. Password hashing and storage, session persistence,
concrete cookie construction, action execution, HTML rendering, client-address
lookup, and socket writes remain in `report_portal.py`.

`portal_admin_read_service.py` owns Administration login/dashboard/session and
service-status read decisions, including redirect intent, query-message
projection, authentication policy, public session-status shape, and lazy
service probing. `report_portal.py` retains concrete session lookup, service
probes, HTML rendering, JSON encoding, and socket writes; its inherited
`_require_admin_auth` compatibility method remains available to dedicated
server subclasses even though the GET route uses the extracted service.

`portal_health_read_service.py` owns the legacy health JSON schema and isolated
scan-root inspection. Top-level HTML counting is iterator-based rather than
materializing file lists, and per-root filesystem failures remain visible
without failing the health response. Report discovery, runtime roots, local
address selection, timestamps, JSON encoding, and socket writes remain in
`report_portal.py`.

`portal_general_read_service.py` owns lazy dispatch and response projection for
the portal home, health, favorites, beacon history, asset inventory, DHCP
discovery, software inventory, and CTI reads. Exact-route selection invokes
only its corresponding injected callback. `report_portal.py` retains runtime
dependency composition, JSON serialization, HTML rendering, and socket writes.

`portal_post_intake.py` owns POST path acceptance, safe `Content-Length`
parsing, per-route request-size limits, and exact JSON, not-found, login, or
Administration-dashboard rejection intent. Administration authentication is
lazy and consulted only for an invalid Administration action. The HTTP handler
retains bounded body reads, form rendering, and socket writes.

`portal_json_write_service.py` owns ordered application dispatch across CTI,
Asset Inventory, SOC and Incident Response, legacy status, Settings,
Administration service, and Resource Library JSON writes. It preserves
same-origin and Administration authorization laziness and centralizes SOC
response-cache invalidation. `report_portal.py` retains concrete callback
composition, JSON serialization, Administration form handling, and sockets.

`portal_resource_action_read.py` owns asynchronous Resource Library action ID
validation, pending-state projection, and byte-preserving status reads. The
portal retains the concrete action-status directory, JSON encoding for
synthetic responses, content headers, and socket writes.

`portal_catalog_read_service.py` owns public report-index projection and lazy
dispatch of operational metric renderers. Ordinary metrics never scan the
report catalog; only the catalog index and portal-update metric invoke the
injected scan port. Report discovery and concrete HTML renderers remain in
`report_portal.py`, along with response encoding and socket writes.

`portal_catalog_delivery.py` owns traversal-safe static and report asset
resolution, file read and error policy, MIME selection, lazy report lookup,
report-open redirects, and download response projection. `report_portal.py`
retains the concrete asset roots, report discovery callback, and HTTP socket
writes.

`portal_catalog_routes.py` owns report catalog, operational metric, legacy
static alias, report view, open, and download path classification. It makes
catalog-scan requirements explicit, so unrelated metrics, static files, and
unknown requests cannot trigger an expensive recursive report-tree walk;
filesystem delivery and traversal enforcement live in
`portal_catalog_delivery.py`.

`portal_incident_read_model.py` owns the pure request and presentation policy
for durable Incident Response lists: allowlisted filters and sort fields,
bounded page sizes, parameterized status predicates, schema-aware sort SQL,
pagination, optional legacy columns, the empty-schema response, case-bound
analysis selection, shared reviewer/adjudication normalization, and
deterministic evidence, freshness, asset row composition. The portal retains
read-only SQLite and inventory-file access for legacy analysis fallback
queries; loaded records are passed into pure composers through an explicit
callback boundary.

`portal_incident_list_service.py` owns application-level list composition. It
joins the typed repository page to case-bound legacy-analysis recovery,
review-state composition, adjudication, and asset presentation while keeping
SQLite query construction, HTTP errors, and inventory-file loading outside the
service.

`portal_incident_read_service.py` owns list and detail read orchestration. It
coordinates request parsing, schema-aware empty pages, repository snapshots,
asset inventory, row composition, persisted-response decoding, review state,
report rendering, prior SOC analysis, and the stable public payload while
preserving distinct validation, missing-schema, missing-case, and database-
unavailable responses. Its dependency bundle keeps the concrete database,
inventory, policy, renderer, and portal error formatter replaceable; the portal
retains only runtime wiring and compatibility facades.

`portal_incident_actions.py` owns pure analyst-action validation and bounded
payload construction. Its first contract covers incident status transitions,
resolution-reason requirements, reviewer aliases, and field-length limits;
case existence and the append-only alert-store mutation remain portal concerns.

`portal_incident_repository.py` owns the primary Incident Response list's
read-only SQLite batches: case counts and pages, summary-versus-legacy row
selection, analysis and reviewer lookup, newest adjudication selection, and
optional-column compatibility. It also loads resilient evidence-freshness,
reviewer, and case-bound adjudication records for incident detail views, and
resolves the current Incident Responder analysis without trusting a stale or
cross-role foreign pointer. A typed detail bundle combines the case, current IR
analysis, latest prior SOC analysis, and review records while explicit lookup
errors preserve schema-unavailable versus case-not-found behavior. The module
has no HTTP, filesystem, asset-resolution, or presentation responsibility.

`portal_incident_reanalysis.py` owns bounded reanalysis-progress request policy
and read-side aggregation: normalized allowlisted run IDs, newest-run
selection, per-status case counts, requested-run case pages, missing-schema
state, and the stable progress payload. It ignores unknown durable case states
instead of allowing them to corrupt the five recognized progress buckets and
has no HTTP or mutation responsibility.

`portal_incident_review_model.py` owns pure Incident Response detail-review
presentation: evidence coverage and freshness, primary-versus-effective
outcomes, reviewer disagreement, bounded disputed fields, adjudication, and
case-resolution metadata. It also owns safe persisted-response decoding and the
stable detail API payload shape. It reuses the shared reviewer policy but has
no persistence, HTTP, filesystem, or asset-resolution access.

`portal_incident_report_renderer.py` owns escaped Incident Response report
composition: report sections, factual timelines, bounded Security Onion and
OSquery audit presentation, immutable executed-query details, and the aggregate
query count exposed to the client. `report_portal.py` retains the compatibility
entry point and injects its shared text, list, linked-finding, analyst-review,
and investigation-audit callbacks. The renderer has no persistence, HTTP,
filesystem, process, or network access.

`portal_investigation_audit_renderer.py` owns escaped presentation of the
broker-authorized interactive pivot trail. It expands stable investigation
purposes, bounds rounds and trusted queries, renders backend-specific OQL, KQL,
Elasticsearch DSL, OSquery SQL, and structured PCAP/Zeek requests, and exposes
only executed audit records. `report_portal.py` retains the compatibility entry
point and injects shared text, counter, and query-to-finding policies. The
renderer cannot execute model-authored queries and has no persistence, HTTP,
filesystem, process, or network access.

`portal_review_panel_renderer.py` owns escaped analyst-review presentation:
review freshness and coverage, primary-versus-reviewer comparison, bounded
failure and disputed-field details, factored adjudication, case resolution,
and the human-decision action state. `report_portal.py` retains the compatibility
entry point and injects shared text, outcome-label, and empty-review policies.
The renderer has no persistence, mutation, HTTP, filesystem, process, or
network access.

| Domain | Current responsibility examples | Target modules |
| --- | --- | --- |
| HTTP composition | server, handler, GET/POST dispatch | `portal.entrypoint`, `portal.routes.registry` |
| Health and administration | service metrics, Docker/n8n status, actions, backups | `portal.services.health`, `portal.services.admin`, matching routes/renderers |
| Settings and model routing | model roster, provider readiness, settings writes | `portal.services.settings`, `portal.routes.settings` |
| Assets and DHCP | overlays, review, promotion, mutations | `portal.services.assets`, `portal.repositories.assets` |
| Software Inventory | filters, PostgreSQL response, OS correlation | `portal.services.software`, `portal.routes.software` |
| SOC Alerts | group query, statuses, analysis queue, PCAP, escalation | `portal.services.alerts`, `portal.routes.alerts` |
| Incident Responder | cases, detail, reanalysis, review/adjudication | `portal.services.incidents`, `portal.routes.incidents`, `portal.renderers.incidents` |
| LLM activity | current execution, primary/reviewer/adjudication logs | `portal.services.llm_activity` |
| Logs and resources | indexed log views, file operations, resource library | `portal.services.logs`, `portal.services.resources` |
| Shared I/O | bounded HTTP, token/header checks, SQLite/PostgreSQL/filesystem access | `portal.adapters.*`, existing bounded primitives |

Route handlers validate/authorize and call one service. Services return JSON or
view models, not raw HTTP responses. Renderers escape content and perform no
I/O. Repositories own query execution and return bounded domain rows.

The following remain stable: method/path bindings, response schemas, status
codes, request limits, token/authorization requirements, cache headers, and
service identity at `/healthz`.

## Static Dashboard Builder

Current owner:
`onion-sentinel-dashboard/scripts/build_soc_alerts_dashboard.py` (4,440
lines).

| Boundary | Responsibilities |
| --- | --- |
| `components.shell` | application shell, navigation, page header/footer |
| `components.tables` | escaped tables, reactive behavior, responsive columns |
| `components.status` | badges, model/activity state, pulse and verdict styles |
| `components.forms` | settings controls, validation/error/success presentation |
| `components.evidence` | details, collapsible queries, copy controls, provenance |
| `pages.home`, `pages.reports`, `pages.alerts`, `pages.incidents` | page-specific composition |
| `pages.settings`, `pages.assets`, `pages.software` | administrative/inventory composition |
| `pages.ac_hunter`, `pages.cti`, `pages.siem`, `pages.threat_hunter`, `pages.logs` | specialist page composition |
| `dashboard.builder` | validated inputs, page registry, deterministic publication plan |

`dashboard_time_format.py` owns dependency-free ISO timestamp parsing, Unix
timestamp conversion, local display formatting, and embedded timestamp
normalization. Dashboard components can now share one explicit time policy
without importing the monolithic builder.

Page builders receive view models. They do not read SQLite, PostgreSQL,
configuration, log files, or subprocess state. Existing public page filenames,
API URLs, form field names, accessibility behavior, and navigation remain
stable. Shared CSS and JavaScript have one source of truth.

First extraction checkpoint:
`onion-sentinel-dashboard/scripts/dashboard_shell_components.py` owns the
immutable page registry, navigation icons, accessible navigation rendering,
severity-class sanitization, and placeholder-page rendering. The legacy
builder imports and re-exports those names while it remains the composition
root. The production installer copies the component beside the builder before
dashboard generation, and the modularization contract verifies both files.

`dashboard_shell_page.py` owns the immutable document shell, global SOC Alerts
styles, suppression and triage dialogs, live alert-table client, and shared
detail/timeline hydration clients. `build_html` retains runtime aggregation and
passes eight explicit, already-escaped or trusted component fragments through
`DashboardShellViewModel`; sentinel replacement avoids interpreting CSS and
JavaScript braces as a general-purpose format language.

The first page-specific checkpoint is
`onion-sentinel-dashboard/scripts/dashboard_logs_page.py`. It owns the Logs
page markup, responsive styles, and bounded lazy-viewer client behavior. The
builder re-exports `logs_page_section` for compatibility; server-side log
catalog and redaction policy remain in `application_logs.py`.

`onion-sentinel-dashboard/scripts/dashboard_software_inventory_page.py` owns
the Software Inventory page markup, evidence-language guardrails, responsive
table/card styles, filters, pagination, and reactive refresh client. The
builder re-exports `software_inventory_page_section`; inventory collection and
normalization remain behind the existing `/api/software-inventory` contract.

`onion-sentinel-dashboard/scripts/dashboard_asset_inventory_page.py` owns the
Asset Inventory and DHCP review page markup, responsive styles, paging,
operator-confirmed write dialogs, and reactive refresh client. The builder
re-exports `asset_inventory_page_section`; authorization, transactional
revalidation, collection, and persistence remain behind the existing asset
and DHCP API contracts.

`onion-sentinel-dashboard/scripts/dashboard_ac_hunter_page.py` owns the AC
Hunter behavioral-triage page markup, analyst guardrails, responsive finding
tables, normalized-field rendering, and read-only snapshot refresh client. The
builder re-exports `ac_hunter_page_section`; collection, relay transport,
normalization, caching, and verdict scoring remain in the AC Hunter backend.

The Settings client is assembled by
`dashboard_settings_assets.py` from `dashboard_settings_client_shell.py`,
`dashboard_settings_client_model.py`, and
`dashboard_settings_client_actions.py`. These bounded fragments respectively
own prompt/memory/provider setup, model-route normalization, and persistence
plus event wiring while preserving one injected client script. The builder
continues to re-export `SETTINGS_PAGE_CSS`, `SETTINGS_PAGE_JS`, and
`inject_settings_assets` until the Settings renderer receives its view-model
boundary.

`dashboard_settings_agent_card.py` establishes the first Settings renderer
view-model boundary. The dashboard builder supplies runtime-derived prompt,
model, memory, and path data through `AgentSettingsCardViewModel`; the pure
renderer owns escaping and markup for the structurally identical Incident
Responder, SIEM Engineer, Cyber Threat Intel, and Threat Hunter cards. A
separate `SocAgentSettingsCardViewModel` and renderer own the SOC Analyst card
and its automation-policy controls without moving runtime reads out of the
composition root.

`dashboard_settings_page.py` owns the complete pure Settings renderer through
`SettingsPageViewModel`, `AiProviderSettingsViewModel`, and
`MaxMindSettingsViewModel`. Bounded sub-renderers own the native harness,
Hermes, OpenClaw, MaxMind databases, agent-section assembly, and memory modal.
`settings_page_section` remains the runtime composition adapter: it reads
prompts/configuration and discovers models, normalizes those values, produces
trusted owned control fragments, and passes the resulting view model to the
page renderer.

`dashboard_incident_response_page.py` owns the API-backed Incident Responder
case queue, responsive case presentation, reanalysis controls, evidence/query
detail behavior, copy controls, sorting, pagination, and reactive refresh
client. The builder re-exports `incident_response_page_section`; incident
storage, authorization, reanalysis execution, and detail serialization remain
behind the existing `/api/soc-incidents` contracts.

`dashboard_analyst_adjudication_modal.py` owns the shared SOC/Incident analyst
decision dialog, review badges, accessible status feedback, and same-origin
append-only submission client. The builder directly re-exports
`analyst_adjudication_modal_html`; authentication, current-analysis binding,
terminal-action guards, case resolution, and adjudication persistence remain
behind the existing alert-store API contracts.

`dashboard_alert_detail_markdown.py` owns the dependency-free report Markdown
subset, inline escaping/link policy, evidence-table classification, front
matter removal, nested collapsible-section state, and deterministic HTML
rendering. Small state methods replace the former 153-line parser function;
the builder directly re-exports its established helper names so report and
detail contracts remain stable.

`dashboard_alert_detail_layout.py` owns the versioned canonical section order,
display labels, legacy aliases, immutable layout result, heading
normalization, and fenced-code-aware relocation of unknown or duplicate legacy
sections. This keeps historical Markdown from controlling the current report
structure while preserving every displaced section under Raw Logs.

`dashboard_alert_detail_values.py` owns dependency-free row and JSON access,
nested evidence lookup, Markdown-table cell normalization, empty-value
filtering, and selection of the preserved Security Onion raw event. The
builder re-exports these helpers while repository and rendering boundaries are
split in later checkpoints.

`dashboard_alert_detail_evidence.py` owns the five fixed structured evidence
domains: Security Onion metadata, network/flow, protocol, host/sensor, and
threat context. Each domain has a bounded renderer, and the compatibility
sequence remains available while canonical report composition is separated.

`dashboard_alert_detail_ai.py` owns pending and completed AI narrative,
correlation, model-provenance, and complete-response JSON sections. Explicit
field helpers preserve false boolean findings while keeping fallback and
legacy related-group handling out of the report composition function.

`dashboard_alert_detail_enrichment.py` owns embedded-versus-stored enrichment
selection, bounded evidence and limit tables, content detection, indicator
counting, and lifecycle status summaries. Its small renderers share the
dashboard timestamp and table-cell policies directly.

`dashboard_alert_detail_sections.py` owns severity resolution, authoritative
identity and summary sections, triage and analyst-note fallbacks, and complete
raw/legacy/AI JSON evidence. These core sections now accept mapping-like view
data and do not import SQLite or filesystem state.

`dashboard_alert_detail_composer.py` is the pure orchestration boundary for
the versioned Detailed Alert Report. It selects current-versus-legacy AI
evidence, composes every required section exactly once, validates generated H2
order, and returns immutable layout issues without reading runtime state.

`dashboard_alert_repository.py` is the read-only SQLite boundary for the SOC
Alerts dashboard. It adapts legacy alert-store schemas, selects rows once,
builds the PCAP request index from the same snapshot, and normalizes grouped
detections with stable keys, timelines, repeat counts, time bounds, and
enrichment carry-forward. The dashboard builder now consumes this repository
result instead of owning SQL and grouping policy.

`dashboard_alert_report_model.py` owns the shared `AlertReport` view contract
and canonical severity ordering used across dashboard pages. The builder
re-exports both during migration, giving the report factory and page renderers
a stable dependency without importing the monolithic builder.

`dashboard_alert_report_factory.py` transforms one normalized repository row
into the shared `AlertReport` model. It owns attachment labeling, endpoint and
summary normalization, canonical detail composition, and final model assembly.
An explicit `AlertReportFactoryServices` interface injects the remaining
stateful AI/PCAP status and DOM-validation services, preventing a circular
dependency on the dashboard builder while those workflow services are split
into their own modules.

`dashboard_report_repository.py` is the read-only Markdown discovery and
disaster-recovery boundary. It deduplicates configured source roots, rejects
hidden, unsupported, derived, and path-escaping artifacts, preserves explicit
later-source precedence for alert IDs, parses legacy identity/network/severity
fields, and constructs deterministic fallback `AlertReport` models when SQLite
is unavailable. The unused legacy SQLite-to-Markdown composer was removed
instead of being preserved as dead modular code.

`dashboard_ai_artifact_repository.py` is the read-only prompt/result artifact
and worker-process correlation boundary. It rejects malformed and non-object
JSON, preserves newest-per-alert precedence, stamps source metadata, separates
pure prompt/command correlation from bounded `ps` inspection, and exposes an
explicit configuration used by both report assembly and observed-model
provenance fallback.

`dashboard_alert_ai_workflow.py` owns grouped candidate selection, test/filter
exclusions, severity-floor eligibility, analysis artifact precedence, and the
running/queued/analyzed/skipped status contract. The report factory consumes
this policy directly, while the builder re-exports its public functions and
labels for compatibility with settings rendering and existing callers.

`dashboard_alert_pcap_workflow.py` owns the join between parsed PCAP artifacts,
broker request state, and grouped alert identity. It resolves analyzed,
queued/parsing, retry, no-packets, failed, and absent states and selects parsed
records by group, alert, then request ID. Runtime paths enter through
`PcapWorkflowConfig`; builder wrappers preserve the prior public call shape.

`dashboard_model_routing.py` is the dashboard adapter over the canonical
`onion_sentinel.analysis.providers.routing` package deployed at the stack root.
It preserves dashboard compatibility names and OpenClaw/Hermes safety
normalization while owning only UI-specific primary, reviewer, and adjudicator
assignment policy. This removes duplicated route parsing and identity policy
from the dashboard builder without forking the inference runtime contract.

`dashboard_ai_settings.py` owns dashboard defaults and the read-only migration
of persisted AI-provider settings. It normalizes legacy mode/roster fields,
provider executable and model allowlists, severity aliases, GeoIP path aliases,
and independent primary/reviewer/adjudicator assignments. The builder retains
only a path-aware compatibility wrapper, so runtime and test path overrides do
not leak filesystem state into the settings policy.

`dashboard_investigation_skills.py` owns discovery of the trusted harness skill
validator, fail-closed registry loading, and the escaped read-only Settings
catalog. `InvestigationSkillCatalogConfig` makes registry, validator, and home
paths explicit; the builder retains path-aware wrappers so deployed and
repository layouts use the same strict code-owned skill validation contract.

`dashboard_model_presentation.py` owns exact provider-route labels, independent
reviewer/adjudicator selector filtering, configured assignment projection, and
observed execution-provenance labels shared by dashboard activity and Reports.
It performs no settings, artifact, or process I/O; the builder reads only the
newest stamped artifact when no valid assignment exists and passes that record
into the pure projection policy.

`portal_llm_runtime_state.py` owns the live portal's corresponding execution
state projection: active-phase versus rolling-deploy fields, exact Codex CLI,
Hermes Agent, OpenClaw, and Ollama routes, provider inference, reasoning effort,
and model-free preparing/finalizing phases. It is pure and never falls back to
an assigned model when execution provenance is absent; `report_portal.py`
retains current-record collection and the compatibility import facade.

`dashboard_static_composition.py` owns the side-effect-free transformation from
the shared dashboard shell to each static route. A `StaticPagePlan` supplies
escaped route metadata, server-rendered navigation and content, while the
module preserves the SOC Alerts-only contracts and system-health navigation
without importing repositories, runtime paths, or page-specific services.

`dashboard_publication.py` owns crash-safe publication of status and beacon
JSON, lazy detail fragments, static assets, canonical page routes, and legacy
route aliases. `DashboardPublicationPaths` makes every source and destination
explicit; the builder's compatibility wrappers resolve mutable runtime/test
globals at call time and retain the existing CLI and output contract.

`dashboard_soc_shell_content.py` owns the immutable API-backed alert-table
scaffold, responsive evidence-column contract, mobile triage controls, and
resilient intake overview. The builder supplies only live severity, AI, size,
path, and report-count values before composing these pure fragments into the
shared shell.

`dashboard_flow_page.py` owns the pure data-flow renderer, enrichment-service
tiles, responsive pipeline styles, and privacy-toggle client. The builder
assembles `FlowPageViewModel` from live alert/report/model/notification metrics
and re-exports the page assets during the compatibility migration.

`dashboard_cyber_threat_intel_page.py` owns the pure CTI lifecycle workspace,
responsive styles, and revision-aware CRUD client. The builder assembles a
`CyberThreatIntelPageViewModel` from actionable local-signal counts and the
assigned CTI model; CTI persistence and authorization remain behind the
existing program API.

`dashboard_threat_hunter_page.py` owns bounded KQL, OQL, and OSQuery pivot
generation, candidate rendering, responsive styles, expansion state, copy
controls, and reactive refresh. The builder ranks reports and converts the top
candidates into `ThreatHuntCandidateViewModel` instances while compatibility
wrappers preserve the existing report-oriented helper signatures.

`dashboard_siem_engineering_assets.py` owns the SIEM Engineering base and
expanded-report styles plus the accessible, reactive recommendation-expansion
client. `dashboard_siem_engineering_page.py` owns immutable recommendation and
page view models plus the pure evidence report, tuning row, detection row, ROI,
table, and page renderers. The builder retains settings/report selection and
normalizes runtime `AlertReport` objects at the composition boundary.

`dashboard_reports_assets.py` owns the Reports page responsive activity-log
styles and reactive current-run/history client. Its live API refresh preserves
observed model, provider, reasoning effort, agent, job, phase, telemetry,
pagination, and per-agent totals. `dashboard_reports_page.py` owns immutable
current-run, activity-row, and page view models plus the pure initial renderer.
The builder retains bounded JSONL/current-state reads and converts persisted
execution provenance into those presentation models.

`dashboard_executive_home_assets.py` owns Executive Home responsive styles and
the viewer-local hour-label client. `dashboard_executive_home_page.py` owns
immutable donut, hourly-intake, cache, and page view models plus pure KPI/chart
renderers. The builder retains alert aggregation and bounded metric loading,
then normalizes those results at the composition boundary.

## Alert Store

Current owner: `n8n/alert_store/alert_store.js` (12,586 lines). The runtime
remains CommonJS during this migration.

| Boundary | Responsibilities |
| --- | --- |
| `server.js` / composition root | validate configuration, build repositories/services/routes, start/stop server |
| `routes/*` | method/path registration, auth, bounded parsing, response serialization |
| `services/alerts` | alerts, grouping, state transitions, enrichment coordination |
| `services/ai_jobs` | queue, claims, leases, completion, reanalysis lineage |
| `services/incidents` | escalation, case state, investigation artifacts/reviews |
| `services/inventory` | asset and software snapshot/import workflows |
| `services/ac_hunter` | snapshot ingestion and query |
| `services/notifications` | Telegram/outbox state and retry decisions |
| `services/health` | metrics and bounded health snapshot |
| `repositories/*` | SQLite/PostgreSQL transaction ownership and migrations |
| `jobs/*` | provider scheduler, enrichment scheduler, projectors, outboxes |

Routes never compose SQL. Services own transaction scope and idempotency.
Repositories never call HTTP or background schedulers. Existing database
schemas, migrations, shadow projection, public routes, health fields, and
controlled-evaluation allowlists remain compatible.

## Deployment Map

The current production installer copies individual files. These additions are
required before extracted code is imported in production:

| Source tree | Runtime tree | Deployment rule |
| --- | --- | --- |
| `n8n/onion_sentinel` | `$HOME/n8n-local/onion_sentinel` | staged complete-tree copy and atomic replacement |
| `onion-sentinel-dashboard/portal` | `$HOME/n8n-local/onion-sentinel-dashboard/portal` | staged complete-tree copy |
| `onion-sentinel-dashboard/pages` and `components` | corresponding dashboard runtime directories | staged complete-tree copy |
| `n8n/alert_store/routes`, `services`, `repositories`, `jobs` | corresponding `$HOME/n8n-local/alert_store` directories | install before service restart; reject incomplete tree |
| `operations/onion_sentinel_eval` | evaluation workspace only | not required by production services unless explicitly packaged |

The installer must validate imports and required files from staging before it
stops consumers. Runtime backup/restore, secret scanning, release identity, and
readiness must include the new trees. A failed package validation leaves the
old tree and services untouched.

Independent-review package construction, text/repetition policy, and
fail-closed response validation live under `onion_sentinel.analysis.review`.
The same package owns bounded shadow-adjudication package and validation
policy, while model execution and retry orchestration remain outside it.
Authorization-sensitive conclusion guards live under
`onion_sentinel.analysis.conclusions`; orchestration preserves their existing
order after factored-verdict normalization and deterministic rule validation.
Collector-owned rule-intent reconciliation is isolated in the same package,
with endpoint trust, verdict normalization, and bounded-text policy injected
from their authoritative runtime owners.
Advisory suppress/drop coherence is a separate conclusion policy module; it
records deterministic blockers and always preserves explicit human approval
as the only authority for detection-control changes.
Durable Incident Responder report schema, timeline ordering, normalization,
and canonical narrative reconciliation are isolated from query-evidence
completeness scoring so each policy can evolve independently.
Incident evidence completeness evaluates initial Security Onion collection,
iterative query pivots, and live endpoint OSQuery as separate bounded sources,
then publishes one deterministic confidence cap and ordered limiter audit.
Reviewer supplemental reconciliation is isolated under
`onion_sentinel.analysis.review`; it admits one discriminator-backed round,
rebuilds the blind package, suppresses recursion, and delegates governed query
execution through an injected interface owned by the query pipeline.
Reviewer-derived memory and automation authorization are a separate pure
policy stage; control tuning remains human-approved even when the reviewer is
high-confidence and fully agrees.
Durable investigation-round audit, exact request/result digest bindings,
bounded rejected-proposal stubs, and repair-terminal read-only completion live
under `onion_sentinel.analysis.query.audit`. The runner injects the canonical
digest and broker result-binding functions so the package cannot invent query
authority, query text, evidence, or execution outcomes.
Logical-query outcome accounting and deterministic evidence-gap publication
live under `onion_sentinel.analysis.query.outcomes`. Grouped broker envelopes,
nested partial results, zero-success runs, repaired attempts, unreported calls,
and narrowed time windows retain distinct audit semantics.
Multi-round entry, one-shot repair scheduling, and post-synthesis exhaustion
decisions live under `onion_sentinel.analysis.query.stopping` and are surfaced
through the query state boundary. They consume only bounded state and cannot
execute a model, authorize a backend, mutate evidence, or widen repair scope.
The stable `onion_sentinel.analysis.query.engine` interface owns immutable
admission, ignored-request, remaining-capacity, and repair-attempt transitions.
Every transition returns its resulting state plus bounded audit metadata; the
legacy runner consumes those transitions instead of maintaining a parallel
mutable budget ledger.
The evaluation-only missing-pivot retry lives under
`onion_sentinel.analysis.query.planning_retry`. It owns the single-attempt
instruction lifecycle, prompt-size admission, model-call recording, route
attestation, and required-request validation while receiving model and harness
operations only through injected callbacks.
Canonical per-round result handling lives under
`onion_sentinel.analysis.query.round_result`. It invokes the already-authorized
broker only through an injected callback, rejects malformed result envelopes
as read-only `invalid_response` records, preserves empty rounds, computes repair
failures before local policy rejections are merged, and cannot select or widen
query scope.
Per-round request normalization, repair-scope validation, backend admission,
semantic deduplication, and authorization enforcement live under
`onion_sentinel.analysis.query.round_admission`. Runtime authority remains in
injected ports; the package returns an immutable admission result and cannot
execute a query, call a model, access the Relay, or widen repair scope.
Bounded observable promotion lives under
`onion_sentinel.analysis.query.observables`. Only successful or partial rows
from the trusted Security Onion and PCAP/Zeek broker classes reach the injected
validator; existing and new values remain stable, deduplicated, and capped.
Deterministic repair-stage artifacts live under
`onion_sentinel.analysis.query.repair_stage`. The authoritative engine decision
is converted into bounded audit metadata, exact pending scopes, a secret-safe
single-attempt prompt artifact, and exact reconstructed requests without a
model call or any opportunity to widen query authority.
Post-query evidence synthesis lives under
`onion_sentinel.analysis.query.synthesis`. It owns follow-up metadata, stable
call identity, injected harness preflight/recording order, route attestation,
response shape validation, and terminal request accounting while model access
remains an injected port.
Durable run finalization lives under
`onion_sentinel.analysis.query.finalization`. It consumes terminal proposals,
assembles planning/repair/limit/outcome/binding audit sections, publishes
evidence gaps, and enforces the controlled-evaluation completeness gate using
only injected audit and outcome authorities.
The stable multi-round interface lives under
`onion_sentinel.analysis.query.coordinator`. It composes immutable engine
transitions and the extracted admission, execution-result, repair, observable,
synthesis, and finalization stages through explicit runtime ports. The legacy
runner is a compatibility composition root and does not own the pivot loop.
The AI lifecycle state machine lives under `onion_sentinel.pipeline`. Its
single typed runtime context exposes the ordered load, attestation, preparation,
analysis, governed-pivot, review, adjudication, guard, validation, commit, and
post-commit transitions as bounded metadata-only audit records. It owns no
provider, query, filesystem, network, database, or harness side effects.
The legacy runner functions remain compatibility delegates and inject runtime
policy explicitly, preserving existing test seams while keeping review-package
mutation and reviewer-output admission out of the composition root.

## Characterization Matrix

ARR-72 must cover at least these seams before extraction:

| Seam | Positive | Negative/failure |
| --- | --- | --- |
| Provider adapter | valid structured response and observed identity | timeout, malformed output, unavailable binary, identity mismatch |
| Query engine | authorized multi-round evidence pivot | denial, empty result, gap, repair, budget exhaustion, unavailable backend |
| Review pipeline | agreement and evidence-bound correction | material disagreement, invalid references, reviewer failure, unresolved state |
| Conclusion pipeline | supported verdict and calibrated confidence | unsupported maliciousness, contradictory endpoint evidence, coverage gap |
| Result unit of work | atomic result plus post-commit memory | precommit failure, partial artifact, index failure, restart reconciliation |
| Scheduler/job repository | priority claim and terminal completion | lost lease, duplicate runner, stale success, crash recovery |
| Harness repository/run | valid stage/event/ledger chain | invalid transition, digest mismatch, stale run, schema incompatibility |
| Portal route/service | authorized bounded response | invalid request, unauthorized mutation, oversized body, unavailable repository |
| Dashboard page/component | escaped deterministic accessible output | hostile content, missing data, narrow viewport/long values |
| Alert-store route/service | transactional idempotent result | duplicate command, rollback, concurrent claim, controlled-mode denial |

The executable coverage index lives at
`operations/quality/modularization-characterization.json`. Each seam is bound
to named positive, negative, and failure-path unittests. The index is validated
by `tests/test_modularization_characterization.py`; deleting or renaming a
contract test without updating the reviewed seam coverage therefore fails the
suite. The referenced tests remain the behavioral authority—the index is
traceability metadata, not a replacement for executing them.

## Extraction Definition of Done

An extraction issue is complete only when:

1. the destination module has one documented reason to change;
2. inputs, outputs, errors, side effects, and owner are explicit;
3. characterization tests pass against old and new implementations;
4. callers use the new interface;
5. the legacy symbol delegates or is proven unused before removal;
6. module, function, complexity, dependency, and cycle checks pass;
7. installer, backup, restore, and runtime import checks include the module;
8. secret and forbidden-runtime-file scans pass;
9. focused and full affected tests pass; and
10. the change is reversible without a database or wire-contract downgrade.

The final ARR-85 gate additionally requires full SOC/IR investigation parity,
provider identity attestation, operational SLOs, production readiness, bounded
canary, and rollback verification.
