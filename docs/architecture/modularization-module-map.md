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

- Analysis CLI option families, default-path injection, bounded runtime limits,
  generation controls, and invocation validation now live in
  `onion_sentinel.analysis.entrypoint`; the runner retains the legacy
  package-free-import-safe `parse_args` delegate.
- Controlled-evaluation discovery, exact memory-freeze enforcement, output and
  harness-database confinement, one-time token consumption, deferred-result
  reconciliation, prompt loading, role attestation, settings resolution, live
  OSQuery preparation, enrichment preparation, and evidence-contract binding
  now live in `onion_sentinel.startup` behind typed policy and port records.
- Bounded prompt-builder execution, latest-artifact selection, and concrete
  prompt-attestation port binding now live in the 100-line
  `onion_sentinel.startup_runtime_adapter`. Controlled bootstrap still occurs
  before either prompt path can run, and live runner callables are resolved at
  invocation time so fail-before-work and characterization seams remain exact.
- Controlled-evaluation runtime binding now lives in the 211-line
  `onion_sentinel.evaluation.runtime_adapter`. It projects live runner policy
  and callables into the package-owned isolation and result-identity modules,
  consumes the ephemeral mutation token before model children, confines direct
  output and temporary state to the owner-private evaluation root, rechecks
  frozen routes before Relay or model work, and requires both observed routes
  in the result. The runner retains lazy signature-compatible delegates so
  operator and characterization patch seams remain effective.
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
- `n8n/bin/local_ai_runtime_contract.py` owns the package-free import-time
  constants and classified error types re-exported by the runner namespace.
  It is direct-copied beside the runner, contains no credentials, and preserves
  pinned V1 import before the package tree is available.
- `n8n/bin/local_ai_analysis_contract.py` owns the package-free model
  transport, evidence-reference, reviewer-validation, and investigation-query
  policy tables re-exported by the runner namespace. It is direct-copied
  beside the runner and depends only on the runtime and investigation-query
  contracts, keeping both contract modules below the size-warning threshold.
- `n8n/bin/local_ai_runtime_compat.py` owns legacy runtime I/O, analysis-index,
  memory-journal, system-resource, prompt-loading, and settings delegates. The
  bounded `local_ai_compatibility_facade.py` installer rebinds extracted
  function globals to the runner namespace so existing monkeypatch and pinned
  compatibility seams remain exact without duplicating implementation.
- `n8n/bin/local_ai_dependency_compat.py` owns the legacy provider, reporting,
  primary-execution, and evidence package loaders plus their policy/dependency
  bindings. It is installed through the same facade-global seam and contains no
  provider execution, evidence mutation, or persistence policy.
- `n8n/bin/local_ai_query_dependency_compat.py` owns legacy investigation-query
  package loaders and their policy/dependency binding records. Execution,
  authorization, provenance, prompt-budget, and repair behavior remain in the
  package modules; the compatibility layer only supplies the historical ports.
- `n8n/bin/local_ai_conclusion_review_dependency_compat.py` owns legacy
  conclusion-guard, incident-report, and independent-review package loaders and
  dependency records. It contains no verdict, confidence, authorization,
  adjudication, or evidence policy beyond translating the historical bindings.
- `n8n/bin/local_ai_evaluation_routing_compat.py` owns controlled-evaluation
  route/identity delegates, model-roster normalization, runtime attestation,
  phase publication, settings loading, and provider-output parsing facades. The
  actual isolation, routing, identity, and provider policy remains package-owned.
- `n8n/bin/local_ai_evidence_compat.py` owns hosted-evidence projection,
  immutable evidence-reference, and reviewer-catalog compatibility delegates.
  It binds only package-owned evidence/review behavior and carries no collector,
  query-execution, or transport implementation.
- `n8n/bin/local_ai_investigation_compat.py` owns supporting provider-neutral
  investigation-query normalization, audit, prompt-admission, and repair
  delegates. The runner retains only the two statically verified execution and
  bounded-loop composition delegates. Every path calls package-owned policy and
  runtime adapters; the module retains the mutable pivot-loader slot solely for
  exact test and pinned-runtime compatibility.
- `n8n/bin/local_ai_provider_compat.py` owns legacy Ollama, Codex CLI, Hermes,
  OpenClaw, and provider-route transport delegates. Bounded process execution,
  credential isolation, schema construction, identity attestation, and route
  selection remain implemented in the provider package modules.
- `n8n/bin/local_ai_review_compat.py` owns legacy independent-review,
  supplemental-pivot, disagreement-adjudication, review-gate, and post-commit
  memory-plan delegates. Reviewer validation, evidence isolation, automation
  authorization, and transaction semantics remain package-owned.
- `n8n/bin/local_ai_conclusion_compat.py` owns legacy factored-verdict,
  deterministic-guard, confidence, incident-report, audit, and final-response
  delegates. `local_ai_compatibility_modules.py` provides the ordered package-free
  registry installed into the 250-line runner facade; it contains no policy.
- Concrete Markdown rendering and atomic output-publication binding now live
  in `local_ai_pipeline_adapters.write_outputs`; the runner transaction port
  delegates directly and no longer retains `render_markdown` or
  `write_outputs` compatibility symbols. The production installer and
  executable compatibility manifest direct-copy this required adapter beside
  the runner.
- Startup, memory-policy, publication, post-commit, telemetry, optional harness
  completion, and committed-output port binding also live in
  `local_ai_pipeline_adapters`. The runner now selects package stages and
  passes runtime state; the adapter alone translates legacy globals into
  package ports. The adapter remains a cohesive 478-line composition module.
- The cohesive 594-line `analysis.query.runtime_adapter` owns the concrete
  per-invocation binding of provider, governed-query, harness-observation,
  prompt admission/provenance/byte budgeting, audit/outcome accounting,
  scoped repair, deterministic planning, and coordinator ports. The legacy
  query entry point resolves limits and routes, constructs immutable records,
  and delegates without retaining a second runtime implementation.
- `analysis.query.invocation_adapter` binds the compatibility call to immutable
  invocation options, exact route/hosted prompt limits, controlled-evaluation
  observation requirements, configured/default executors, and coordinator
  dependencies without extending query or model authority.
- The 301-line `analysis.query.execution_runtime_adapter` now owns concrete
  mixed-backend execution binding, Security Onion authorization projection,
  bounded trusted-query audits, live endpoint and derived-evidence dispatch,
  and enrichment transport/credential discovery. Controlled evaluation still
  suppresses production credential discovery before checking either the live
  environment or `~/n8n-local/.env`; the runner retains thin compatibility
  delegates so existing authorization and characterization seams remain live.
- `analysis.query.request_runtime_adapter` owns concrete provider-neutral
  request normalization and the destructive consumption/translation of legacy
  PCAP and live-OSQuery request fields. Backend policy remains in the existing
  query modules; live runner callables stay dynamically bound for compatibility.
- `analysis.evidence.runtime_adapter` owns the concrete reference registry,
  columnar/hosted/transport/traversal policy binding, owner-alias disclosure,
  fixed-point hosted synchronization, result-bound references, contract
  attachment, and response-reference validation. Review catalog policy and
  collector-typed exemptions are bound by `analysis.review.runtime_adapter`.
- Model roster normalization, exact route construction/parsing, assigned/live
  metadata, external-harness route handling, and reviewer model identity now
  live in `onion_sentinel.analysis.providers.routing`. The legacy runner keeps
  thin symbol delegates for dynamic-import compatibility.
- Default settings, protected saved-settings merge, fixed Codex catalog and
  reasoning admission, Hermes/OpenClaw executable validation and resolution,
  per-role primary/reviewer/adjudicator normalization, and explicit CLI
  override binding now live in the 325-line
  `analysis.providers.runtime_adapter`. It resolves compatibility callables at
  invocation time and never reads provider credential stores or accepts shell
  fragments; the runner retains only lazy signature-compatible delegates.
- Concrete Ollama, Codex, Hermes, OpenClaw, credential-artifact, inference-lock,
  bounded-process, prompt-transport, and final provider-dispatch binding now
  lives in the 331-line `analysis.providers.execution_adapter`. Provider policy
  and observed-identity attestation remain in their existing package modules;
  the adapter resolves runner ports at invocation time so controlled TMPDIR,
  exact executable, private Hermes auth, hosted-evidence synchronization, and
  test/operator patch seams retain their established behavior.
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
- Concrete operational run-log resource projection, copy-on-write live phase
  records, atomic phase publication, best-effort phase notification, immutable
  Security Onion/appliance/live-OSQuery audit binding, disabled-by-default live
  OSQuery capability preparation, and incident-list formatting now live in the
  143-line `analysis.reporting.runtime_adapter`. All policy and I/O ports are
  resolved from live runner bindings; telemetry remains supplemental and live
  endpoint access remains role-gated and read-only.
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
- The concrete alert-store transport, controlled-result retry, spool,
  quarantine, journal stage/promotion/replay, memory-plan, and post-commit
  persistence bindings now live in the 301-line
  `analysis.persistence.runtime_adapter`. It resolves injected compatibility
  callables from the runner at invocation time, preserving test/operator seams
  and exact crash-recovery ordering without a duplicate runner implementation.
- Pure legacy-outcome canonicalization, orthogonal verdict derivation,
  model-field admission, contradiction detection, and compatibility audit
  records now live in `analysis.conclusions.verdict`.
- Evidence-reference validity, corroborating-source diversity, schema repair,
  contradictions, deterministic guard caps, incident-completeness caps, and
  confidence audit records now live in `analysis.conclusions.confidence`.
- Concrete bounded hypothesis/correlation normalization, factored-verdict and
  scope binding, trusted endpoint-gap reconciliation, deterministic evidence,
  confidence, tuning and authorization guard binding, and Incident Response
  report normalization/reconciliation now live in the 259-line
  `analysis.conclusions.runtime_adapter`. The runner retains lazy compatibility
  delegates and every dependency is resolved from live bindings so guard order,
  test seams, and fail-closed evidence behavior remain exact.
- Ordered second-opinion triggers and deterministic primary/reviewer field
  comparison now live in `analysis.review.comparison`. Consequential verdict,
  handling, escalation, and control-tuning differences remain material;
  non-escalatory context differences remain visible but advisory.
- Reviewer case precedence, blind-package evidence hashing, bounded validation
  telemetry, field-specific repair guidance, and rejected-observable-safe error
  categories now live in `analysis.review.contracts`.
- Typed-field, traversal-bounded observable, taxonomy, artifact, and detector
  shorthand discovery now lives in `analysis.review.catalogs`. Arbitrary prose
  cannot promote a foreign domain, artifact, or rule label into the review
  allowlist; the legacy runner retains compatibility delegates.
- Recursive local, reviewer-safe, and hosted evidence copying plus
  transactional fixed-point contract rebinding now live in
  `analysis.evidence.transport`; route-specific projection primitives remain
  isolated in `analysis.evidence.hosted_projection`.
- Blind package copying, anti-anchoring sanitization, operator-confirmed memory
  admission, transport-before-catalog ordering, review schema/contracts, and
  supplemental-context re-binding now live in `analysis.review.package`.
- Material-disagreement publication policy now lives in
  `analysis.review.disagreement`; validated shadow adjudication projection
  lives in `analysis.review.projection`; and required/completed review
  fail-closed automation controls live in `analysis.review.gates`.
- Reviewer route admission, prompt selection, harness-observed model attempts,
  deterministic repair, supplemental-pivot composition, comparison,
  adjudication, automation/memory disposition, failure capture, and terminal
  reconciliation now live in `analysis.review.workflow`. The legacy runner
  constructs every port at call time so existing patch seams remain stable.
- Concrete blind-package, reviewer-validation, supplemental-pivot,
  comparison, adjudication, automation-authorization, saved-response,
  configured-review, and controlled-precommit binding now lives in the
  274-line `analysis.review.runtime_adapter`. It resolves every policy and port
  from live runner bindings, strips caller-supplied runtime attestations from
  saved fixtures, and preserves strict frozen-evaluation observation and
  reviewer revalidation before commit.
- Canonical, digest-bound operator authorization validation now lives in
  `analysis.conclusions.authorization_evidence`; the runner retains private
  compatibility delegates used by characterization tests.
- Selected-event versus grouped-history disposition normalization now lives in
  `analysis.conclusions.scope`. Multi-observation history defaults to
  unresolved monitoring unless the model supplies valid scoped values, while
  invalid scope vocabulary is retained in a bounded validation audit.
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
  inert evidence and never recursively reinterpreted. The same module owns the
  stricter hosted-transport recognizer, including exact envelope keys, bounded
  string tables and row indexes, canonical counts, digest grammar, optional
  self-accounting validation, and boolean-as-integer rejection.
- Hosted evidence disclosure control now lives in
  `analysis.evidence.hosted_projection`. It owns exact positive field-path
  projection for Elastic, PCAP/Zeek, and OSQuery rows; recursive token, secret,
  path, content, and query-string redaction; empty-shell pruning; protected
  SHA-256 ancestry; compact-column preservation; and post-redaction byte
  accounting. The extracted token grammar also closes the legacy `api_token`
  key gap. The runner retains only compatibility delegates and injects dynamic
  schema, query-budget, path-sentinel, serializer, and envelope-validation
  policy.
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
  normalization, result limits, request/result digest validation, and
  capture-artifact source binding for PCAP/Zeek-derived evidence now live in
  `analysis.query.derived`.
- Bounded target selection and read-only SELECT validation for live endpoint
  OSQuery requests now live in `analysis.query.endpoint`.
- Collector-owned observable authorization, opaque target-to-case binding,
  positive row support digests, and bounded multi-round endpoint evidence
  custody now live in `analysis.query.live_endpoint`. The query boundary never
  renders reports or exposes the underlying authorized observable in a support
  binding.
- Role-scoped capability advertisement, non-sensitive case-token derivation,
  and the single bounded collect-then-reason endpoint pass now live in
  `analysis.query.live_workflow`. Deployment config discovery, collector
  transport, and model invocation remain injected composition-root ports;
  collector failure is retained as an explicit final-pass evidence gap.
- Bounded public live-OSQuery audit and row-preview projection now live in
  `analysis.reporting.live_osquery`. This reporting boundary cannot authorize
  a target, dispatch a query, or mutate the private evidence accumulator.
- Immutable Security Onion Query DSL/KQL provenance and bounded appliance
  OSQuery snapshot projection now live in
  `analysis.reporting.evidence_audits`. The module exposes collector-authored
  query identity and bounded result previews but never projects Security Onion
  hit documents or performs collector I/O.
- Assignment-versus-observed model identity, execution mode, artifact paths,
  bounded alert metadata, deduplicated PCAP byte accounting, prompt-context
  sizing, resource maxima, and active-run initialization now live in the pure
  `analysis.reporting.run_log` projection. Bounded mactop and GPU sensor
  execution, metric parsing, cooperative cancellation, and per-run maxima now
  live in `analysis.system_resources`. Atomic JSON, durable owner-only JSON,
  canonical payload digests, confined active-record names, JSONL append,
  bounded artifact reads, and bounded system-prompt loading now live in
  `analysis.runtime_io`; the runner retains only lazy compatibility delegates
  so the pinned package-free v1 import contract remains intact.
- Exact request envelopes, backend identity, deterministic query-ID fallback,
  backend parameter projection, and cross-backend drop audit now live in
  `analysis.query.request`.
- Advertised investigation backend admission and the trusted local
  prerequisites for Security Onion, PCAP/Zeek, OSQuery, and enrichment now
  live in `analysis.query.capability`.
- Cache-first public-enrichment collection, bounded record projection,
  digest-bound evidence identity, independent execution, evidence contract
  admission, result binding, and terminal error projection now live in
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
- Protocol-first Incident Responder planning now lives in
  `analysis.query.deterministic_planning`. It ranks only collector-authorized
  event tuples against the selected alert, derives fixed advertised packs and
  bounded UTC windows, suppresses semantically unsafe cross-sensor direction,
  and emits no executable query language. Digest, UTC, pack-field, role-mode,
  and agent-role policy remain injected by the legacy composition root.
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

The completed ARR-93 entrypoint is a 61-line compatibility facade.
`scheduler_facade.py` installs its historical public symbol surface from the
cohesive scheduler modules and binds adapters to the importing module's live
namespace, so source-loader tests and operational overrides remain effective.
`scheduler_runtime_compat.py` owns clock projection, owner-only maintenance
drain validation, wake/dashboard signaling, read-only reconciliation, indexed
capability detection, and the final application delegate.

`scheduler_application.py` owns the preflight-to-settlement application flow:
single-process nonblocking lock acquisition, locked initialization, repeated
selection and processing, controlled-run state projection, and final
settlement. The legacy `main()` now only binds current facade collaborators,
so tests and operational overrides retain their existing interception points.

`scheduler_composition.py` owns the late-bound port assembly for startup,
terminal recovery, claim, execution, outcome, drain, worker, settlement, and
application services. Its pure builders receive the compatibility facade's
live namespace, preserving call-time test and operator overrides without
acquiring database, network, process, or credential authority.

`scheduler_configuration.py` owns queue timestamp/group/severity SQL,
launchd-facing default projection, CLI policy assembly, AI-settings policy,
provider-lane resolution, and Codex prompt ceilings. Compatibility delegates
pass the facade's live constants and environment at call time, so saved settings
and test overrides retain the exact historical behavior.

`scheduler_selection_compat.py` owns facade-level construction of indexed and
legacy selection requests and source ports, bounded test-fixture exclusion, and
defensive durable-payload decoding. Indexed fairness and legacy artifact
freshness remain enforced by their extracted selection services; live facade
bindings preserve compatibility overrides.

`scheduler_job_compat.py` owns facade-level durable-job reporting and
reconciliation, manual reanalysis identity, immutable claim snapshot and route
binding, strict shared AI-settings loading, bounded helper execution, incident
evidence collection, prompt construction, and runner invocation. It composes
the extracted enforcement services from live facade ports; it does not weaken
claim, route, process, or artifact boundaries.

`scheduler_controlled_compat.py` owns the facade-level controlled-evaluation
policy assembly: frozen-runtime admission, ephemeral mutation-token containment,
bounded recovery transport and payload binding, owner-private artifact access,
terminal proof delegation, frozen-memory settlement, and deployed-release
attestation. Extracted controlled services remain the enforcement owners; this
module preserves their legacy signatures and call-time dependency seams.

`scheduler_cli.py` now owns the launchd-facing argument schema, runtime path
options, lane and queue controls, numeric bounds, and fail-closed controlled-
evaluation identity validation. `auto-run-ai-analysis.py` retains a thin
compatibility facade that resolves its existing mutable defaults and injects
the alert-ID, dispatch-ID, and stable-group-key policies at parse time, so
tests and operators keep the exact CLI and environment behavior.

`scheduler_controlled_runtime.py` owns fail-closed admission of a frozen
one-member evaluation worker: canonical owner-private runtime paths, exact job
pins, release and ephemeral-token attestations, loopback-only alert-store
origin, isolated temporary storage, frozen inputs, disabled live OSQuery, and
runtime-confined mutable markers. The compatibility function constructs its
policy and collaborators at call time so existing test and operator overrides
remain observable.

`scheduler_controlled_recovery.py` owns the single-spool recovery state
machine: fail-closed directory inspection, exact artifact cardinality and
filename binding, bounded owner-private loading, replay-or-terminal-proof
handling, frozen-memory settlement, and durable spool unlink. Payload
validation and read-only database proof remain injected ports, allowing their
separate extraction without weakening the crash-recovery sequence.

`scheduler_controlled_terminal_proof.py` is the read-only recovery repository.
Within one immutable SQLite transaction it loads the durable job, committed
analysis, and optional IR attempt, then proves exact job identity, cleared
lease state, frozen dispatch metadata, accepted fields, full stored-response
digest, claim binding, and role-appropriate attempt completion. Parse, schema,
or database failures return no proof and never mutate state.

`scheduler_controlled_payload.py` owns fail-closed validation of a spooled
controlled result. It binds the exact identity field set, release, dispatch,
alert, group, role, lease-derived IR attempt, independent primary and reviewer
routes, frozen-memory marker, claim digest, and completed reviewer response,
then produces the immutable recovery projection and both response digests.
The scheduler facade injects route patterns and canonicalization policies.

The controlled storage compatibility boundary is split into three small,
layered modules. `scheduler_javascript_compat.py` implements bounded ECMAScript
trim, truthiness, string conversion, UTF-16 truncation, JSON number rendering,
Unicode escaping, and object-key ordering. `scheduler_controlled_canonical.py`
uses those primitives to mirror alert-store timestamp normalization and
canonical JSON hashing. `scheduler_controlled_acceptance.py` projects and
compares every immutable `recordAiAnalysisResult` field. This isolates the
cross-runtime parity code from scheduler orchestration while retaining facade
imports for compatibility.

`scheduler_controlled_artifacts.py` is the recovery filesystem repository. It
accepts only canonical descendants, owner-only directories, and bounded
owner-only non-symlink JSON files. Frozen-memory settlement additionally
requires the exact task schema, analysis ID, submitted-response digest, and
two explicitly disabled empty candidate lanes before unlinking and fsyncing
the containing directory. The facade supplies the current effective UID and
retains the legacy call signatures used by the recovery state machine.

`scheduler_controlled_result_client.py` owns controlled replay transport to
alert-store. It sends one byte-stable compact JSON body, bounds attempts and
receipt size, retries transport/5xx/408/425/429 failures, treats HTTP 409 as
indeterminate pending terminal database proof, rejects other client errors,
and accepts only a receipt with the exact analysis ID, submission digest, and
well-formed stored-response digest. Mutation headers remain an injected port
so the ephemeral controlled-evaluation credential stays in the facade.

`scheduler_controlled_release.py` reads the deployed commit attestation from
an authoritative process value or a bounded literal, non-symlink `.env` file;
it never evaluates shell syntax and rejects missing, malformed, duplicate, or
oversized values. `scheduler_controlled_claim_contract.py` derives non-secret
IR attempt IDs and binds controlled candidates to an exact durable job,
release, frozen dispatch identity, canonical enabled primary/reviewer routes,
and distinct reviewer model. Settings loading, stable-key policy, and the
facade's public rejection type remain injected ports.

`scheduler_ai_settings.py` is the scheduler's fail-closed projection of the
untrusted AI settings document. It performs bounded UTF-8 object loading,
derives hosted Codex/Hermes lane roles without admitting OpenClaw's local GPU
routes, detects Codex use across primary/reviewer/adjudicator assignments,
applies the saved automatic-analysis severity floor, and builds the strict
normalized-plus-raw snapshot used by controlled route binding. The canonical
runner parser and bounded reader are injected so scheduler and runner retain
one normalization contract.

`scheduler_artifact_repository.py` owns the pre-indexed scheduler's read-only
filesystem artifact index. It tolerates malformed or concurrently removed
legacy JSON files, resolves prompt packages through current database grouping,
retains deterministic fallback grouping for aged-out alerts, compares AI
analysis freshness against alert- and group-scoped PCAP and prompt evidence,
prefers stable V2 group identities during reconciliation, and reuses a prompt
only while it remains newer than matching parsed PCAP evidence. The scheduler
facade retains compatibility delegates while indexed deployments remain
independent of this upgrade-window repository.

`scheduler_legacy_reconciliation.py` owns the pre-indexed durable-job cleanup
projection. It enumerates pending AI intent, preserves active legacy and V2
alias identities, identifies only truly orphaned queue keys, and permits
artifact completion reconciliation only for a previously started job without
fresh evidence or an explicit rerun latch. Older durable-job schemas retain
their historical compatibility behavior. The combined projection depends on
the artifact repository but remains read-only; alert-store owns every status
mutation.

`scheduler_prompt_builder.py` owns bounded prompt-package preparation. It
projects scheduler and job inputs into the trusted builder argv, clamps legacy
related/PCAP limits, binds role-specific prompts and memory, carries incident
evidence and blind-reanalysis intent, preserves only the bounded terminal
diagnostic on deterministic builder failure, and accepts output only when the
published path exists inside the configured prompt directory and fits the
role-aware initial package budget. The facade injects mutable defaults and
process execution at call time for compatibility.

`scheduler_runner_invocation.py` owns the analysis runner argv, role-specific
prompt and evidence-policy paths, the multi-turn outer watchdog, bounded child
output, and controlled-evaluation child environment projection. Ordinary jobs
continue to inherit their environment implicitly; controlled jobs alone receive
the complete frozen result identity, isolated `TMPDIR`, and a validated
ephemeral mutation token. The facade resolves mutable defaults and collaborators
at call time so existing tests, launchd behavior, and operator overrides remain
observable.

`scheduler_claim.py` owns compare-and-set processing acquisition,
server-authoritative job/alert/group replacement, controlled claim identity,
IR reanalysis-attempt binding, contention projection, and automatic-threshold
retirement. Its mutable claim receipt is populated immediately after a server
transition so any later validation error still exposes only the exact owned
lease to the outer retry/release handler.

`scheduler_claim_snapshot.py` is the read-only repository behind that
server-authoritative replacement. It validates the returned job, lease-bound
group, single representative alert, current SQLite stable identity and optional
stable key, and supported triage severity before returning an immutable
snapshot to claim orchestration. Database failures are translated without
weakening identity checks, and the facade injects stable-key and severity
policy.

The controlled claim contract owns both sides of the exact-lease boundary:
pre-claim candidate expectations and post-claim frozen-dispatch validation.
The post-claim check repeats release and enabled-route validation before
binding job, group, alert, stable-key, and dispatch identities, protecting the
window between read-only selection and atomic alert-store acquisition.

`scheduler_execution.py` owns processing-lease renewal, controlled-route
revalidation before Relay evidence collection, Incident Response evidence
collection, fresh indexed versus reusable legacy prompt selection, assigned
agent-role projection, controlled result identity, and runner dispatch. Its
explicit request and source bundles keep evidence and inference effects
testable while the launchd wrapper binds mutable runtime collaborators at call
time for compatibility.

`scheduler_drain.py` owns per-drain exclusions and counters, the runtime
automation-floor refresh, maintenance checks immediately before each claim,
read-only indexed-versus-legacy selection, candidate identity projection, and
the dry-run/max-attempt stop contract. Claim contention explicitly returns its
attempt slot, while completed and recovered outcomes update the shared state
used by final settlement.

`scheduler_worker.py` is the per-selection application workflow. It composes
claim, server-authoritative identity replacement, execution, process outcome,
controlled-claim rejection, and recoverable exception handling while carrying
the mutable exact-lease receipt across every failure edge. The launchd wrapper
now owns only preflight, lock lifetime, dependency binding, drain iteration,
and final settlement.

`scheduler_outcome.py` owns child-process output projection, production
completion and retryable-failure transitions, exact controlled-lease release,
and crash-safe controlled result spool recovery. It returns an explicit loop
outcome instead of controlling the drain directly, so the entrypoint retains
its established stop/continue and aggregate settlement semantics without
embedding storage or recovery policy.

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

The first ARR-86 extraction implements the policy boundary as
`n8n/bin/harness_policy.py`. It owns external-harness exclusion, role/task/run/
stage/trust identities, capability and approval policy, bounded budgets,
default-deny policy parsing, immutable authorization decisions, safe disabled
defaults, and owner-controlled policy-file loading. The legacy harness re-exports
the exact symbols; SQLite and run execution depend inward on this policy module.
The unchanged legacy `HarnessPolicy.from_dict` validator retains its exact
ratcheting allowance under the new owner and may not grow.

`n8n/bin/harness_contracts.py` owns immutable job envelopes, bounded and
secret-safe audit metadata, content-free investigation-skill attestations,
hypothesis and terminal ledger manifests, and conservative evidence-row
accounting. It depends only on `harness_policy.py` plus SQLite's read interface;
it has no database lifecycle, network, model, or query execution authority.
Unchanged legacy complexity allowances for skill attestation and job-envelope
parsing move exactly to this owner and remain ratcheting.

`n8n/bin/harness_query_contract.py` owns bounded returned-count observation,
recursive truncation detection, and exact per-query status resolution from a
Security Onion batch. Individual status is admitted only when outer response,
read-only controls, query ordering, audit ordering, query/result digests,
semantic validity, timeout state, and successful shard accounting agree. The
full outer result remains the durable provenance object.

`n8n/bin/harness_memory.py` owns the pure post-analysis memory-promotion
decision. It preserves the existing unresolved-reference, corroborating-source,
confidence, independent-review, shared-memory approval, and role-capability
gates without gaining persistence or runtime credential access.

`n8n/bin/harness_run_completion.py` owns response-ledger recording, completion
budget enforcement, post-commit memory/SLO audit events, and terminal success or
failure settlement. It composes with the run foundation and execution mixins;
the public `HarnessRun` name and method surface remain unchanged in the
217-line compatibility facade.

`n8n/bin/harness_store_foundation.py` owns hardened SQLite connection setup,
read-only preflight of existing schema versions, versioned schema creation and
migration, owner-only file permissions, committed-event audit mirroring,
idempotent hash-chain insertion, mutable-run enforcement, and atomic stage
updates. `HarnessStore` inherits this foundation so repository transactions and
the legacy class/API remain unchanged.

`n8n/bin/harness_store_run_repository.py` owns atomic run creation and collision
checks, append-only event/stage transitions, and exact evidence/evidence-contract
registration. It composes with the store foundation as a mixin; all writes retain
`BEGIN IMMEDIATE`, mutable-run checks, idempotency keys, commit-before-audit
ordering, and the original snapshot return contract.

`n8n/bin/harness_store_decision_repository.py` owns evidence-bound hypothesis
revision and decision ledger writes. It preserves backward-only revision
rejection, same-revision collision detection, citation requirements for
supported/contradicted hypotheses, bounded decision projection, canonical
response/rationale digests, and commit-before-audit ordering.

`n8n/bin/harness_store_execution_repository.py` owns atomic pre-execution
budget reservations plus immutable model-call and tool-call ledgers. Reservation
collisions, enforce-vs-shadow limits, provider/model/path/harness attribution,
read-only/query coverage, input/output digests, and commit-before-audit stage
updates retain their existing transaction and idempotency behavior.

`n8n/bin/harness_store_trace_repository.py` owns terminal settlement, bounded
snapshots, full event/hash/ledger verification, and public trace export. It
preserves terminal immutability, ledger-manifest version compatibility,
hypothesis-manifest and payload digests, event-chain continuity, constant-time
digest comparisons, and verification-before-export behavior.

`n8n/bin/harness_run_foundation.py` owns durable run identity and counters,
elapsed-time enforcement, prompt-evidence cataloguing, model preflight,
role/capability tool authorization, and atomic query-batch budget reservation.
It receives the store as a port and retains shadow-vs-enforce semantics,
approval gates, exact route binding, collision-safe reservations, and bounded
prompt evidence accounting.

`n8n/bin/harness_run_execution.py` owns phase-to-stage projection and durable
model-call/query-round observation. It preserves preflight-before-execution,
exact assigned/observed route and provider identity, full outer-result digest
provenance, per-query status binding, returned-row/truncation accounting,
evidence registration, and tool/model ledger ordering.

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

`operations/trace_evaluation_skills.py` owns trace-level extraction and strict
validation of the content-free skill-selection attestation. It validates the
started-event payload, bounded canonical skill identities, registry availability,
and exact job-digest binding through an injected hashing port. The legacy trace
evaluator remains the composition root and preserves pre-attestation trace
compatibility.

`operations/trace_evaluation_storage.py` owns read-only SQLite admission and
ledger loading for trace evaluation. It resolves only existing regular files,
opens SQLite with `mode=ro` and `query_only`, holds one consistent read
transaction, rejects newer schema versions, and exposes bounded run/table reads
without initialization or migration behavior.

`operations/trace_evaluation_integrity.py` owns deterministic hypothesis
digests, versioned terminal ledger manifests, event hash-chain validation, and
terminal-manifest binding. Manifest schemas, identity columns, terminal states,
hashing, normalization, and the error type are injected so the proof engine is
independent of SQLite and CLI concerns.

`operations/trace_evaluation_reviewer.py` owns content-free reviewer evidence
projection and the fail-closed reviewer completion contract. It binds canonical
review and supplemental calls to exact primary/reviewer decision rows, reports
material field disagreement, and validates repair and completion counts through
injected normalization ports.

`operations/trace_evaluation_model_contract.py` owns construction of the
bounded canonical model-call proof. It classifies the closed primary,
query-planning, follow-up, reviewer, supplemental, and adjudication call
grammar; enforces round sequencing and retry budgets; and emits content-free
facts plus exact violation codes through an immutable policy.

`operations/trace_evaluation_model_completion.py` owns bounded model-purpose
completion and exact repair classification. It preserves deterministic call
ordering, distinguishes valid single calls from the two authorized repair
sequences, and keeps validation failures visible unless the exact reviewer or
adjudication repair contract supersedes them.

`operations/trace_evaluation_model_routes.py` owns assigned-route authorization
and observed runtime identity proof. It indexes bounded policy events, detects
missing, duplicate, denied, mismatched, and orphaned route evidence, and verifies
collector-recorded model, provider, path, and harness identity through an
immutable policy with explicit parsing and normalization ports.

`operations/trace_evaluation_run.py` owns evaluation of one immutable harness
run. It loads bounded ledgers through an injected read-only port, projects tool,
evidence, budget, memory, reviewer, model, route, skill, and integrity facts,
derives coverage gaps, and assembles the established content-free per-run report
without owning SQLite lifecycle or CLI behavior.

`operations/trace_evaluation_output.py` owns the trace evaluator's output
boundary. It renders the stable concise terminal summary and writes complete
JSON reports atomically with owner-only permissions, a same-directory temporary
file, flush and filesystem synchronization, and cleanup on failure.

`operations/trace_evaluation_summary.py` owns cross-run trace aggregation. A
typed accumulator separates workload, model, route, tool, evidence, reviewer,
budget, memory, coverage, skill, and data-quality dimensions; small report
section builders preserve the stable aggregate JSON schema while database reads,
normalization, ratios, timestamps, and limits remain injected composition ports.

`operations/trace_evaluation_events.py` owns logical tool-query terminal outcome
resolution plus safe terminal and budget control-event projection. It preserves
failed attempts in the ledger while allowing only a later terminal success for
the same query identity to resolve a coverage gap, and derives stable legacy and
current budget operation identities without exporting response content.

`operations/trace_evaluation_contract.py` owns stable trace report schemas,
limits, manifest and run identity columns, status vocabularies, error identity,
and pure canonicalization, digest, normalization, ratio, integer, and bounded
JSON primitives. The evaluator imports these symbols as its public compatibility
surface while remaining a sub-600-line composition root.

`operations/trace_evaluation_api.py` is the reusable trace-evaluation
composition API. It binds immutable policies and explicit service ports for the
extracted storage, integrity, skill, event, reviewer, model, route, run, summary,
and output modules and retains the legacy callable surface. The executable
`evaluate-harness-traces.py` re-exports that API and owns only CLI parsing,
terminal presentation selection, exit classification, and process termination.

`operations/cohort_freezing.py` owns database-newest and exact-imported-row
cohort freezing. Immutable policy and explicit source ports bind identity
validation, read-only database snapshots, representative-alert custody,
pre-run state, execution contracts, and private digest-sealed manifest writes.
The legacy cohort command remains the composition root and preserves its CLI
and callable signatures.

`operations/cohort_http.py` owns loopback-origin enforcement, race-resistant
owner-only evaluation-token reads, bounded same-origin dashboard POSTs, and
response-body receipts. Error classes, byte limits, token syntax, and canonical
request serialization are injected by the cohort composition root so transport
cannot silently broaden campaign authority.

`operations/cohort_dispatch_contract.py` owns deterministic request projection,
dashboard acceptance validation, and durable-job payload identity checks for
analyze, escalate, and single-case reanalysis dispatches. It is transport- and
database-free; the composition root supplies stable-group identity, dispatch
digests, release validation, and fail-closed error types.

`operations/cohort_dispatch_readback.py` owns read-only post-acceptance proof
for SOC analysis, incident escalation, and single-case reanalysis. It binds the
HTTP acceptance identity to one active durable job, unchanged job payload,
exact case/run row, representative alert, and zero premature analyses before
the queue workflow may persist an accepted state.

`operations/cohort_dispatch_workflow.py` owns idempotent cohort queue state
transitions. It refuses partial/replayed cohorts, seals dispatch intent before
network I/O, persists ambiguous and rejected outcomes without retrying, and
marks acceptance only after the injected readback proof succeeds. The module
has no concrete database, HTTP, or filesystem dependency.

`operations/cohort_monitor_binding.py` re-proves accepted dispatch provenance
at every monitor observation. It rejects representative drift, durable-job or
payload replacement, cohort/release/route mutation, altered case/run identity,
and jobs predating the recorded POST window before exposing bounded job state
to terminal monitoring.

`operations/cohort_monitor_contract.py` owns durable-job timestamp ordering,
terminal-state interpretation, and the exact completed-analysis job window.
It rejects missing or malformed temporal evidence, post-terminal analysis, and
results generated before the accepted job began.

`operations/cohort_monitor_workflow.py` owns per-member and whole-cohort
terminal observation. It reconciles accepted SOC and Incident Responder jobs
with exact fresh analysis identities, case and reanalysis state, second-opinion
metadata, bounded polling, and digest-sealed monitor snapshots through injected
read-only data and time ports.

`operations/cohort_execution_skills.py` owns strict skill-selection
attestation validation and its bounded public projection. It enforces exact
skill identity fields, registry and content digests, selection limits,
mandatory readiness, and advisory-only execution without loading a registry.
The same module also validates the canonical, content-free skill summary in
offline cohort exports so collection and grading share one proof boundary.

`operations/cohort_evaluation_job_proof.py` owns deterministic dispatch
identity, accepted/read-back/completed durable-job provenance, and the exact
dispatch-to-analysis completion window used by offline grading. Regexes,
canonical hashing, stable-key validation, timestamp parsing, and error type are
injected so the module remains independent of storage, network, and CLI code.

`operations/cohort_evaluation_harness_gate.py` owns offline grading invariants
for model-call accounting, repair bounds, route failures, tool-ledger equality,
dynamic read-only query evidence, Incident Responder Security Onion coverage,
and response/chain digests. It receives canonical hashing and model-call proof
validation as ports and performs no trace, database, or network access.

`operations/cohort_evaluation_execution_admission.py` owns exact fresh-analysis
admission, accepted-once proof, primary and reviewer response-route binding,
public proof identity, harness identity, and dispatch/run timestamp freshness.
Prior-analysis lookup, digest verification, task-kind derivation, and timestamp
parsing are injected, leaving the module independent of persistence and CLI
concerns.

`operations/cohort_evaluation_result_member.py` owns validation and normalized
projection of one execution-gated cohort-export member. It binds stable-group
identity to the detection, enforces unique bounded rank and role, invokes the
execution-proof port, and emits ordered identity, detection-digest, verdict,
provider, second-opinion, and query-audit projections without file access.

`operations/cohort_evaluation_result_export.py` owns sealed export admission,
frozen selection and execution-gate validation, ordered member-set proof,
frozen-plan reconstruction, and the bounded grading projection. Hashing,
content policy, execution-contract validation, and member policy are injected;
the legacy loader is reduced to private file input plus this normalization call.

`operations/cohort_evaluation_scoring.py` owns rubric case scoring, hard-failure
application, verdict comparison, role statistics, query-safety and dangerous
action counts, shadow acceptance checks, promotion-scope warnings, and paired
cross-role comparison. All thresholds, rubric weights, verdict fields, and
promotion cohort size are supplied by an immutable scoring policy.

`operations/cohort_evaluation_workflow.py` composes the pure paired-role grading
workflow after private inputs have been loaded and normalized. It validates the
shared frozen cohort, binds independent adjudication by stable group, evaluates
both roles through injected scoring ports, and assembles the sealed report data.
Filesystem access, private output, Markdown rendering, and CLI behavior remain
outside this module.

`operations/cohort_evaluation_markdown.py` owns bounded, secret-free Markdown
presentation of sealed cohort evaluation data. It separates header, role
summary, criterion, case, finding-code, and cross-role sections so report layout
can evolve without changing grading logic.

`operations/cohort_evaluation_private_output.py` owns atomic owner-only report
output. It rejects symlink replacement and unbounded JSON, creates private
parents, fsyncs files and directories, and exposes no grading or rendering
policy.

`operations/cohort_evaluation_query_audit.py` owns content-free query-audit
summary and execution-binding proof. It normalizes unique bounded dynamic tool
bindings, validates call/round/query identity and request/result digests, counts
Security Onion and dynamic queries, and recomputes the canonical binding digest
without accepting query text or result content.

`operations/cohort_evaluation_execution_contract.py` owns exact admission of
the frozen shadow evaluation contract. It validates release and controlled
route syntax, requires an independent reviewer model, and enforces the optional
controlled-profile route pair without loading exports or grading results.

`operations/cohort_evaluation_result_policy.py` owns the metadata-only export
content gate and bounded observed-verdict projection. It rejects exports that
do not explicitly exclude sensitive payload classes and converts malformed
duplicate identifiers into a non-creditable sentinel label for scoring.

`operations/cohort_evaluation_execution_proof.py` orchestrates fresh-analysis,
durable-dispatch, public-proof, skill, identity, query, model/tool gate, and
timestamp admission through injected immutable policy. The lower-level proof
validators remain canonical in their focused modules; this layer only orders
them and returns the sealed public proof after every gate succeeds.

`operations/cohort_evaluation_contracts.py` is the canonical cohort-grading
contract surface for schemas, input/output bounds, controlled model routes,
identity patterns, verdict domains, query classes, hard failures, and rubric
weights. The evaluator API and CLI import these values rather than maintaining
independent policy copies.

`operations/cohort_evaluation_private_input.py` owns owner, mode, file-type,
symlink, size, UTF-8, JSON-root, and exact-source-digest checks for offline
evaluation inputs. It performs no grading or cohort interpretation.

`operations/cohort_evaluation_result_loader.py` composes the canonical export
and member policies for one role, then loads and normalizes the sealed export
through injected private-I/O and execution-proof ports. The CLI no longer
constructs the nested result policy inline.

`operations/cohort_evaluation_api.py` is the public sealed-evaluation workflow
boundary. It loads each role through injected result ports, validates paired
cohort identity, loads independent adjudication, binds stable groups, builds
role reports, and assembles the final report without parsing CLI arguments or
writing output files.

`operations/cohort_evaluation_service.py` configures the canonical contracts,
admission policies, scoring policy, API ports, and bounded report adapters. The
160-line `evaluate-investigation-cohort.py` executable is now only argument
parsing, API invocation, output selection, summary printing, and exit status;
its compatibility facade delegates the prior import surface to this service.

`operations/cohort_query_audit_projection.py` owns the collector-side bounded
projection of query-audit sections, trusted round queries, result metadata, and
tool bindings. It explicitly allowlists scalar provenance fields and excludes
query text and result rows. The cohort runner delegates execution-binding proof
to the canonical `cohort_evaluation_query_audit.py` implementation.

`operations/cohort_execution_proof_service.py` composes fresh-result admission,
single-trace evaluation, skill attestation, trace/route integrity, model and
reviewer proof, read-only tool/query binding, failure aggregation, and sealed
public proof rendering. Trace loading and query binding remain injected so the
runner can preserve deterministic failure-path testing and strict I/O control.

`operations/cohort_analysis_metadata.py` owns exact analysis row identity,
bounded response parsing and hashing, scalar result projection, reviewer-route
projection, and query-audit projection. Database schema enforcement and
canonical response hashing are injected by the cohort runner.

`operations/cohort_preflight.py` owns frozen representative identity,
immutable detection evidence, stable-group-key compatibility, and exact SOC or
Incident Responder pre-run-state validation. Database lookups and active-work
queries remain injected by the cohort runner so the policy stays deterministic
and independently testable.

`operations/cohort_dispatch_identity.py` owns validation and deterministic
derivation of replay-stable dispatch IDs from the frozen plan, exact member
identity, stable-group key, rank, and dispatch kind. Cryptographic primitives
and identity patterns remain injected by the cohort runner.

`operations/cohort_manifest_contract.py` owns cohort identity, agent/model
routes, stable-group keys, the immutable execution contract, ordered member
identity, and the frozen-plan digest. `operations/cohort_private_input.py`
separately owns owner, mode, symlink, size, encoding, JSON-root, and bounded
source-row checks before delegating manifest semantics to that pure contract.

`operations/cohort_runner_service.py` is the repository-only composition root
that binds the extracted freeze, manifest, dispatch, preflight, monitor,
execution-proof, and export services. The historical
`operations/run-incident-harness-cohort.py` path is a 20-line compatibility
CLI that delegates parser construction and execution to the service.

`operations/cohort_runner_cli.py` owns parser construction, command-to-service
argument mapping, summary rendering, and exit-code policy. The composition root
injects cohort operations and handled exception types, leaving the historical
executable free of application logic.

`operations/cohort_artifact_io.py` owns alert-store-compatible JavaScript
response receipt hashing plus digest-bound, atomic, owner-only JSON artifact
writes. Hash functions, digest patterns, bounds, and error types are injected;
the composition service retains compatibility wrappers for existing callers.

`operations/cohort_storage_core.py` owns existing-file SQLite admission in
read-only/query-only mode, table and column inspection, schema fingerprinting,
and cycle-safe alert-group alias resolution. The hash function and fail-closed
error type are injected by the composition service.

`operations/cohort_storage_state.py` owns read-only summary, incident-case,
durable-job, reanalysis, and analysis-identity queries plus exact SOC/Incident
Responder frozen pre-state projections and dispatch-race proof. It consumes the
storage-core policy and exposes no filesystem or HTTP behavior.

`operations/cohort_source_rows.py` owns imported source-row identity,
detection-field projection, frozen-detection comparison, and pre-state
comparison contracts. Validation patterns, exported fields, and the fail-closed
error type are injected by the composition service.

`operations/cohort_representative_state.py` owns read-only current-summary,
raw-alert representative, stable-group-key binding, and single-case lookup
operations. Storage validation, alias resolution, incident-case lookup, and
immutable evidence fields are injected by the composition service.

`operations/cohort_second_opinion_state.py` owns the approved-column,
read-only projection of second-opinion execution metadata used by cohort
monitoring and export.

`operations/cohort_runner_contracts.py` owns shared cohort schemas, limits,
identity patterns, fail-closed error types, canonical JSON hashing, constant-time
comparison, and the UTC clock used by the runner composition layer.

`operations/cohort_dispatch_adapters.py` owns the fixed loopback HTTP policy,
private evaluation-token adapter, bounded dashboard POST adapter, and pure
request/acceptance/durable-payload contract composition. Dispatch identity
functions are injected through a narrow ports object.

`operations/cohort_monitor_adapters.py` owns durable-job time-window contract
composition and the bounded read-only projection for one exact reanalysis run
case. Timestamp parsing is injected through a narrow ports object.

`operations/cohort_artifact_adapters.py` owns fixed alert-store receipt,
canonicalization, digest-binding, digest-validation, and owner-only JSON write
policies over the lower-level artifact IO module.

`operations/cohort_manifest_adapters.py` owns fixed manifest validation,
private-input admission, execution-contract, ordered-identity, frozen-plan, and
deterministic dispatch-identity policy composition.

`operations/cohort_freeze_state_composition.py` composes read-only SQLite
admission, cohort state projections, representative identity binding, and
frozen-member preflight into one bounded service used by freeze, dispatch, and
monitor workflows.

`operations/cohort_runtime_composition.py` composes bounded dispatch,
acceptance readback, terminal monitoring, analysis/query metadata, execution
proof, and digest-sealed export. The runner service re-exports this API as a
thin compatibility façade.

`operations/cohort_execution_models.py` owns model-call and reviewer execution
evidence. It validates canonical model-call facts, bounded repair sequences,
terminally successful purposes, required independent review, supplemental
review limits, and reviewer decision completeness while producing the exact
public proof projections consumed by cohort export.

`operations/cohort_execution_tools.py` owns route authorization, read-only
tool-ledger, collector query-audit, dynamic pivot, and tool-call binding proof.
It requires successful dynamic read-only evidence, exact audit-to-ledger
identity and digest equality, and Security Onion query evidence for Incident
Responder runs before producing the tool portion of an execution proof.

`operations/cohort_execution_trace.py` owns harness run identity, execution
status, role/task/correlation/alert binding, assigned routes, hash-chain and
terminal-ledger integrity, response commit digests, and dispatch-to-completion
timestamp ordering. It returns validated terminal evidence without performing
database access or rendering the final cohort proof.

`operations/cohort_execution_render.py` owns the canonical public execution
proof shape and its terminal SHA-256 seal. It accepts only already-validated
skill, model, tool, trace, and response evidence and performs no database,
filesystem, trace-evaluator, or policy work.

`operations/cohort_execution_result.py` owns fresh result admission before a
harness trace may receive credit. It binds completed analysis identity and
role, rejects frozen prior identities, proves exactly-once accepted dispatch
and temporal freshness, and validates assigned primary/reviewer routes plus
evaluation-memory freeze attestation.

`operations/cohort_export.py` owns terminal cohort admission, public member
projection, execution-proof aggregation, ordered identity and execution
contract digests, restricted-content policy, and the non-replacing private
export write. Database monitoring and per-member proof evaluation remain
injected ports so export cannot broaden evidence or campaign authority.

`operations/cohort_model_call_proof.py` is the canonical offline model-call
grammar verifier. It recomputes primary planning/follow-up rounds, exact
reviewer and adjudicator repair sequences, supplemental-review bounds, route
and purpose identity, aggregate counts, fact digests, and reviewer completion
from the exported bounded facts rather than trusting claimed proof totals.

`operations/cohort_adjudication.py` owns strict independent-adjudication
normalization. Separate stages validate top-level experiment metadata, exact
source-role coverage, unique stable cases, digest-referenced ground truth,
bounded query/telemetry codes, complete role assessments, hard-failure codes,
and rubric scores without reading cohort results or calculating grades.

`prompt_incident_evidence_projection.py` owns the model-facing, in-memory
projection of already-validated incident evidence. It applies deterministic
prefix limits to Elastic hits and OSQuery rows, records source and retained
canonical digests and byte counts, accumulates projection reasons, and rejects
collector artifacts that arrive preprojected. The legacy builder retains thin
delegates so package construction and existing integrations keep the same API.

`prompt_incident_grounding.py` owns the immutable incident prompt digest. It
removes only explicitly mutable projected sample fields, authenticates the
original Elastic-hit and OSQuery-row counts, byte lengths, and SHA-256 digests,
and binds package identity, selected alert/group, instructions, response
schema, detection validation, restricted evidence identity, response controls,
and every immutable query/execution field. Evidence validation is an injected
port and runs before the digest is admitted; missing or mismatched grounding
fails closed. The builder retains compatibility delegates for the package
compactor and existing integrations.

`prompt_builder_cli.py` owns the prompt builder's stable command-line schema,
numeric safety bounds, agent-role allowlist, and role-specific default prompt
and memory paths. The legacy `parse_args()` constructs defaults and callbacks
at call time, preserving operator overrides while removing parser policy from
the evidence and package assembly module.

`prompt_builder_io.py` owns bounded runtime-artifact reads, strict object-root
JSON loading, fail-soft embedded JSON parsing, system-prompt fallback, integer
normalization, and safe output filename projection. Byte and root-type limits
are enforced before artifacts enter prompt assembly. The builder retains its
legacy helper names as compatibility delegates and supplies environment-derived
limits and fallback text explicitly.

`prompt_builder_policy.py` owns environment-derived runtime paths and byte
limits plus immutable query-contract, pack, derived-operation, filter, regex,
and evidence-bound policy. This separates deployment configuration and query
capabilities from prompt orchestration while preserving the builder's imported
constant surface for existing callers and characterization tests.

`prompt_investigation_query_context.py` owns the split trust projection for
investigation pivots. It derives exact anchor-bound observables, typed event
tuples and sensor role semantics, a selected-alert-centered time envelope, the
hidden broker authorization context, and the separate model-visible backend
capabilities and budgets. Query-contract version policy and legacy parsing
helpers remain injected by the builder facade, preserving v1/v2 runtime parity.

`prompt_correlation_context.py` owns read-only cross-alert candidate
projection. It loads observable-index and persisted-correlation candidates,
selects one bounded representative per stable group, attaches only size-capped
collector JSON for deterministic relationship derivation, combines observable,
time, persisted, and relationship scores, and emits a prompt-safe view that
excludes raw event bodies. Database reads and trusted fact/scoring policy are
injected by the builder facade; prior analyses remain labeled hypotheses and
cannot independently create a correlation candidate.

`prompt_correlation_facts.py` owns trusted collector-field normalization and
deterministic relationship derivation. It validates canonical Community ID v1
values, bounds raw JSON before parsing, normalizes IPs, ports, protocols, DNS
answers, and timestamps, and emits only same-Community-ID, reversed-five-tuple,
or same-client DNS-answer-to-encrypted-destination relationships within strict
time bounds. Each relationship carries an interpretation limit and remains a
lead rather than evidence of authorization or maliciousness. JSON decoding and
row access are injected by the builder facade.

`prompt_authorization_context.py` owns fail-closed operator-authorization
normalization and projection. It validates bounded endpoint, rule, port,
transport, and UTC time selectors; derives the exact selected event tuple;
requires every tuple component to be covered; revalidates stored campaign
membership against the current policy; and exposes only digest-bound canonical
coverage plus bounded observations. Free-form authorization prose and operator
identity never enter prompt evidence. Database connections, row queries, row
access, alert parsing, and timestamp parsing remain injected by the builder
facade, while missing schemas and malformed records yield no trusted evidence.

`prompt_alert_projection.py` owns the bounded model-facing projection of the
selected alert and deployed detection rule. It admits only explicit alert
fields, suppresses packet-bearing or oversized message text, replaces content
values with hashes and lengths, allowlists safe numeric/boolean rule modifiers,
and exposes only state preconditions relevant to matching. Alert JSON parsing,
row access, and deployed-rule extraction remain injected by the builder facade.

`prompt_alert_group.py` owns indexed duplicate-group selection and its bounded
model-facing frequency/timeline summary. It prefers stable group identity,
falls back to suppression identity, and finally uses the exact available
legacy identity columns without scanning alerts in Python. It enforces
admitted filter statuses, test-alert policy, caller row limits, schema/query
fail-soft behavior, and a separate timeline sample bound. Schema inspection,
query execution, row access, integer normalization, test filtering, and group
key derivation remain injected by the builder facade. The module also derives
stable durable-harness lineage from collector group identity and marks manual
blind reanalysis without accepting model-authored identifiers. It also projects
the latest indexed analyst decision for that group and defaults fail-soft to an
open state when the legacy decision schema is unavailable.

`prompt_alert_queries.py` owns exact and priority-based alert selection plus
bounded related-alert history. Priority selection normalizes requested severity
levels, uses an injected local clock for the lookback, applies the test-alert
policy, and preserves severity/score/recency ordering. Related history is
limited in SQL and pivots only on the selected rule and explicit source or
destination endpoints. Query execution, filtering, row access, and time remain
injected by the builder facade.

`prompt_alert_store.py` owns the builder's small read-only SQLite adapter,
legacy-safe row access, parameterized test-alert exclusion predicate, fail-soft
table inspection, and stable duplicate-group key and digest derivation. The
builder keeps the original helper surface as compatibility delegates so the
domain modules remain independently injectable and existing runtime imports do
not change.

`prompt_detection_context.py` owns ordered preparation of the exact detection
group, deterministic investigation-skill selection, rule/playbook predicate
validation, bounded packet features, and time-aware asset resolution. Exact
rows are bound to the selected deployed rule's SID, revision, and rule digest;
rows with conflicting collector identities are excluded before packet feature
extraction. Asset candidates are derived only from explicit endpoint fields;
sensor/observer identity is never recursively promoted into endpoint evidence. The
legacy builder composition root injects every database, parser, registry, and
resolver operation; the module opens no database and reads no runtime file on
its own. Exact-group selection failures stop playbook and asset processing, and
only exact selected rows are admitted to packet validation, asset resolution,
and subsequent query planning.

`prompt_detection_facade.py` owns configured query-context policy and runtime
sources plus exact-detection, asset-observable, role-task, and model-policy
adapters. It binds immutable policy to the pure query/detection modules and
reuses the evidence facade's alert-group and parsing ports. The legacy builder
re-exports these entry points without retaining their dependency assembly.

`prompt_builder_compatibility.py` preserves the prompt builder's public helper
surface while delegating bounded I/O, SQLite access, incident-evidence
projection, mandatory grounding, and package compaction to their focused
modules. This keeps legacy callers stable without returning those concerns to
the CLI composition root.

`prompt_evidence_admission.py` owns governed admission of exact-row query
context, public-enrichment indicators, agent memory, correlation context, and
restricted Incident Responder evidence. It binds query authorization to the
selected exact detection rows, projects enrichment indicators by exact kind,
removes model-authored memory and prior correlation hypotheses during blind
reanalysis, and preserves the validate/reject/project/revalidate order for
incident evidence. All query builders, file reads, validators, and projectors
are injected by the legacy composition root; source memory and correlation data
remain unchanged by blind filtering.

`prompt_evidence_facade.py` owns the configured alert-store adapters that bind
alert grouping, selection, prior analyses, PCAP, public enrichment,
authorization, correlation, and compact alert projection to shared read-only
SQLite, parsing, and policy utilities. The legacy builder re-exports these
functions for compatibility but no longer owns their dependency assembly.

`prompt_evidence_snapshot.py` owns ordered read-only evidence collection in two
explicit stages. The core stage projects the daily rollup, grouped alert, PCAP,
public enrichment, authorization, analyst state, correlation, and compact alert
views before governed admission. The historical stage runs only after current
evidence admission succeeds, loads prior analyses before related alerts and
notifications, and skips the prior-model read entirely during blind reanalysis.
It owns the bounded latest-rollup file read and notification-log projection;
database connections, query execution, and all other projections remain
injected by the legacy composition root. Any collector failure stops all later
reads in that stage.

`prompt_package_compactor.py` owns deterministic prompt admission reduction.
It stabilizes declared serialized size, attempts lossless compact JSON first,
then applies an ordered set of bounded historical, asset, enrichment, PCAP,
memory, Elastic-hit, and OSQuery-row reductions. It preserves mandatory IR
grounding by digest, validates every incident-evidence projection, prioritizes
exact-alert PCAP evidence, and fails closed if the package still exceeds its
budget. The builder facade injects evidence validators and digest policy.

`prompt_package_orchestrator.py` owns the ordered application workflow that
collects the core snapshot, prepares exact detection context, admits trusted
evidence, builds the response contract, collects bounded history, and assembles
the final prompt-package view. Runtime ports and immutable bounds enter through
typed source and policy records; the legacy builder is now a composition root
and compatibility facade rather than the workflow implementation.

`prompt_pcap_evidence.py` owns bounded prompt-facing PCAP projection. It
classifies alert-store requests as exact-alert or stable-group-related with an
exact-alert fallback for legacy schemas, tries sanitized request-ID artifact
paths before a bounded compatibility scan, rejects unrelated artifacts,
prioritizes exact evidence, and stops at the configured evidence limit. Zeek,
TShark, sample text, file metadata, and local query indexes have explicit caps;
raw packet bodies and broker messages are never projected. Database queries,
row access, and bounded JSON loading remain injected by the builder facade.

`prompt_public_enrichment.py` owns bounded prompt-facing projection of cached
public-enrichment results. It keeps small provider responses intact, replaces
large responses with a digest-bound 16 KiB prefix, deduplicates provider
records across grouped alerts, normalizes skipped/error status, and bounds
records, indicators, and status lists. Verdict aggregation and model guidance
explicitly treat enrichment as reputation and context rather than sole proof
of compromise. Group-row access and JSON parsing remain injected by the
builder facade.

`prompt_prior_analysis.py` owns bounded historical model-output projection.
It prefers the indexed `ai_analysis_runs` record for the exact alert or stable
group and only falls back to pre-index JSON artifacts when the index is empty
or unavailable. The compatibility scan and admitted result count are explicit
bounds, invalid or oversized artifacts are skipped, and indexed results remain
authoritative whenever present. Database execution, row access, and bounded
JSON loading remain injected by the builder facade; blind-reanalysis exclusion
remains the responsibility of the historical snapshot orchestrator.

`prompt_response_contract.py` owns the model-visible instruction and response
schema contract. Static grounding, factored verdict fields, hypothesis and
memory shapes, governed query-request schema, and the incident-response report
shape are immutable module data copied per invocation. The composition root
injects only the role prompt, task, agent role, blind-reanalysis flag, exact
query-pack names, and query-contract feature flag. Incident-only grounding and
report fields cannot leak into SOC Analyst packages, and returned structures do
not share mutable state across investigations.

`prompt_role_task.py` owns immutable role-specific investigation objectives.
Incident Responder blind reanalysis replaces prior model context with human and
operator-confirmed context, while SIEM engineering, CTI, and threat-hunting
roles receive distinct bounded objectives without changing the evidence
contract. Every specialist objective distinguishes supplied evidence from
proposed work and prohibits claims of unrecorded query or response execution.
The same module owns the stable hosted-review eligibility and prompt-privacy
policy applied to every role.

`prompt_package_view_model.py` owns final model-facing package assembly. It
maps prepared core, detection, admitted, and historical subsystem results into
their exact evidence sections; merges lineage, policy, runtime-file references,
and the response contract; declares the exact context excluded
from blind reanalysis, keeps incident evidence out of SOC Analyst packages,
and fails closed when an Incident Responder package lacks validated restricted
Security Onion evidence. Collection, validation, projection, and persistence
remain outside this pure assembly boundary.

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

`portal_settings_runtime.py` owns the late-bound compatibility orchestration
across prompt and memory allowlists, AI settings normalization/persistence,
MaxMind readiness metadata, Ollama catalog inspection, and CLI/Hermes startup
readiness. It resolves all paths, locks, process/network ports, and patchable
policy callbacks through the injected facade runtime and does not import the
HTTP handler.

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
runtime configuration, timestamp compatibility, and public facade functions
used by existing integrations. `portal_asset_runtime.py` owns the remaining
asset, DHCP, and software read orchestration while resolving all host paths,
clocks, transport, and patchable compatibility callbacks through the injected
portal runtime.

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

`portal_admin_runtime.py` owns late-bound Administration action state,
singleton action launch, bounded version/update discovery, cron failure
projection, process/service probes, and allowlisted service startup. Host paths,
commands, environment, clocks, and patchable process ports are supplied by the
compatibility runtime; the module does not import the HTTP handler.

`portal_admin_session_store.py` owns Administration CSRF-token validation and
private persistence, PBKDF2 password-record validation, hashed session
persistence and expiry, and strict cookie projection. `report_portal.py`
retains the configured runtime paths and thin compatibility functions used by
the Onion Sentinel HTTP adapter.

`portal_resource_library_write.py` owns payload normalization and dispatch for
the four classified remove, tag, rename, and favorite mutations, including
their existing 200/400 result mapping. `portal_resource_library_store.py` owns
bounded PDF resolution within configured roots, filename/tag normalization,
metadata persistence, rename/removal behavior, and side-effect orchestration
through injected queue, worker, and refresh callbacks. `report_portal.py`
retains host paths, process launching, and thin compatibility functions. The
current compatibility contract applies route
allowlisting but no Administration or same-origin authorization to these four
writes; this module makes that policy boundary visible without changing it.

`portal_soc_status_write.py` owns the compatibility `/api/soc-alerts/status`
request boundary: legacy empty-object JSON fallback, downstream mutation
dispatch, explicit error-status preservation, 400 fallback, and success-only
cache invalidation signaling. The existing `update_soc_alert_status` function
retains identifier/status validation, stale-browser safeguards, review gates,
alert-store transport, and disaster-recovery persistence policy.

`portal_sse_stream.py` owns the bounded SOC-alert server-sent-event lifecycle,
exact response headers, stable revision projection, keepalive frames, and clean
socket-disconnect handling. `report_portal.py` injects the cached snapshot,
digest, clock, and sleep callbacks from its compatibility runtime.

`portal_http_handler.py` owns HTTP response framing, HEAD/GET/POST dispatch,
same-origin review-write policy, Administration session checks, and bounded
error/redirect translation. A late-bound runtime provider preserves the
existing patchable compatibility surface and the production
`OnionSentinelHandler` subclass without importing the facade or creating a
dependency cycle.

`portal_http_read_adapter.py` owns the ordered GET read chain across general,
Administration, SOC, asynchronous Resource Library, catalog, and static-file
delivery. The handler retains only HTTP framing, authentication policy, POST
intake, and delegation.

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
injected scan port. `portal_report_catalog.py` owns bounded read-only HTML
discovery, excluded-directory filtering, stable report identity,
title/category projection, deduplication, ordering, and SOC-dashboard
selection. `report_portal.py` retains the configured roots, concrete HTML
renderers, compatibility function names, response encoding, and socket writes.

`portal_metric_detail_renderer.py` owns the escaped HTML shell and operational
metric detail projections for update, backup, uptime, disk, and portal-refresh
views. It receives already-collected metrics and formatting callbacks;
`report_portal.py` retains host probes, configured paths, and compatibility
function names.

`portal_operational_runtime.py` owns late-bound uptime/fan composition, disk
usage and bounded inventory probes, backup/update health sources, relative-time
and Administration outcome labels, cron summary/menu projection, icon policy,
and passphrase-path redaction. Host paths, process execution, caches, clocks,
and formatting ports remain injected by the compatibility runtime.

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
`onion-sentinel-dashboard/scripts/build_soc_alerts_dashboard.py` is an
99-line compatibility entrypoint. Its implementation is split across bounded
`dashboard_builder_contract.py`, `dashboard_builder_settings.py`,
`dashboard_builder_report_core.py`, `dashboard_builder_reports.py`,
`dashboard_builder_pages.py`, `dashboard_builder_publication.py`, and
`dashboard_builder_runtime.py` modules. Every layer is below 800 lines and is
installed beside the entrypoint.

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

The ARR-80 compatibility facade forwards runtime-path and collaborator
overrides into each layer. This preserves legacy imports and runtime injection
while page renderers continue to receive validated view models and publication
remains behind one deterministic orchestration boundary.

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

## Investigation Query Contract

`n8n/bin/investigation_query_contract.py` is a bounded compatibility facade for
the v2 investigation-query wire contract. The governed implementation is split
into `investigation_query_schema.py`, `investigation_query_normalization.py`,
`investigation_query_authorization.py`, `investigation_query_rendering.py`, and
`investigation_query_response.py`. Dependencies flow in that order and remain
acyclic; authorization and response validation continue to fail closed.

The versioned runtime installer atomically installs the complete v2 module tree
only after the exact v2 contract is selected. The bundled v1 facade, collector,
and manifest remain frozen and byte-stable. No module receives credentials or
transport authority, and Security Onion and Relay access remain read-only.

## PCAP Evidence Processor

`n8n/bin/process-pcap-evidence.py` is a bounded CLI and import-compatibility
facade. Configuration and shared bounded utilities live in
`pcap_processor_contract.py`; database and artifact admission in
`pcap_processor_storage.py`; payload-free Zeek projection and aggregation in
`pcap_processor_zeek.py`; bounded packet/protocol analysis in
`pcap_processor_tshark.py`; and report persistence, cleanup, and orchestration
in `pcap_processor_workflow.py`.

The facade forwards legacy runtime overrides to the owning layer before each
compatibility call. Existing operator/test injection remains available without
allowing lower layers to import the facade. The installer stages every module
beside the entrypoint. Raw captures remain path-confined and read-only; derived
claims retain tool, timestamp, direction, coverage, and cleanup provenance.

## Detection Validation

`n8n/bin/detection_validation.py` is a bounded import-compatibility facade.
`detection_validation_rule.py` owns deployed-rule and alert metadata parsing;
`detection_validation_packet.py` owns bounded packet primitives and deployed
content constraints; `detection_validation_features.py` owns group evidence
aggregation; `detection_validation_policy.py` owns versioned playbooks and
deterministic predicate policy; and `detection_validation_result.py` owns the
conclusion-safe public result projection.

The dependency chain is acyclic and never points back to the facade. A rule
match remains an evidence fact rather than an independent malicious verdict.
Unsupported fields, missing coverage, negative evidence, rule identity drift,
and confidence limiters remain explicit and fail closed. The installer stages
the complete module set beside every runtime consumer.

## Alert Store

Current owner: `n8n/alert_store/alert_store.js` (12,586 lines). The runtime
remains CommonJS during this migration.

| Boundary | Responsibilities |
| --- | --- |
| `server.js` / composition root | validate configuration, build repositories/services/routes, start/stop server |
| `composition/*` | inject already-owned runtime ports and assemble route/service registries without owning policy or persistence |
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

`composition/controlled_incident_composition.js` owns the construction graph
for controlled job admission and transitions, durable incident-reanalysis
ownership and recovery, controlled retirement replay, and manual/frozen
incident dispatch. It receives persistence, transaction, queue, serialization,
identity, and runtime ports explicitly; the legacy entry point retains only
the environment-specific adapters and public compatibility functions.

`composition/application_composition.js` assembles schema installation,
domain persistence, automatic response routing, alert ingestion, and startup
recovery from explicit database, policy, service, lifecycle, and serialization
ports. SQL and transaction semantics remain in their existing service owners.

`composition/runtime_foundation_composition.js` consumes the already-validated
runtime configuration and constructs authorization, logging, disk admission,
worker signaling, scoring, enrichment, SQLite, notification, beacon, alert
group, request-admission, and PostgreSQL auxiliary owners. Controlled-runtime
validation remains in the legacy entrypoint and therefore still precedes log
or database creation; credential-bearing values are passed only to their
existing bounded adapters.

`composition/mutable_runtime_owners.js` explicitly owns the lazily initialized
durable-job queue, PostgreSQL shadow outbox/projector, pipeline metrics, and
PCAP transfer repository. Request, recovery, health, and background-worker
composition access those instances through owner functions, preserving the
existing startup sequence without sharing facade-level mutable globals.

`composition/evidence_processing_composition.js` owns PCAP request and
completion repositories, AI review/correlation persistence, post-commit
durable drains, and deferred AI-result acceptance. Incident-bound acceptance
is constructed only after controlled incident ownership exists, preserving
immutable attempt provenance without a circular module dependency.

`composition/startup_persistence_compatibility.js` owns additive SQLite column
compatibility, atomic stable-identity backfill, and the ordered schema/startup
sequence. It receives schema owners after application composition, preserving
the controlled-evaluation short circuit without entrypoint-owned migration
logic.

`composition/application_runtime_ports.js` assembles the service and lifecycle
ports consumed by application composition. Lazy durable, metrics, and shadow
owners are resolved only when their existing startup or request action runs;
the entrypoint no longer duplicates that adapter graph.

`composition/http_application_runtime.js` owns the exact public route graph,
controlled request boundary, bounded dispatcher, health runtime projection,
HTTP resource limits, scheduled workers, and service lifecycle. It consumes
the existing foundation, application, controlled, evidence, mutable, and
startup owners and remains below the 300-line entry/composition target.

`composition/application_graph_runtime.js` owns the remaining application
assembly graph: startup compatibility, PCAP policy, mutable state, evidence,
controlled incident, application services, acceptance binding, and schema
initialization. The entrypoint now retains only platform loading, runtime
configuration, foundation construction, application graph construction, and
HTTP lifecycle startup.

`lib/postgres_asset_normalization.js` owns PostgreSQL asset and DHCP input
normalization, bounded identity/provenance validation, observation freshness
and fingerprints, inventory snapshot shaping, and public asset projection.
The legacy `postgres_asset_store.js` path continues to export
`normalizeInventoryRecord` for compatibility.

`lib/postgres_asset_schema.js` owns checked-in schema installation and the
exact supported schema-version gate. `lib/postgres_asset_read_projection.js`
owns parameterized search/filter pagination, allowlisted ordering, bounded
snapshot traversal, health counts, and public PostgreSQL asset projections.

`lib/postgres_asset_inventory_repository.js` owns atomic inventory import,
versioned operator edits, identifier conflict checks, and demotion back to
preserved DHCP evidence. `lib/postgres_asset_dhcp_repository.js` owns DHCP
reconciliation, promotion, and approved IP-change transactions.
`lib/postgres_asset_health_projection.js` owns the bounded schema, inventory,
DHCP, and append-only audit health projection. `postgres_asset_store.js` is a
thin compatibility facade over these owners.

## Deployment Map

The current production installer copies individual files. These additions are
required before extracted code is imported in production:

| Source tree | Runtime tree | Deployment rule |
| --- | --- | --- |
| `n8n/onion_sentinel` | `$HOME/n8n-local/onion_sentinel` | staged complete-tree copy and atomic replacement |
| `onion-sentinel-dashboard/portal` | `$HOME/n8n-local/onion-sentinel-dashboard/portal` | staged complete-tree copy |
| `onion-sentinel-dashboard/pages` and `components` | corresponding dashboard runtime directories | staged complete-tree copy |
| `n8n/alert_store/routes`, `services`, `repositories`, `jobs`, `composition` | corresponding `$HOME/n8n-local/alert_store` directories | install before service restart; reject incomplete tree |
| `operations/onion_sentinel_eval` | evaluation workspace only | not required by production services unless explicitly packaged |

The installer must validate imports and required files from staging before it
stops consumers. Runtime backup/restore, secret scanning, release identity, and
readiness must include the new trees. A failed package validation leaves the
old tree and services untouched.

Controlled evaluation runtime admission lives under
`onion_sentinel.evaluation.runtime_isolation`. It validates the exact mode and
ephemeral token, alternate loopback alert-store origin, canonical owner-only
runtime tree and frozen files, pinned private temp directory, isolated incident
evidence route, and explicitly disabled live OSQuery configuration. The runner
retains only the compatibility return tuple and process-local temp-directory
binding.

Controlled result lease-environment consumption, durable identity and release
binding, and exact assigned/reviewer route parity live under
`onion_sentinel.evaluation.result_identity`. Lease variables are removed before
model execution, and the frozen settings file, normalized runtime settings,
and enabled-route roster must agree before Relay or model invocation.

Frozen-evaluation reviewer precommit admission now lives under
`onion_sentinel.evaluation.reviewer_gate`. It requires a distinct configured
reviewer route, a one-repair-bounded attempt history, a recordable validated
response, and an attestation bound to the current case and evidence hash before
the result may cross the persistence boundary.

Assigned-route initial model execution and harness observation now live under
`onion_sentinel.analysis.primary_execution`. It attaches the evidence contract,
rejects missing or unknown agent assignments, records both successful and
failed model calls, preserves shadow-versus-enforce observation behavior, and
verifies the observed route during controlled evaluation.

Codex CLI catalog validation, executable-path admission, Hermes/OpenClaw
harness normalization, legacy roster migration, compatibility-mode derivation,
and primary/reviewer/adjudicator assignment composition now live under
`onion_sentinel.analysis.providers.settings`. Provider credentials and process
execution remain outside this pure settings boundary.

Bounded provider runtime-artifact reads, non-symlink admission, descriptor
identity checks, strict UTF-8 decoding, and JSON-object validation now live in
`onion_sentinel.analysis.providers.artifacts`. The same boundary owns
fail-closed model-output object parsing: it accepts strict or fenced JSON and
the first independently complete object, but never repairs malformed evidence.

Independent-review package construction, text/repetition policy, and
fail-closed response validation live under `onion_sentinel.analysis.review`.
The same package owns bounded shadow-adjudication package and validation
policy. `analysis.review.workflow` now owns bounded model execution and retry
orchestration through injected provider, harness, query, adjudication, guard,
clock, and reporting ports; it reads no configuration or environment state
and directly authorizes no evidence or operational action.
`analysis.review.adjudication_workflow` separately owns frozen-reviewer versus
configured-adjudicator route selection, identity separation, harness
attestation, the two-attempt validation repair, and terminal shadow audit. All
model, clock, package, validation, and reconciliation operations remain
injected ports, and the workflow always denies automation authority.
Authorization-sensitive conclusion guards live under
`onion_sentinel.analysis.conclusions`; orchestration preserves their existing
order after factored-verdict normalization and deterministic rule validation.
`analysis.conclusions.response` owns the complete ordered response boundary:
safe schema repair, intermediate tool-protocol removal, incident-report shape
handling, closed-vocabulary checks, factored verdict normalization, every
authorization/evidence/tuning guard, scope disposition, confidence
calibration, and final report reconciliation. Runtime-specific policies and
guard implementations remain injected, making ordering directly testable.
Model-supplied correlation group admission, bounded evidence and pivot fields,
confidence repair, and deterministic episode identity now live in
`analysis.conclusions.correlation`.
Collector-owned rule-intent reconciliation is isolated in the same package,
with endpoint trust, verdict normalization, and bounded-text policy injected
from their authoritative runtime owners.
Endpoint trust decisions live under
`onion_sentinel.analysis.evidence.endpoint`. Live OSQuery facts require an
exact normalized-query digest, validated batch provenance, a supported table,
and a row/column/observable digest binding. Explicit endpoint or host evidence
collections remain a separate trusted path, while fixed Security Onion
appliance OSQuery snapshots cannot satisfy endpoint attribution. The same
module exposes only grounded fields from complete, read-only, untruncated
investigation result rows for deterministic evidence-gap reconciliation.
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
The initial protocol-first plan lives under
`onion_sentinel.analysis.query.deterministic_planning`. It is a pure,
repeatable compiler from the trusted local event tuple and advertised backend
capabilities to fixed read-only request envelopes. It does not consume model
observables, query text, credentials, filesystem state, or network access.
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
Backend-specific canonicalization of observables, UTC windows, OSQuery SQL,
derived-evidence filters, and enrichment indicators now lives under
`onion_sentinel.analysis.query.semantic_identity`. Query labels and prose do
not affect the digest used by round-admission deduplication.
Bounded observable promotion lives under
`onion_sentinel.analysis.query.observables`. The module validates exact
Security Onion response/query digests and PCAP/Zeek query/result/reference
bindings before recursively recognizing approved IP, domain, host, and user
fields. Only positive evidence rows can produce row-bound references; query
filters and unbound values cannot become pivots. Existing and newly discovered
values remain stable, deduplicated, and capped.
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
`onion_sentinel.legacy_pipeline` owns the end-to-end composition order through
explicit runtime ports and decomposed lifecycle stages. The executable `main`
remains only a lazy package delegate so staged V1 compatibility can still
import the runner before the package is installed.
The legacy runner functions remain compatibility delegates and inject runtime
policy explicitly, preserving existing test seams while keeping review-package
mutation and reviewer-output admission out of the composition root.

### SOC alert status runtime

`portal_soc_status_runtime.py` owns the late-bound compatibility wiring between
the report portal and the grouped-alert status repositories, persistence
service, JSON disaster-recovery mirror, repeat-count projection, manual
escalation state, and active-group response composition. The runtime object is
injected so compatibility callers and characterization tests can continue to
replace database, clock, retry, and repository ports without changing the
portal's public functions. Production mutations remain owned by alert-store;
the direct SQLite save path remains limited to the existing offline DR flow.

### SOC PCAP runtime

`portal_soc_pcap_runtime.py` owns the late-bound compatibility wiring for
admitted PCAP artifacts, bounded artifact caching, request-state projection,
request normalization, SQLite request persistence, and alert-store request
dispatch. Injected runtime ports preserve the existing database, clock,
filesystem, cache, and loopback service test seams. Capture evidence remains
read-only in the portal, and production request ownership remains with
alert-store.

### LLM activity runtime

`portal_llm_runtime.py` owns late-bound active-run discovery, bounded current
record reads, process liveness checks, durable SQLite history projection,
JSONL/SQLite reconciliation, reviewer and adjudicator hydration, response
caching, and history API composition. SQLite remains authoritative for
committed executions; JSONL remains bounded runtime telemetry, and observed
model/runtime identity continues to come from each independent execution row.

### Grouped SOC query runtime

`portal_soc_query_runtime.py` owns late-bound composition of grouped summary
and fallback queries, analyst-status filtering, page enrichment, AI/PCAP
evidence joins, cached JSON responses, bounded detail-fragment delivery,
metrics, and suppression history. Repository, settings, evidence, cache, and
presentation ports remain injected so the facade's compatibility seams and
failure-path tests remain effective. Paths, pagination, sorting, response
schemas, and exclusion of manually escalated incident groups are preserved.

### Incident action runtime

`portal_incident_action_runtime.py` owns late-bound SOC queue/escalation,
append-only adjudication, incident status changes, single and bulk reanalysis,
controlled-dispatch identity forwarding, progress reads, current-analysis
resolution, and adjudication-history composition. Alert-store remains the
production mutation owner. Database, transport, clock, policy, and history
ports remain injected, preserving status/error contracts and test isolation.

### Incident read runtime

`portal_incident_read_runtime.py` owns bounded incident list/detail composition,
durable review-state projection, escaped review and responder report rendering,
broker-owned query-audit rendering, prior SOC analysis rendering, and the
incident read-service dependency bundle. It preserves lazy evidence loading,
query-digest provenance, output caps, escaping, and the separation between
durable repository records and presentation.

### SOC record runtime

`portal_soc_record_runtime.py` owns raw-alert projection, page-bounded AI
artifact correlation, severity eligibility, grouped AI state, review and
incident metadata joins, evidence metadata, grouped row presentation, and
representative-alert resolution. It preserves SQLite and artifact provenance,
observed analysis state, analyst-review defaults, and late-bound repository,
clock, cache, policy, and presenter seams.

### Portal write runtime

`portal_write_runtime.py` owns bounded authenticated alert-store GET/POST
transport, owner-controlled asset-write token loading, asset mutation request
composition, cache invalidation, dispatch, and CTI callback binding. It
preserves response-size caps, error/status translation, evaluation-token
isolation, write-token isolation, and alert-store ownership of production
mutations.

### SOC core runtime

`portal_soc_core_runtime.py` owns SOC analyst-status write wiring, strict alert
identifier validation, read-only and serialized fallback SQLite connection
boundaries, time/severity/page parsing, visible severity projection, and
allowlisted sorting/cursors. Read connections remain URI read-only; fallback
writes preserve the database owner's journal mode, full transaction rollback,
busy timeout, and process-local serialization.

### SOC detail runtime

`portal_soc_detail_runtime.py` owns stable grouped-detection identity,
page-bounded enrichment projection, evidence-directory sizing, immutable detail
layout validation, escaped layout-error rendering, and canonical collapsible
section transformation. It preserves group IDs/SQL, provenance ordering, path
symlink exclusions, layout version/order, and the rule that live PCAP evidence
cannot append a duplicate out-of-order detail section.

### Portal delivery runtime

`portal_delivery_runtime.py` owns bounded JSON snapshot reads, SSE revision-only
signals, SOC event snapshot composition, acknowledgement response shaping, and
late-bound SOC/general-read/JSON-write callback bundles. It preserves cache
keys, route callback schemas, lazy query/detail delivery, same-origin and admin
authorization callbacks, alert-store write dispatch, and the rule that live
revisions contain digests rather than incident or asset records.

### Portal dashboard runtime

`portal_dashboard_runtime.py` owns metric-detail composition, protected admin
login rendering, modular administration view-model binding, and home dashboard
composition. It preserves existing HTML, authentication messaging, password
setup guidance, metric formatting, cron/admin status seams, and the public
`render_home(reports, host, port)` compatibility signature.

### Portal foundation runtime

`portal_foundation_runtime.py` owns timestamp normalization, module-instance
bound asset/DHCP/software compatibility reads, PCAP transfer-duration
projection, bounded local beacon reads, alert-store pipeline health enrichment,
and PCAP workflow health composition. It preserves same-name reload isolation,
read-source precedence, response bounds, legacy transfer derivation, and
read-only health dependencies.

### Portal access runtime

`portal_access_runtime.py` owns admin token/password/session compatibility
wiring and Resource Library metadata, queue, worker trigger, rename, tag,
favorite, removal, and cookie composition. Password material remains hashed in
the existing store; session IDs remain server-side; filenames and tags remain
normalized; resource actions remain append-only Hermes work requests with the
same admin authorization enforced by the HTTP write adapter.

### Portal catalog runtime

`portal_catalog_runtime.py` owns local-address discovery, report title/category
projection, allowlisted report discovery, SOC default selection, daily-brief
classification, human sizes, and symlink-deduplicated full artifact-library
disk usage. It preserves excluded-directory policy, standalone report inputs,
allocated-block accounting, and loopback fallback without changing catalog
routes or report IDs.

### Portal configuration composition root

`portal_runtime_config.py` owns the report portal's imports, immutable defaults,
filesystem locations, limits, route constants, service/action definitions, and
small configuration data types. `report_portal.py` re-exports those names
before binding compatibility delegates, so existing callers and tests can
still patch facade attributes without domain modules importing the entrypoint.
Both the configuration root and compatibility facade remain below the
800-line hard review threshold; the HTTP handler remains below 250 lines.

### Portal compatibility bindings

`portal_compat_bindings.py` declaratively maps legacy public names to their
domain runtime implementations, initializes per-portal caches/locks and small
presentation policies, composes incident/SOC callback bundles, and builds the
HTTP handler against the exact importing module instance. This keeps same-name
reload isolation and late-bound test overrides while reducing
`report_portal.py` to configuration re-export, binding, and startup only.

### Software Inventory state validation

`software_inventory_state.py` owns owner-controlled bounded snapshot reads,
schema and timestamp validation, evidence provenance enforcement, and normalized
state projection. `software_inventory.py` remains the package-free compatibility
facade and owns query/asset response composition; the production installer copies
both files together. Four unchanged legacy validators retain their exact
ratcheting complexity/length allowances under the new module path; those
allowances may shrink but cannot grow and are not approval for new debt.

`software_inventory_query.py` owns the fixed public filter contract, freshness
classification, safe public-record projection (including bounded User-Agent
evidence), and stable unavailable/error response shape. It depends only on the
state contract and performs no storage or network access.

`software_inventory_assets.py` owns complete-inventory identity labeling and
fail-closed endpoint operating-system correlation. Passive evidence can receive
an OS projection only through one current, high-confidence, non-DHCP static
asset association; conflicts, partial inventories, stale validity, and dynamic
address claims remain unlabeled or uncorrelated.

`software_inventory_response.py` owns bounded state-to-API composition:
time-window selection, fixed filtering and sorting, pagination, summaries,
coverage truthfulness, warnings, and revision projection. The 61-line
`software_inventory.py` facade re-exports the legacy public and private symbols
used by the portal and tests while performing no storage or response work.

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
