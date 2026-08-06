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

Current owner: `n8n/bin/run-local-ai-analysis.py` (19,462 lines).

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
`onion-sentinel-dashboard/scripts/build_soc_alerts_dashboard.py` (11,421
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

Page builders receive view models. They do not read SQLite, PostgreSQL,
configuration, log files, or subprocess state. Existing public page filenames,
API URLs, form field names, accessibility behavior, and navigation remain
stable. Shared CSS and JavaScript have one source of truth.

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
