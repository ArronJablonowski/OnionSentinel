# Untrusted Telemetry And Tool-Boundary Threat Model

Status: enforced release contract

Owner: Onion Sentinel analysis, portal, and dashboard maintainers

Tracked by: ARR-23, related to ARR-70

Applies to: Security Onion alerts, packet-derived strings, OSQuery results,
public-enrichment responses, model output, API bodies, report artifacts, and
all values crossing an investigation or presentation boundary.

## Security Objective

Onion Sentinel treats evidence as data. No alert, packet, hostname, process
field, provider response, model response, query result, or persisted report can
become an instruction, executable query, command, filesystem path, credential,
or outbound destination merely because its text asks the system to do so.

Security Onion and Relay access remains read-only. Tool authority, schemas,
budgets, credentials, destinations, and system prompts come only from trusted
repository code plus operator-controlled runtime configuration. A security
failure must fail closed, preserve attributable evidence, and remain visible in
tests, logs, or release-gate output without copying secrets or raw private data.

## Trust Zones And Data Flow

1. **Untrusted collection:** alerts, Elastic rows, PCAP-derived fields, endpoint
   rows, HTTP bodies, and public provider bodies enter with attacker-controlled
   strings and encodings.
2. **Admission and projection:** bounded parsers, positive field projections,
   provenance validation, and secret redaction produce evidence objects. This
   zone cannot grant query or process authority.
3. **Model context:** canonical system prompts and code-owned tasks are trusted;
   evidence is nested in the user data envelope and is explicitly labeled
   untrusted. Model output remains untrusted.
4. **Tool broker:** model output may propose only a closed structured request.
   Code validates the outer schema, backend capability, parameters, time scope,
   budgets, and authorization, then code constructs exact provider syntax. Raw
   model commands, DSL, paths, scripts, regular expressions, packet payloads,
   URLs, and parser arguments are never executed.
5. **Persistence and presentation:** owner-only atomic artifacts retain
   provenance. HTML and Markdown boundaries escape active content and admit
   only bounded UTF-8 text without terminal or bidi instruction controls.
6. **Egress:** provider routes and destinations are operator-owned. Isolated
   OpenClaw permits only the exact loopback Ollama endpoint; evidence cannot
   select a destination or carry hosted credentials into that runtime.

Credentials remain outside every evidence object and source artifact. Query
execution results remain attributable to an executed audit/query digest; model
claims are not proof that a query ran.

## Threat And Control Matrix

| Threat | Required control | Fail-closed/observable result | Executable evidence |
| --- | --- | --- | --- |
| Prompt or indirect prompt injection | Code-owned system/task messages; evidence nested in the user JSON envelope; repeated instruction that provider, endpoint, and packet strings are untrusted | Text remains data and cannot alter message role, prompt path, tool policy, or response schema | `test_prompt_injection_remains_nested_user_evidence` |
| Path traversal and dot-file disclosure | Decode once, reject empty/dot/parent parts, resolve below the admitted root, reject symlink destinations at publication boundaries | 404/denial or classified publication error; no outside file read/write | `test_request_size_and_traversal_fail_before_read_or_file_access` and existing artifact/path suites |
| Command, query, or tool-argument injection | Closed request envelope; exact backend parameter projection; code-owned query builders and authorization context | Unknown top-level/executable fields are rejected before a backend normalizer or tool runs | `test_model_text_cannot_supply_executable_query_fields` and query authorization suites |
| Oversized input/resource exhaustion | Route-specific request limits before body read; bounded response readers, row counts, nested items, prompt budgets, report items, and artifact sizes | 400/413 or typed bounded failure; no unbounded read, model call, or persistence | `test_request_size_and_traversal_fail_before_read_or_file_access` and bounded HTTP suites |
| Malicious encodings and active presentation content | Strict JSON decoding; bounded Unicode admission replaces surrogates, C0/C1, and bidi controls; HTML escaping; safe HTTP(S)-only Markdown links | Output remains UTF-8 encodable and script text is inert; malformed values cannot crash report publication | `test_malicious_json_encoding_cannot_break_report_publication` |
| Secret disclosure | Positive evidence projection, sensitive-key/value/path removal, provider environment isolation, owner-only artifacts, secret scan | Sensitive fields are omitted or replaced with a redaction marker; no credential enters Git, prompts, logs, or Linear | `test_hosted_projection_redacts_sensitive_evidence` and hosted projection suites |
| Unsafe egress/model-route substitution | Exact operator-owned provider/model route, observed identity attestation, fixed argv, proxy clearing, and exact loopback allowlist for isolated OpenClaw | Startup/model request exits before network use and reports an operator-safe route error | `test_non_loopback_model_egress_fails_closed` and model-routing suites |

The authoritative synthetic corpus is
`operations/fixtures/untrusted-telemetry-adversarial.json`. It contains no live
hostnames, credentials, evidence, or production identifiers.

## Release Gate

Every change to a parser, prompt projection, model adapter, query builder,
report generator, Markdown/HTML renderer, path resolver, hosted-evidence
projection, or outbound route must run:

```bash
python3 operations/run-untrusted-telemetry-gate.py
```

The full Python suites on production Python 3.9 and the current development
runtime, module/import/cycle checks, secret scan, installer validation, Node
tests, and representative SOC/IR replays remain mandatory. This focused gate
does not replace them.

## Residual Risk And Change Rules

- Rendered evidence can contain persuasive human-readable text. UI escaping
  prevents execution, not social engineering; analysts must validate claims
  against provenance and the claim-evidence graph.
- Unicode confusables are retained because blanket transliteration would alter
  forensic evidence. Surrogates and instruction controls are replaced only at
  presentation boundaries; raw owner-only evidence retains its original digest.
- Public enrichment and hosted models remain external trust zones. Positive
  projection, bounded transport, route attribution, and runtime credential
  isolation are mandatory even when a provider is reputable.
- A future write-capable tool, arbitrary query mode, new outbound destination,
  relaxed evidence projection, or raw HTML feature requires a separate threat
  model and explicit operator authorization before implementation.
- Security failures cannot be downgraded to warnings or acceptance exceptions
  merely to keep a release moving. Add red characterization first, preserve the
  evidence, and relate the defect to ARR-23/ARR-70.
