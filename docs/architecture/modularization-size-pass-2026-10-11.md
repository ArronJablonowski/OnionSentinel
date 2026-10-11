# Physical source-size modularization pass

This is a source-only refactor of commit
`076bc23c94ceb58c013c18a84c70c8e76cb9a828`. It does not deploy, restart services,
change query permissions, resolve the PCAP broker failure, or qualify production.

## Enforced limits

`operations/check-code-size.py` measures physical lines, including comments and
blank lines, across tracked and new, non-ignored code. It includes Python,
JavaScript/TypeScript, shell, extensionless executable scripts, SQL, HTML and CSS,
as well as tests. Files above 1,000 lines fail. Existing production-module
budgets remain tighter: a 600-line target and 800-line new-module limit. The
previous absolute new-file allowance of 1,200 is now 1,000.

Run `zsh operations/check-source-quality.zsh` and the unittest suite before
committing. The repository-size contract is also exercised by unittest discovery.

There is one explicit, byte-pinned exception: the 1,957-line frozen
`n8n/compat/investigation-pivots-v1/investigation_query_contract.py`. Its existing
manifest and SHA-256 remain unchanged. A changed byte fails the size policy.
The project ADR requires a separately versioned, coordinated enforcement-point
migration before altering or retiring that bundle. Therefore this pass does
not claim that literally every repository code file is below 1,000 lines.

## Ownership and compatibility

- The Mac Studio installer retains its CLI and caller shell. Five sourced
  owners handle staging validation, investigation guards, service quiescence,
  runtime payload and dashboard payload. Source expansion for phase validation
  is read-only. Runtime reconciliation reads owners from the same Git revision
  as the entry point, never from an unrelated working-tree revision.
- The Security Onion forced-command exporter retains constants, public
  signatures and patchable ports. Six `so_evidence_*` owners separate bounded
  transport, validation, query execution, historical schema handling, result
  projection and dispatch. They do not import the entry point; a late-bound
  adapter supplies configuration, audit state and bounded operations. Fixed
  DHCP/software helper resolution remains relative to the original exporter.
  The Security Onion installer now copies these owners into its root-owned
  library directory. No Security Onion installation was performed here.
- Twenty-three oversized unittest suites retain historical public test classes
  and discovery filenames. Focused case mixins contain original method bodies;
  fixture owners provide setup and reusable builders. Imports are explicit.
  Inherited cases remain visible to characterization checks, and isolated
  subprocess discovery still works. Fixture helpers remain importable from the
  historical test entry points where other test suites depend on them.

## Remaining complexity debt

The extensionless Security Onion exporter was previously outside the Python
module-quality scanner. Extraction makes its legacy function complexity
visible. Eight existing functions now have non-growing, function-specific
ratchet ceilings in `module-quality-baseline.json`. Their complexity was checked
against the original exporter and is identical; no new-function waiver or
module-size exception was added. The longest existing functions remain
`validated_pivot_request` (318 lines) and `execute_search` (208 lines).

These are explicit follow-up decomposition targets, not an assertion that
moving functions alone eliminates all architectural debt. Preserve exact
authorization, provenance, byte/time limits, error shapes and audit behavior
when extracting their smaller validation and response-processing steps.

## Verification caveats

Before this refactor, the current source already failed three tests: the model
template roster expectation and two SOC alert-summary enrichment/static-status
expectations. Re-running the original source of those suites from the base
commit reproduced the same three failures. They are not silently changed into
passing assertions by this refactor. The evaluation-retention subprocess test
also now permits the documented warning exit for actual host disk-capacity
warnings while retaining its cleanup and content-free receipt assertions.

No production deployment, release gate closure, PostgreSQL cutover, or remote
host modification is included in this pass.

### Final verification

- Full Python suite: 5,119 tests; 5,116 passed and the three reproduced baseline
  failures remain. There were no errors or new failures in the final run.
- Exact discovery parity: all 1,132 original test methods across the 23 split
  suites remain present under their historical class names.
- Expanded installer: byte-for-byte parity with the base commit after removing
  only the five new ownership comments; all 16 phase contracts passed.
- Every extracted evidence function retains its original complexity measure.
- Size gate: 1,928 source files scanned, no maintained-source violations; the
  largest maintained file is `tests/test_software_inventory_api.py` (989 lines).
- Module-quality gate and secret scan passed. Shell syntax checks passed for
  the installer and all sourced owners. `git diff --check` passed.

### Subsequent repository QA

The results above describe the initial source-only extraction. The later QA
pass fixed the three reproduced baseline failures and added enrichment,
artifact-selection, covering-index and deployment-preflight regressions. It
also normalized extracted module EOF whitespace, so expanded installer byte
parity is historical characterization, not a current byte-identity claim.
See `../code-review-handoff-2026-10-11.md` for current passing-suite results,
the failed production deployment, recovery evidence and operator prerequisites.
