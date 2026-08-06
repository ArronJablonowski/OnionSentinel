# Onion Sentinel Python Runtime Package

This tree is the stable destination for behavior extracted from the legacy
Python entry points in `n8n/bin`. The supported production executable remains
`n8n/bin/run-local-ai-analysis.py` until its migration is complete.

## Boundary rules

- Package modules never import a legacy entry-point script.
- Contracts contain validated data objects, normalized errors, and dependency
  inversion ports. They do not perform filesystem, network, subprocess,
  database, model, query, or UI work.
- The executable composition root supplies clocks, identifiers, filesystem,
  network, process, repositories, and concrete provider adapters.
- Provider adapters cannot authorize queries, select reviewer policy, persist
  results, or silently fall back to another model route.
- Query execution remains authorized, bounded, audited, and read-only for
  Security Onion and the Relay.
- New modules target 300–600 lines and must remain within the repository
  quality policy.

## Deployment

`install-ai-runtime-package.py` copies this complete tree into a sibling
staging directory, compiles and imports every required module, removes
validation bytecode, and only then atomically replaces
`$STACK_DIR/onion_sentinel`. Invalid or incomplete staging leaves the current
runtime package untouched.

Do not replace this tree with a sequence of individual file copies. A partial
package is not a valid deployable unit.

## Migration method

For each extraction:

1. bind positive, negative, and failure behavior to characterization tests;
2. add the package implementation without importing the legacy wrapper;
3. make the legacy symbol delegate to the package implementation;
4. run focused and complete regression suites;
5. reduce the quality baseline when the legacy file shrinks; and
6. retain the legacy symbol until all runtime and test callers have migrated.
