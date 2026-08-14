# Documentation Index

Important documents:

- `architecture/modularization-adr.md`: accepted modularization decision,
  dependency rules, compatibility constraints, engineering budgets, and
  migration gates for decomposing the largest production files.
- `architecture/modularization-module-map.md`: current-to-target responsibility
  map, stable interfaces, side-effect ownership, deployment changes, and
  extraction sequence.
- `disaster-recovery-runbook.md`: end-to-end restore.
- `security-onion-relay-architecture.md`: full system architecture.
- `soc-alert-storage-ui-scaling-architecture.md`: SQLite-backed dashboard/API design.
- `security-onion-alert-filtering-guide.md`: tuning, scoring, filtering, and suppression.
- `ai-analysis-policy.md`: AI analysis policy and model-routing behavior.
- `llm-harness-and-investigation-runtime-roadmap.md`: security-gated roadmap
  for Hermes Agent, OpenClaw, and the Onion Sentinel investigation runtime.
- `onion-sentinel-investigation-harness.md`: professional-grade harness
  architecture, trust boundaries, evidence and memory governance, specialist
  workflows, evaluation program, and phased production gates.
- `security-onion-api-and-osquery-roadmap.md`: supported API migration and
  policy-brokered host investigation roadmap.
- `reliability-and-slo-runbook.md`: durable workflow, SLO, soak, and recovery
  operations.
- `soc-daily-rollups.md`: daily summary generation.
- `frontend-ui-qa-runbook.md`: responsive Playwright crawl, chaos interaction,
  and visual regression workflow.
- `dashboard-service-boundary.md`: strict ownership boundary between the
  independently served Onion Sentinel UI and the separate Hermes LAN Portal.
- `security/untrusted-telemetry-threat-model.md`: enforced prompt-injection,
  parser, tool-schema, presentation, secret, and egress threat model and gate.
- `ac-hunter-deep-review.md`: read-only AC Hunter integration, fixed
  Mac-to-Relay-to-AC-Hunter path, secret boundaries, trust bootstrap,
  validation, and rollback.

The top-level node READMEs are the fastest path for rebuilds. These documents preserve design history and deeper operational context.
