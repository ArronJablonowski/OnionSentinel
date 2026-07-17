// The legacy/rollback webhook still validates and commits alerts through
// alert-store, but Markdown generation is intentionally deferred to the
// durable post-commit queue. This response keeps relay acknowledgement fast.
return [{json: {
  ...$json,
  stage: 'acknowledge-durable-alert-commit',
  report_written: false,
  report_deferred_to_post_commit: $json.status === 'accepted',
}}];
