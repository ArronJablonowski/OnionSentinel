BEGIN;

CREATE SCHEMA IF NOT EXISTS onion_sentinel_queue;

CREATE TABLE IF NOT EXISTS onion_sentinel_queue.schema_version (
  component TEXT PRIMARY KEY,
  version INTEGER NOT NULL CHECK (version > 0),
  installed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO onion_sentinel_queue.schema_version (component, version)
VALUES ('durable_jobs', 1)
ON CONFLICT (component) DO UPDATE
SET version = EXCLUDED.version,
    installed_at = clock_timestamp();

CREATE TABLE IF NOT EXISTS onion_sentinel_queue.durable_jobs (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  job_type TEXT NOT NULL CHECK (length(job_type) BETWEEN 1 AND 80),
  dedupe_key TEXT NOT NULL CHECK (length(dedupe_key) BETWEEN 1 AND 256),
  payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
  priority INTEGER NOT NULL DEFAULT 0,
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  max_attempts INTEGER NOT NULL DEFAULT 8 CHECK (max_attempts > 0),
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  lease_expires_at TIMESTAMPTZ,
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  completed_at TIMESTAMPTZ,
  last_completed_at TIMESTAMPTZ,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  processing_started_at TIMESTAMPTZ,
  rerun_requested BOOLEAN NOT NULL DEFAULT FALSE,
  UNIQUE (job_type, dedupe_key)
);

CREATE INDEX IF NOT EXISTS idx_osq_durable_jobs_due
  ON onion_sentinel_queue.durable_jobs
  (job_type, priority DESC, next_attempt_at ASC, id ASC)
  WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_osq_durable_jobs_lease
  ON onion_sentinel_queue.durable_jobs (lease_expires_at)
  WHERE status = 'processing';

CREATE INDEX IF NOT EXISTS idx_osq_durable_jobs_updated
  ON onion_sentinel_queue.durable_jobs (updated_at DESC);

CREATE OR REPLACE FUNCTION onion_sentinel_queue.enqueue_durable_job(
  p_job_type TEXT,
  p_dedupe_key TEXT,
  p_payload JSONB DEFAULT '{}'::jsonb,
  p_priority INTEGER DEFAULT 0,
  p_max_attempts INTEGER DEFAULT 8
) RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
  v_id BIGINT;
  v_now TIMESTAMPTZ := clock_timestamp();
BEGIN
  INSERT INTO onion_sentinel_queue.durable_jobs AS current (
    job_type, dedupe_key, payload_json, status, priority, max_attempts,
    next_attempt_at, created_at, updated_at, requested_at
  ) VALUES (
    p_job_type, p_dedupe_key, COALESCE(p_payload, '{}'::jsonb), 'pending',
    p_priority, GREATEST(1, p_max_attempts), v_now, v_now, v_now, v_now
  )
  ON CONFLICT (job_type, dedupe_key) DO UPDATE SET
    payload_json = EXCLUDED.payload_json,
    priority = GREATEST(current.priority, EXCLUDED.priority),
    max_attempts = EXCLUDED.max_attempts,
    status = CASE WHEN current.status = 'processing' THEN 'processing' ELSE 'pending' END,
    next_attempt_at = CASE WHEN current.status = 'processing' THEN current.next_attempt_at ELSE EXCLUDED.next_attempt_at END,
    attempt_count = CASE WHEN current.status = 'processing' THEN current.attempt_count ELSE 0 END,
    completed_at = CASE WHEN current.status = 'processing' THEN current.completed_at ELSE NULL END,
    last_error = CASE WHEN current.status = 'processing' THEN current.last_error ELSE NULL END,
    requested_at = EXCLUDED.requested_at,
    processing_started_at = CASE WHEN current.status = 'processing' THEN current.processing_started_at ELSE NULL END,
    rerun_requested = current.status = 'processing',
    updated_at = EXCLUDED.updated_at
  RETURNING id INTO v_id;
  RETURN v_id;
END;
$$;

CREATE OR REPLACE FUNCTION onion_sentinel_queue.claim_durable_job(
  p_job_type TEXT,
  p_lease_seconds INTEGER DEFAULT 300
) RETURNS SETOF onion_sentinel_queue.durable_jobs
LANGUAGE sql
AS $$
  WITH candidate AS (
    SELECT id
    FROM onion_sentinel_queue.durable_jobs
    WHERE job_type = p_job_type
      AND status = 'pending'
      AND next_attempt_at <= clock_timestamp()
      AND attempt_count < max_attempts
    ORDER BY priority DESC, next_attempt_at ASC, id ASC
    FOR UPDATE SKIP LOCKED
    LIMIT 1
  )
  UPDATE onion_sentinel_queue.durable_jobs AS job
  SET status = 'processing',
      attempt_count = job.attempt_count + 1,
      lease_expires_at = clock_timestamp() + make_interval(secs => GREATEST(30, p_lease_seconds)),
      processing_started_at = clock_timestamp(),
      rerun_requested = FALSE,
      updated_at = clock_timestamp()
  FROM candidate
  WHERE job.id = candidate.id
  RETURNING job.*;
$$;

CREATE OR REPLACE FUNCTION onion_sentinel_queue.complete_durable_job(
  p_id BIGINT
) RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
  v_status TEXT;
  v_now TIMESTAMPTZ := clock_timestamp();
BEGIN
  UPDATE onion_sentinel_queue.durable_jobs
  SET status = CASE WHEN rerun_requested THEN 'pending' ELSE 'completed' END,
      next_attempt_at = CASE WHEN rerun_requested THEN v_now ELSE next_attempt_at END,
      attempt_count = CASE WHEN rerun_requested THEN 0 ELSE attempt_count END,
      lease_expires_at = NULL,
      last_error = NULL,
      completed_at = CASE WHEN rerun_requested THEN NULL ELSE v_now END,
      last_completed_at = v_now,
      processing_started_at = CASE WHEN rerun_requested THEN NULL ELSE processing_started_at END,
      rerun_requested = FALSE,
      updated_at = v_now
  WHERE id = p_id
  RETURNING status INTO v_status;
  RETURN v_status;
END;
$$;

CREATE OR REPLACE FUNCTION onion_sentinel_queue.release_expired_leases()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
  v_count INTEGER;
BEGIN
  UPDATE onion_sentinel_queue.durable_jobs
  SET status = 'pending',
      lease_expires_at = NULL,
      processing_started_at = NULL,
      updated_at = clock_timestamp()
  WHERE status = 'processing'
    AND (lease_expires_at IS NULL OR lease_expires_at <= clock_timestamp());
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$$;

COMMIT;
