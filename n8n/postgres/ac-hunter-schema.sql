BEGIN;

CREATE SCHEMA IF NOT EXISTS onion_sentinel_ac_hunter;

CREATE TABLE IF NOT EXISTS onion_sentinel_ac_hunter.schema_version (
  component TEXT PRIMARY KEY,
  version INTEGER NOT NULL CHECK (version > 0),
  installed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO onion_sentinel_ac_hunter.schema_version (component, version)
VALUES ('ac_hunter_cache', 1)
ON CONFLICT (component) DO UPDATE
SET version = EXCLUDED.version,
    installed_at = clock_timestamp();

CREATE TABLE IF NOT EXISTS onion_sentinel_ac_hunter.snapshots (
  dataset_digest TEXT PRIMARY KEY
    CHECK (dataset_digest ~ '^[0-9a-f]{64}$'),
  dataset_name TEXT NOT NULL
    CHECK (dataset_name = 'security-onion-rolling'),
  collected_at TIMESTAMPTZ NOT NULL,
  payload JSONB NOT NULL
    CHECK (jsonb_typeof(payload) = 'object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_osac_snapshots_collected
  ON onion_sentinel_ac_hunter.snapshots
  (collected_at DESC, dataset_digest);

CREATE TABLE IF NOT EXISTS onion_sentinel_ac_hunter.current_state (
  singleton SMALLINT PRIMARY KEY DEFAULT 1 CHECK (singleton = 1),
  current_digest TEXT REFERENCES onion_sentinel_ac_hunter.snapshots(dataset_digest),
  last_checked_at TIMESTAMPTZ,
  last_changed_at TIMESTAMPTZ,
  last_pull_changed BOOLEAN NOT NULL DEFAULT FALSE,
  successful_pulls BIGINT NOT NULL DEFAULT 0 CHECK (successful_pulls >= 0),
  unchanged_pulls BIGINT NOT NULL DEFAULT 0 CHECK (unchanged_pulls >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO onion_sentinel_ac_hunter.current_state (singleton)
VALUES (1)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS onion_sentinel_ac_hunter.pull_runs (
  pull_id BIGSERIAL PRIMARY KEY,
  checked_at TIMESTAMPTZ NOT NULL,
  dataset_digest TEXT NOT NULL
    CHECK (dataset_digest ~ '^[0-9a-f]{64}$'),
  changed BOOLEAN NOT NULL,
  finding_count INTEGER NOT NULL DEFAULT 0
    CHECK (finding_count BETWEEN 0 AND 1000000),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_osac_pull_runs_checked
  ON onion_sentinel_ac_hunter.pull_runs (checked_at DESC, pull_id DESC);

COMMIT;
