BEGIN;

CREATE SCHEMA IF NOT EXISTS onion_sentinel_software;
CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;

CREATE TABLE IF NOT EXISTS onion_sentinel_software.schema_version (
  component TEXT PRIMARY KEY,
  version INTEGER NOT NULL CHECK (version > 0),
  installed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO onion_sentinel_software.schema_version (component, version)
VALUES ('software_inventory', 1)
ON CONFLICT (component) DO UPDATE
SET version = EXCLUDED.version,
    installed_at = clock_timestamp();

CREATE TABLE IF NOT EXISTS onion_sentinel_software.snapshots (
  snapshot_id TEXT PRIMARY KEY
    CHECK (snapshot_id ~ '^[0-9a-f]{64}$'),
  status TEXT NOT NULL DEFAULT 'staging'
    CHECK (status IN ('staging', 'active', 'retired')),
  updated_at TIMESTAMPTZ NOT NULL,
  collection JSONB NOT NULL
    CHECK (jsonb_typeof(collection) = 'object'),
  expected_records INTEGER NOT NULL
    CHECK (expected_records BETWEEN 0 AND 250000),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  activated_at TIMESTAMPTZ,
  CHECK (
    (status = 'active' AND activated_at IS NOT NULL)
    OR status <> 'active'
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ossi_one_active_snapshot
  ON onion_sentinel_software.snapshots (status)
  WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_ossi_snapshots_created
  ON onion_sentinel_software.snapshots (created_at DESC, snapshot_id);

CREATE TABLE IF NOT EXISTS onion_sentinel_software.inventory_records (
  snapshot_id TEXT NOT NULL
    REFERENCES onion_sentinel_software.snapshots(snapshot_id)
    ON DELETE CASCADE,
  evidence_id TEXT NOT NULL CHECK (evidence_id ~ '^[0-9a-f]{24}$'),
  source TEXT NOT NULL
    CHECK (source IN ('osquery_apps', 'zeek_software', 'http_user_agent')),
  source_dataset TEXT NOT NULL CHECK (length(source_dataset) BETWEEN 1 AND 160),
  tier TEXT NOT NULL CHECK (tier IN ('installed', 'observed', 'inferred')),
  confidence TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
  asset_ref_type TEXT NOT NULL CHECK (asset_ref_type IN ('host', 'ip')),
  asset_ref TEXT NOT NULL CHECK (length(asset_ref) BETWEEN 1 AND 253),
  platform TEXT NOT NULL DEFAULT '' CHECK (length(platform) <= 160),
  operating_system_type TEXT NOT NULL DEFAULT ''
    CHECK (length(operating_system_type) <= 160),
  operating_system_version TEXT NOT NULL DEFAULT ''
    CHECK (length(operating_system_version) <= 512),
  operating_system_source TEXT NOT NULL DEFAULT ''
    CHECK (length(operating_system_source) <= 160),
  operating_system_confidence TEXT NOT NULL DEFAULT ''
    CHECK (operating_system_confidence IN ('', 'low', 'medium', 'high')),
  product TEXT NOT NULL CHECK (length(product) BETWEEN 1 AND 4096),
  version TEXT NOT NULL DEFAULT '' CHECK (length(version) <= 2048),
  category TEXT NOT NULL DEFAULT '' CHECK (length(category) <= 256),
  first_seen TIMESTAMPTZ NOT NULL,
  last_seen TIMESTAMPTZ NOT NULL,
  observation_count BIGINT NOT NULL CHECK (
    observation_count BETWEEN 0 AND 1000000000
  ),
  search_text TEXT GENERATED ALWAYS AS (
    lower(
      product || ' ' || version || ' ' || asset_ref || ' ' || platform || ' '
      || operating_system_type || ' ' || operating_system_version || ' '
      || category || ' ' || source
    )
  ) STORED,
  PRIMARY KEY (snapshot_id, evidence_id),
  CHECK (last_seen >= first_seen)
);

CREATE INDEX IF NOT EXISTS idx_ossi_records_last_seen
  ON onion_sentinel_software.inventory_records
  (snapshot_id, last_seen DESC, evidence_id DESC);
CREATE INDEX IF NOT EXISTS idx_ossi_records_first_seen
  ON onion_sentinel_software.inventory_records
  (snapshot_id, first_seen DESC, evidence_id DESC);
DROP INDEX IF EXISTS onion_sentinel_software.idx_ossi_records_product;
DROP INDEX IF EXISTS onion_sentinel_software.idx_ossi_records_asset;
DROP INDEX IF EXISTS onion_sentinel_software.idx_ossi_records_tier;
DROP INDEX IF EXISTS onion_sentinel_software.idx_ossi_records_confidence;
CREATE INDEX IF NOT EXISTS idx_ossi_records_product_bounded
  ON onion_sentinel_software.inventory_records
  (snapshot_id, left(lower(product), 256), left(lower(version), 128), evidence_id);
CREATE INDEX IF NOT EXISTS idx_ossi_records_asset_bounded
  ON onion_sentinel_software.inventory_records
  (snapshot_id, lower(asset_ref), left(lower(product), 256), evidence_id);
CREATE INDEX IF NOT EXISTS idx_ossi_records_tier_bounded
  ON onion_sentinel_software.inventory_records
  (snapshot_id, tier, left(lower(product), 256), evidence_id);
CREATE INDEX IF NOT EXISTS idx_ossi_records_confidence_bounded
  ON onion_sentinel_software.inventory_records
  (snapshot_id, confidence, left(lower(product), 256), evidence_id);
CREATE INDEX IF NOT EXISTS idx_ossi_records_platform
  ON onion_sentinel_software.inventory_records
  (snapshot_id, lower(platform), last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_ossi_records_source
  ON onion_sentinel_software.inventory_records
  (snapshot_id, source, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_ossi_records_version_conflict
  ON onion_sentinel_software.inventory_records
  (snapshot_id, asset_ref_type, asset_ref, last_seen, md5(lower(product)));
CREATE INDEX IF NOT EXISTS idx_ossi_records_search
  ON onion_sentinel_software.inventory_records
  USING GIN (search_text public.gin_trgm_ops);

COMMIT;
