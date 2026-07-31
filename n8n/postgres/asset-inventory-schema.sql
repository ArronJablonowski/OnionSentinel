BEGIN;

CREATE SCHEMA IF NOT EXISTS onion_sentinel_assets;

CREATE TABLE IF NOT EXISTS onion_sentinel_assets.schema_version (
  component TEXT PRIMARY KEY,
  version INTEGER NOT NULL CHECK (version > 0),
  installed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO onion_sentinel_assets.schema_version (component, version)
VALUES ('asset_inventory', 1)
ON CONFLICT (component) DO UPDATE
SET version = EXCLUDED.version,
    installed_at = clock_timestamp();

CREATE TABLE IF NOT EXISTS onion_sentinel_assets.inventory_records (
  record_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  asset_id TEXT NOT NULL CHECK (length(asset_id) BETWEEN 1 AND 160),
  valid_from TIMESTAMPTZ NOT NULL,
  valid_until TIMESTAMPTZ,
  role TEXT NOT NULL DEFAULT '' CHECK (length(role) <= 160),
  platform TEXT NOT NULL DEFAULT '' CHECK (length(platform) <= 160),
  owner_ref TEXT NOT NULL DEFAULT '' CHECK (length(owner_ref) <= 300),
  criticality TEXT NOT NULL DEFAULT 'unknown'
    CHECK (criticality IN ('low', 'medium', 'high', 'critical', 'unknown')),
  expected_services JSONB NOT NULL DEFAULT '[]'::jsonb
    CHECK (jsonb_typeof(expected_services) = 'array'),
  expected_behaviors JSONB NOT NULL DEFAULT '[]'::jsonb
    CHECK (jsonb_typeof(expected_behaviors) = 'array'),
  source_type TEXT NOT NULL DEFAULT '' CHECK (length(source_type) <= 160),
  source_ref TEXT NOT NULL DEFAULT '' CHECK (length(source_ref) <= 500),
  confidence TEXT NOT NULL DEFAULT 'unknown'
    CHECK (confidence IN ('low', 'medium', 'high', 'unknown')),
  share_with_hosted_models BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CHECK (valid_until IS NULL OR valid_until > valid_from),
  UNIQUE (asset_id, valid_from)
);

CREATE INDEX IF NOT EXISTS idx_osa_inventory_asset_id
  ON onion_sentinel_assets.inventory_records (lower(asset_id), valid_from DESC);
CREATE INDEX IF NOT EXISTS idx_osa_inventory_current
  ON onion_sentinel_assets.inventory_records (valid_from, valid_until)
  WHERE valid_until IS NULL;
CREATE INDEX IF NOT EXISTS idx_osa_inventory_criticality
  ON onion_sentinel_assets.inventory_records (criticality, lower(asset_id));

CREATE TABLE IF NOT EXISTS onion_sentinel_assets.identifiers (
  identifier_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  record_id BIGINT NOT NULL
    REFERENCES onion_sentinel_assets.inventory_records(record_id)
    ON DELETE CASCADE,
  identifier_type TEXT NOT NULL
    CHECK (identifier_type IN ('ip', 'mac', 'hostname')),
  identifier_value TEXT NOT NULL CHECK (length(identifier_value) BETWEEN 1 AND 253),
  normalized_value TEXT NOT NULL CHECK (length(normalized_value) BETWEEN 1 AND 253),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (record_id, identifier_type, normalized_value)
);

CREATE INDEX IF NOT EXISTS idx_osa_identifiers_lookup
  ON onion_sentinel_assets.identifiers (identifier_type, normalized_value, record_id);
CREATE INDEX IF NOT EXISTS idx_osa_identifiers_record
  ON onion_sentinel_assets.identifiers (record_id, identifier_type, normalized_value);

CREATE TABLE IF NOT EXISTS onion_sentinel_assets.dhcp_collection_state (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
  state_json JSONB NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(state_json) = 'object'),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO onion_sentinel_assets.dhcp_collection_state (singleton, state_json)
VALUES (TRUE, '{}'::jsonb)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS onion_sentinel_assets.dhcp_observations (
  discovery_id TEXT PRIMARY KEY CHECK (discovery_id ~ '^[0-9a-f]{20}$'),
  current_ip INET NOT NULL,
  mac_address TEXT NOT NULL DEFAULT '' CHECK (length(mac_address) <= 17),
  hostname TEXT NOT NULL DEFAULT '' CHECK (length(hostname) <= 253),
  identity_type TEXT NOT NULL DEFAULT '' CHECK (length(identity_type) <= 32),
  identity_value TEXT NOT NULL DEFAULT '' CHECK (length(identity_value) <= 253),
  first_seen TIMESTAMPTZ NOT NULL,
  last_seen TIMESTAMPTZ NOT NULL,
  lease_expires_at TIMESTAMPTZ,
  observation_count BIGINT NOT NULL DEFAULT 0 CHECK (observation_count >= 0),
  message_types JSONB NOT NULL DEFAULT '[]'::jsonb
    CHECK (jsonb_typeof(message_types) = 'array'),
  sensors JSONB NOT NULL DEFAULT '[]'::jsonb
    CHECK (jsonb_typeof(sensors) = 'array'),
  evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb
    CHECK (jsonb_typeof(evidence_ids) = 'array'),
  raw_record JSONB NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(raw_record) = 'object'),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CHECK (last_seen >= first_seen)
);

CREATE INDEX IF NOT EXISTS idx_osa_dhcp_last_seen
  ON onion_sentinel_assets.dhcp_observations (last_seen DESC, discovery_id);
CREATE INDEX IF NOT EXISTS idx_osa_dhcp_ip
  ON onion_sentinel_assets.dhcp_observations (current_ip, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_osa_dhcp_mac
  ON onion_sentinel_assets.dhcp_observations (lower(mac_address), last_seen DESC)
  WHERE mac_address <> '';
CREATE INDEX IF NOT EXISTS idx_osa_dhcp_hostname
  ON onion_sentinel_assets.dhcp_observations (lower(hostname), last_seen DESC)
  WHERE hostname <> '';

CREATE TABLE IF NOT EXISTS onion_sentinel_assets.review_decisions (
  decision_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  discovery_id TEXT NOT NULL,
  decision TEXT NOT NULL CHECK (decision IN ('promoted', 'rejected', 'deferred')),
  asset_id TEXT,
  reason TEXT NOT NULL DEFAULT '' CHECK (length(reason) <= 1000),
  operator_ref TEXT NOT NULL DEFAULT '' CHECK (length(operator_ref) <= 300),
  observation_fingerprint TEXT NOT NULL
    CHECK (observation_fingerprint ~ '^[0-9a-f]{64}$'),
  decided_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_osa_review_discovery
  ON onion_sentinel_assets.review_decisions (discovery_id, decided_at DESC);

CREATE TABLE IF NOT EXISTS onion_sentinel_assets.audit_events (
  event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 100),
  actor TEXT NOT NULL DEFAULT 'system' CHECK (length(actor) <= 160),
  asset_id TEXT,
  discovery_id TEXT,
  event_data JSONB NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(event_data) = 'object'),
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_osa_audit_time
  ON onion_sentinel_assets.audit_events (occurred_at DESC, event_id DESC);
CREATE INDEX IF NOT EXISTS idx_osa_audit_asset
  ON onion_sentinel_assets.audit_events (asset_id, occurred_at DESC)
  WHERE asset_id IS NOT NULL;

CREATE OR REPLACE FUNCTION onion_sentinel_assets.reject_audit_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'asset audit events are append-only';
END;
$$;

DROP TRIGGER IF EXISTS trg_osa_audit_append_only
  ON onion_sentinel_assets.audit_events;
CREATE TRIGGER trg_osa_audit_append_only
BEFORE UPDATE OR DELETE ON onion_sentinel_assets.audit_events
FOR EACH ROW EXECUTE FUNCTION onion_sentinel_assets.reject_audit_mutation();

CREATE OR REPLACE VIEW onion_sentinel_assets.inventory_counts AS
SELECT
  COUNT(*)::BIGINT AS records_total,
  COUNT(*) FILTER (
    WHERE valid_from <= clock_timestamp()
      AND (valid_until IS NULL OR valid_until > clock_timestamp())
  )::BIGINT AS current_records,
  COUNT(*) FILTER (WHERE valid_from > clock_timestamp())::BIGINT AS scheduled_records,
  COUNT(*) FILTER (
    WHERE valid_until IS NOT NULL AND valid_until <= clock_timestamp()
  )::BIGINT AS expired_records
FROM onion_sentinel_assets.inventory_records;

COMMIT;
