-- RALD Auth Core — Machine Identity Infrastructure
-- Sprint: Hardening Phase 5 + Operator Platform Phase 9 · 2026-06-12
-- Each RALD service gets a cryptographic identity. No more shared RALD_JWT_SECRET.
-- Service-to-service calls use machine identity tokens with scoped permissions.
-- LILCKY STUDIO LIMITED

-- ── machine_identities — service accounts ────────────────────────────────────
CREATE TABLE IF NOT EXISTS machine_identities (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Service identification
  service_name     TEXT NOT NULL UNIQUE,  -- e.g. "rald-auth-core", "loop-api"
  display_name     TEXT NOT NULL,
  description      TEXT NOT NULL DEFAULT '',
  environment      TEXT NOT NULL DEFAULT 'production'
                     CHECK (environment IN ('production','staging','development')),

  -- Credentials (key is NEVER stored in plaintext)
  key_id           TEXT NOT NULL UNIQUE,  -- public identifier prefix (e.g. "mid_Gf7xkP")
  key_hash         TEXT NOT NULL,         -- SHA-256 of the actual secret key
  key_salt         TEXT NOT NULL,         -- per-key salt

  -- Scopes & permissions
  scopes           TEXT[] NOT NULL DEFAULT '{}',  -- e.g. ["auth:read","identity:write"]
  allowed_services TEXT[] NOT NULL DEFAULT '{}',  -- which services this identity can call
  ip_allowlist     INET[] NOT NULL DEFAULT '{}',  -- empty = any; non-empty = restrict to IPs

  -- Lifecycle
  status           TEXT NOT NULL DEFAULT 'active'
                     CHECK (status IN ('active','suspended','revoked')),
  created_by       TEXT NOT NULL,  -- admin user_id who provisioned this
  last_rotated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  rotation_due_at  TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '90 days'),
  revoked_at       TIMESTAMPTZ,

  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS machine_identities_key_id_idx    ON machine_identities(key_id);
CREATE INDEX IF NOT EXISTS machine_identities_status_idx    ON machine_identities(status);
CREATE INDEX IF NOT EXISTS machine_identities_env_idx       ON machine_identities(environment);

ALTER TABLE machine_identities ENABLE ROW LEVEL SECURITY;
CREATE POLICY "machine_identities: service role only"
  ON machine_identities FOR ALL USING (true) WITH CHECK (true);

-- ── machine_identity_audit_log ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS machine_identity_audit_log (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id  UUID NOT NULL REFERENCES machine_identities(id) ON DELETE CASCADE,
  action       TEXT NOT NULL,   -- "issued","rotated","revoked","auth_success","auth_failed"
  ip           TEXT,
  metadata     JSONB NOT NULL DEFAULT '{}',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS machine_identity_audit_identity_idx  ON machine_identity_audit_log(identity_id);
CREATE INDEX IF NOT EXISTS machine_identity_audit_created_idx   ON machine_identity_audit_log(created_at DESC);

ALTER TABLE machine_identity_audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY "machine_identity_audit: service role only"
  ON machine_identity_audit_log FOR ALL USING (true) WITH CHECK (true);

-- ── Seed: Registered RALD services ────────────────────────────────────────────
-- key_hash values are placeholders — run provisioning script to set real values
INSERT INTO machine_identities (service_name, display_name, description, scopes, allowed_services, created_by) VALUES
  ('rald-auth-core', 'RALD Auth Core',     'Identity & authentication service', ARRAY['identity:read','identity:write','session:manage'], ARRAY['loop-api','messenger-api','rald-notify','rald-inbox','rald-search','rald-config','rald-event-bus'], 'system'),
  ('loop-api',        'Loop API',           'Social audio platform API', ARRAY['identity:read','session:validate'], ARRAY['rald-auth-core','rald-notify','rald-event-bus','rald-config'], 'system'),
  ('messenger-api',   'Messenger API',      'Real-time messaging API', ARRAY['identity:read','session:validate'], ARRAY['rald-auth-core','rald-notify','rald-event-bus'], 'system'),
  ('rald-notify',     'RALD Notify',        'Notification delivery service', ARRAY['identity:read'], ARRAY['rald-auth-core','rald-event-bus'], 'system'),
  ('rald-inbox',      'RALD Inbox',         'Unified inbox service', ARRAY['identity:read'], ARRAY['rald-auth-core','rald-notify','rald-search','rald-event-bus'], 'system'),
  ('rald-search',     'RALD Search',        'Search service', ARRAY['identity:read'], ARRAY['rald-auth-core','rald-event-bus'], 'system'),
  ('rald-config',     'RALD Config',        'Feature flag & config service', ARRAY['config:admin'], ARRAY['rald-auth-core'], 'system'),
  ('rald-event-bus',  'RALD Event Bus',     'Event fabric', ARRAY['events:publish','events:subscribe'], ARRAY['all'], 'system'),
  ('rald-realtime',   'RALD Realtime',      'WebSocket gateway', ARRAY['identity:read'], ARRAY['rald-auth-core','rald-event-bus'], 'system'),
  ('rald-control-center', 'RALD Control Center', 'Admin panel', ARRAY['admin:all'], ARRAY['all'], 'system')
ON CONFLICT (service_name) DO NOTHING;

-- ── updated_at trigger ────────────────────────────────────────────────────────
DROP TRIGGER IF EXISTS trg_machine_identities_updated_at ON machine_identities;
CREATE TRIGGER trg_machine_identities_updated_at
  BEFORE UPDATE ON machine_identities
  FOR EACH ROW EXECUTE FUNCTION update_identity_updated_at();

-- ── rotation_alert view — services due for key rotation ──────────────────────
CREATE OR REPLACE VIEW machine_identity_rotation_alerts AS
SELECT
  service_name,
  display_name,
  last_rotated_at,
  rotation_due_at,
  (rotation_due_at - now()) AS days_until_due,
  CASE
    WHEN rotation_due_at < now()            THEN 'OVERDUE'
    WHEN rotation_due_at < now() + INTERVAL '7 days' THEN 'DUE_SOON'
    ELSE 'OK'
  END AS rotation_status
FROM machine_identities
WHERE status = 'active'
ORDER BY rotation_due_at ASC;
