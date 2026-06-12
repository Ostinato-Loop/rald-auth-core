-- RALD Auth Core — Webhook Registry
-- Sprint: Hardening Phase 8 · Developer Platform Completion · 2026-06-12
-- Enables developers to register webhooks for identity events.
-- LILCKY STUDIO LIMITED

CREATE TABLE IF NOT EXISTS webhook_registry (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  developer_id    UUID REFERENCES developer_profiles(id) ON DELETE CASCADE,
  app_id          TEXT,

  -- Webhook config
  name            TEXT NOT NULL,
  endpoint_url    TEXT NOT NULL,
  secret          TEXT NOT NULL,          -- HMAC-SHA256 signing secret
  
  -- Subscriptions
  event_types     TEXT[] NOT NULL DEFAULT '{}',
  
  -- Status
  status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active','paused','suspended')),
  failure_count   INTEGER NOT NULL DEFAULT 0,
  last_triggered  TIMESTAMPTZ,
  last_failure    TIMESTAMPTZ,
  
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS webhook_registry_user_id_idx     ON webhook_registry(user_id);
CREATE INDEX IF NOT EXISTS webhook_registry_status_idx      ON webhook_registry(status);
CREATE INDEX IF NOT EXISTS webhook_registry_event_types_idx ON webhook_registry USING GIN(event_types);

ALTER TABLE webhook_registry ENABLE ROW LEVEL SECURITY;
CREATE POLICY "webhook_registry: own"
  ON webhook_registry FOR ALL
  USING (user_id = auth.uid());
CREATE POLICY "webhook_registry: service write"
  ON webhook_registry FOR ALL
  USING (true) WITH CHECK (true);

-- ── webhook_deliveries — track delivery history ───────────────────────────────
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_id      UUID NOT NULL REFERENCES webhook_registry(id) ON DELETE CASCADE,
  event_type      TEXT NOT NULL,
  event_id        TEXT,
  payload         JSONB NOT NULL DEFAULT '{}',
  status          TEXT NOT NULL CHECK (status IN ('delivered','failed','retrying')),
  http_status     INTEGER,
  error_message   TEXT,
  attempt_count   INTEGER NOT NULL DEFAULT 1,
  delivered_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS webhook_deliveries_webhook_id_idx ON webhook_deliveries(webhook_id);
CREATE INDEX IF NOT EXISTS webhook_deliveries_status_idx     ON webhook_deliveries(status);

ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;
CREATE POLICY "webhook_deliveries: service only"
  ON webhook_deliveries FOR ALL USING (true) WITH CHECK (true);

-- ── updated_at trigger ────────────────────────────────────────────────────────
DROP TRIGGER IF EXISTS trg_webhook_registry_updated_at ON webhook_registry;
CREATE TRIGGER trg_webhook_registry_updated_at
  BEFORE UPDATE ON webhook_registry
  FOR EACH ROW EXECUTE FUNCTION update_identity_updated_at();
