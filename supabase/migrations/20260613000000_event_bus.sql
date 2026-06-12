-- RALD Ecosystem — Event Bus Schema
-- Phase 1 of Final Hardening + Event Bus + Governance Plan
-- The Event Bus is the nervous system of the RALD ecosystem.
-- Every product publishes events. Every consumer subscribes.
-- Features: replay protection, dead letter queue, retries, audit logging.
-- LILCKY STUDIO LIMITED — 2026-06-13

-- ═══════════════════════════════════════════════════════════════
-- PART A: EVENT DEFINITIONS REGISTRY
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS event_definitions (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type    TEXT NOT NULL UNIQUE,        -- e.g. "USER_CREATED", "ROOM_CREATED"
  domain        TEXT NOT NULL,               -- e.g. "auth", "loop", "messenger", "system"
  description   TEXT NOT NULL DEFAULT '',
  schema_version INT  NOT NULL DEFAULT 1,    -- increment when payload shape changes
  is_active     BOOLEAN NOT NULL DEFAULT true,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed all core, loop, messenger, and future events
INSERT INTO event_definitions (event_type, domain, description) VALUES
  -- Core auth/identity events
  ('USER_CREATED',              'auth',      'New user account created'),
  ('USER_UPDATED',              'auth',      'User profile or account updated'),
  ('USER_DELETED',              'auth',      'User account deleted or scheduled for deletion'),
  ('USERNAME_CLAIMED',          'auth',      'Username claimed by a user'),
  ('USERNAME_RELEASED',         'auth',      'Username released back to available pool'),
  ('USERNAME_PROTECTED',        'auth',      'Username marked protected by admin'),
  ('USERNAME_TRANSFER_STARTED', 'auth',      'Username transfer/settlement process initiated'),
  ('USERNAME_TRANSFER_SETTLED', 'auth',      'Username transfer completed and settled'),
  ('PROFILE_UPDATED',           'auth',      'Public profile updated'),
  ('DEVICE_REGISTERED',         'auth',      'New device registered for user'),
  ('DEVICE_TRUSTED',            'auth',      'Device promoted to trusted status'),
  ('DEVICE_REVOKED',            'auth',      'Device revoked/removed'),
  ('SESSION_CREATED',           'auth',      'New session issued'),
  ('SESSION_REVOKED',           'auth',      'Session explicitly revoked'),
  ('VERIFICATION_APPLIED',      'auth',      'User applied for verification badge'),
  ('VERIFICATION_GRANTED',      'auth',      'Verification badge granted'),
  ('TRUST_SCORE_UPDATED',       'auth',      'User trust score recomputed'),
  ('MACHINE_IDENTITY_ROTATED',  'auth',      'Machine service identity key rotated'),
  -- Loop events
  ('ROOM_CREATED',              'loop',      'Audio room created'),
  ('ROOM_JOINED',               'loop',      'User joined an audio room'),
  ('ROOM_LEFT',                 'loop',      'User left an audio room'),
  ('ROOM_ENDED',                'loop',      'Audio room ended'),
  ('COMMUNITY_CREATED',         'loop',      'Loop community created'),
  ('COMMUNITY_JOINED',          'loop',      'User joined a community'),
  ('COMMUNITY_LEFT',            'loop',      'User left a community'),
  -- Messenger events
  ('MESSAGE_SENT',              'messenger', 'Direct or group message sent'),
  ('MESSAGE_RECEIVED',          'messenger', 'Message delivered to recipient'),
  ('THREAD_CREATED',            'messenger', 'New conversation thread created'),
  -- Workspace events
  ('WORKSPACE_CREATED',         'workspace', 'New workspace created'),
  ('WORKSPACE_MEMBER_ADDED',    'workspace', 'Member added to workspace'),
  ('WORKSPACE_MEMBER_REMOVED',  'workspace', 'Member removed from workspace'),
  -- Governance events
  ('COUNTRY_ACTIVATED',         'governance','Country moved to active status'),
  ('COUNTRY_RESTRICTED',        'governance','Country access restricted'),
  ('KILL_SWITCH_ACTIVATED',     'governance','Emergency kill switch activated'),
  ('KILL_SWITCH_DEACTIVATED',   'governance','Emergency kill switch deactivated'),
  -- Future events (foundation only — not active)
  ('MAIL_RECEIVED',             'mail',      '[FUTURE] Email received at username@rald.me'),
  ('PAYMENT_CREATED',           'payments',  '[FUTURE] Payment intent created'),
  ('PAYMENT_COMPLETED',         'payments',  '[FUTURE] Payment completed'),
  ('ABUSE_DETECTED',            'moderation','Abuse signal detected by engine'),
  ('ABUSE_RESOLVED',            'moderation','Abuse case resolved')
ON CONFLICT (event_type) DO NOTHING;

-- ═══════════════════════════════════════════════════════════════
-- PART B: MAIN EVENT STORE
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS rald_events (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Identity
  event_type      TEXT NOT NULL REFERENCES event_definitions(event_type),
  domain          TEXT NOT NULL,                 -- copied for fast querying without join
  schema_version  INT  NOT NULL DEFAULT 1,

  -- Source
  source_service  TEXT NOT NULL,                 -- "rald-auth-core", "loop-api", etc.
  source_user_id  UUID REFERENCES auth_users(id) ON DELETE SET NULL,  -- NULL for system events
  source_ip       INET,
  source_request_id TEXT,                        -- X-Request-ID for tracing

  -- Payload
  payload         JSONB NOT NULL DEFAULT '{}',   -- event-specific data
  metadata        JSONB NOT NULL DEFAULT '{}',   -- headers, CF-Ray, country, etc.

  -- Idempotency / replay protection
  idempotency_key TEXT UNIQUE,                   -- optional; set by producer to prevent duplicates

  -- Delivery tracking
  status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','processing','delivered','failed','dead_lettered')),
  retry_count     INT  NOT NULL DEFAULT 0,
  max_retries     INT  NOT NULL DEFAULT 3,
  next_retry_at   TIMESTAMPTZ,
  last_error      TEXT,

  -- Audit
  processed_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rald_events_type_idx        ON rald_events(event_type);
CREATE INDEX IF NOT EXISTS rald_events_domain_idx      ON rald_events(domain);
CREATE INDEX IF NOT EXISTS rald_events_user_idx        ON rald_events(source_user_id) WHERE source_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS rald_events_status_idx      ON rald_events(status) WHERE status IN ('pending','failed');
CREATE INDEX IF NOT EXISTS rald_events_created_idx     ON rald_events(created_at DESC);
CREATE INDEX IF NOT EXISTS rald_events_idem_idx        ON rald_events(idempotency_key) WHERE idempotency_key IS NOT NULL;

ALTER TABLE rald_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY "rald_events: service full access" ON rald_events FOR ALL USING (true) WITH CHECK (true);

-- ═══════════════════════════════════════════════════════════════
-- PART C: EVENT SUBSCRIPTIONS
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS event_subscriptions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subscriber_name TEXT NOT NULL,             -- e.g. "rald-notify", "rald-search"
  event_type      TEXT NOT NULL REFERENCES event_definitions(event_type),
  webhook_url     TEXT,                      -- NULL = internal queue pull
  is_active       BOOLEAN NOT NULL DEFAULT true,
  filter_jsonpath TEXT,                      -- optional JSONPath filter on payload
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (subscriber_name, event_type)
);

-- Core subscriptions
INSERT INTO event_subscriptions (subscriber_name, event_type, is_active) VALUES
  ('rald-notify',   'USER_CREATED',          true),
  ('rald-notify',   'DEVICE_REGISTERED',     true),
  ('rald-notify',   'SESSION_REVOKED',       true),
  ('rald-notify',   'MACHINE_IDENTITY_ROTATED', true),
  ('rald-search',   'USER_CREATED',          true),
  ('rald-search',   'PROFILE_UPDATED',       true),
  ('rald-search',   'USERNAME_CLAIMED',      true),
  ('rald-search',   'USERNAME_RELEASED',     true),
  ('rald-inbox',    'MESSAGE_SENT',          true),
  ('rald-inbox',    'MESSAGE_RECEIVED',      true),
  ('rald-realtime', 'ROOM_CREATED',          true),
  ('rald-realtime', 'ROOM_JOINED',           true),
  ('rald-realtime', 'ROOM_LEFT',             true),
  ('rald-realtime', 'ROOM_ENDED',            true)
ON CONFLICT (subscriber_name, event_type) DO NOTHING;

-- ═══════════════════════════════════════════════════════════════
-- PART D: DEAD LETTER QUEUE
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS event_dead_letter_queue (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  original_event_id UUID NOT NULL REFERENCES rald_events(id) ON DELETE CASCADE,
  subscriber_name TEXT NOT NULL,
  failure_reason  TEXT NOT NULL,
  failure_count   INT  NOT NULL DEFAULT 1,
  last_failed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at     TIMESTAMPTZ,                -- NULL = still dead; set when re-processed
  resolution_note TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS event_dlq_subscriber_idx ON event_dead_letter_queue(subscriber_name);
CREATE INDEX IF NOT EXISTS event_dlq_resolved_idx   ON event_dead_letter_queue(resolved_at) WHERE resolved_at IS NULL;

ALTER TABLE event_dead_letter_queue ENABLE ROW LEVEL SECURITY;
CREATE POLICY "event_dlq: service full access" ON event_dead_letter_queue FOR ALL USING (true) WITH CHECK (true);

-- ═══════════════════════════════════════════════════════════════
-- PART E: EVENT REPLAY LOG
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS event_replay_log (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  replayed_event_id UUID NOT NULL REFERENCES rald_events(id) ON DELETE CASCADE,
  replayed_by     TEXT NOT NULL,             -- service or admin user_id
  reason          TEXT NOT NULL DEFAULT '',
  replayed_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ═══════════════════════════════════════════════════════════════
-- PART F: CONVENIENCE VIEW — pending events
-- ═══════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW pending_events AS
SELECT
  e.id,
  e.event_type,
  e.domain,
  e.source_service,
  e.source_user_id,
  e.payload,
  e.status,
  e.retry_count,
  e.next_retry_at,
  e.created_at
FROM rald_events e
WHERE e.status IN ('pending', 'failed')
  AND (e.next_retry_at IS NULL OR e.next_retry_at <= now())
ORDER BY e.created_at ASC;

COMMENT ON TABLE rald_events IS 'RALD Ecosystem Event Bus — central event store for all cross-service events';
COMMENT ON TABLE event_dead_letter_queue IS 'Events that failed all retries — require manual inspection and re-processing';
COMMENT ON TABLE event_subscriptions IS 'Per-service event subscriptions — defines which services consume which events';
