-- RALD Auth Core — Machine Identity Seed
-- Sprint: Public Beta Hardening · 2026-06-15
--
-- Inserts the initial set of machine identity records for all ecosystem services
-- that authenticate service-to-service via the /machine/auth endpoint.
--
-- HOW IT WORKS:
--   1. This migration inserts a row per service with a placeholder secret.
--   2. After migration, the operator MUST run the provisioning script:
--        scripts/provision-machine-identities.sh
--      which calls POST /machine/identities/rotate for each service and sets the
--      real secret via: wrangler secret put MACHINE_KEY_SECRET
--   3. The `key_id` (mid_*) is stable and committed here. The actual secret is
--      never stored in Git — it is set via wrangler secrets.
--
-- SECURITY: The placeholder `secret_hash` inserted here is a random SHA-256 hash
-- of a known-invalid string. It will be overwritten by the provisioning script.
-- The machine_identities table stores hashed secrets, not plaintext.
-- LILCKY STUDIO LIMITED

-- Ensure the table exists (safe guard — created in 20260612400000)
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.tables WHERE table_name = 'machine_identities'
  ) THEN
    RAISE EXCEPTION 'machine_identities table missing — run 20260612400000_machine_identity.sql first';
  END IF;
END $$;

-- ── Ecosystem service machine identities ──────────────────────────────────────
-- key_id values are stable identifiers; secrets are provisioned separately.
-- ON CONFLICT DO NOTHING: re-running this migration is safe.

INSERT INTO machine_identities (
  id, service_name, display_name, environment, status,
  key_id, secret_hash,
  scopes, rotation_due_at, created_at, updated_at
) VALUES

-- loop-api: fires room events, follow notifications, DMs to notify service
(
  gen_random_uuid(),
  'loop-api',
  'Loop API Worker',
  'production',
  'active',
  'mid_loop_api_prod_001',
  encode(sha256('PLACEHOLDER_loop_api_prod_001__MUST_ROTATE_VIA_PROVISIONING_SCRIPT'), 'hex'),
  ARRAY['notify:send', 'events:publish', 'search:index'],
  NOW() + INTERVAL '90 days',
  NOW(), NOW()
),

-- messenger: fires message notifications, DM events
(
  gen_random_uuid(),
  'messenger',
  'Messenger API Worker',
  'production',
  'active',
  'mid_messenger_prod_001',
  encode(sha256('PLACEHOLDER_messenger_prod_001__MUST_ROTATE_VIA_PROVISIONING_SCRIPT'), 'hex'),
  ARRAY['notify:send', 'events:publish'],
  NOW() + INTERVAL '90 days',
  NOW(), NOW()
),

-- rald-event-bus: ecosystem event routing
(
  gen_random_uuid(),
  'rald-event-bus',
  'RALD Event Bus',
  'production',
  'active',
  'mid_event_bus_prod_001',
  encode(sha256('PLACEHOLDER_event_bus_prod_001__MUST_ROTATE_VIA_PROVISIONING_SCRIPT'), 'hex'),
  ARRAY['events:publish', 'events:subscribe', 'identity:read'],
  NOW() + INTERVAL '90 days',
  NOW(), NOW()
),

-- rald-config: reads feature flags, writes config state
(
  gen_random_uuid(),
  'rald-config',
  'RALD Config Service',
  'production',
  'active',
  'mid_config_prod_001',
  encode(sha256('PLACEHOLDER_config_prod_001__MUST_ROTATE_VIA_PROVISIONING_SCRIPT'), 'hex'),
  ARRAY['config:read', 'config:write'],
  NOW() + INTERVAL '90 days',
  NOW(), NOW()
),

-- rald-search: indexes user and content data
(
  gen_random_uuid(),
  'rald-search',
  'RALD Search Service',
  'production',
  'active',
  'mid_search_prod_001',
  encode(sha256('PLACEHOLDER_search_prod_001__MUST_ROTATE_VIA_PROVISIONING_SCRIPT'), 'hex'),
  ARRAY['search:index', 'search:read', 'identity:read'],
  NOW() + INTERVAL '90 days',
  NOW(), NOW()
),

-- rald-notify: sends notifications across channels
(
  gen_random_uuid(),
  'rald-notify',
  'RALD Notify Service',
  'production',
  'active',
  'mid_notify_prod_001',
  encode(sha256('PLACEHOLDER_notify_prod_001__MUST_ROTATE_VIA_PROVISIONING_SCRIPT'), 'hex'),
  ARRAY['notify:send', 'notify:read'],
  NOW() + INTERVAL '90 days',
  NOW(), NOW()
),

-- rald-realtime: room state coordination
(
  gen_random_uuid(),
  'rald-realtime',
  'RALD Realtime Service',
  'production',
  'active',
  'mid_realtime_prod_001',
  encode(sha256('PLACEHOLDER_realtime_prod_001__MUST_ROTATE_VIA_PROVISIONING_SCRIPT'), 'hex'),
  ARRAY['events:publish', 'identity:read'],
  NOW() + INTERVAL '90 days',
  NOW(), NOW()
),

-- rald-auth (self) — auth service calling notify for rotation alerts
(
  gen_random_uuid(),
  'rald-auth',
  'RALD Auth Core (self)',
  'production',
  'active',
  'mid_auth_prod_001',
  encode(sha256('PLACEHOLDER_auth_prod_001__MUST_ROTATE_VIA_PROVISIONING_SCRIPT'), 'hex'),
  ARRAY['notify:send', 'identity:read', 'identity:write'],
  NOW() + INTERVAL '90 days',
  NOW(), NOW()
)

ON CONFLICT (key_id) DO NOTHING;

-- ── Verify seed worked ─────────────────────────────────────────────────────────
DO $$ DECLARE cnt INT; BEGIN
  SELECT COUNT(*) INTO cnt FROM machine_identities WHERE status = 'active';
  IF cnt < 8 THEN
    RAISE WARNING 'machine_identities seed: expected >= 8 active rows, found %', cnt;
  ELSE
    RAISE NOTICE 'machine_identities seed: % active machine identities registered', cnt;
  END IF;
END $$;

COMMENT ON TABLE machine_identities IS
  'Machine identity registry. Seeded 2026-06-15 with 8 ecosystem services. '
  'Secrets are PLACEHOLDERS — run scripts/provision-machine-identities.sh after migration.';
