-- RALD Auth — WebAuthn / FIDO2 Credentials
-- Run in Supabase SQL Editor before enabling biometric login
-- All ALTER TABLE are idempotent (IF NOT EXISTS).
-- LILCKY STUDIO LIMITED

-- ── WebAuthn credentials table ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid        NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  credential_id text        NOT NULL UNIQUE,      -- Base64URL-encoded credential ID
  public_key    text        NOT NULL,             -- Base64URL-encoded COSE public key
  counter       bigint      NOT NULL DEFAULT 0,   -- Signature counter (anti-replay)
  device_type   text,                             -- "singleDevice" | "multiDevice"
  backed_up     boolean     DEFAULT false,        -- Synced credential (passkey)
  transports    text[]      DEFAULT '{}',         -- ["internal","hybrid",...] 
  created_at    timestamptz DEFAULT now(),
  last_used_at  timestamptz
);

CREATE INDEX IF NOT EXISTS webauthn_credentials_user_id_idx
  ON webauthn_credentials(user_id);

-- ── Row Level Security ────────────────────────────────────────────────────────
ALTER TABLE webauthn_credentials ENABLE ROW LEVEL SECURITY;

-- Service role bypasses RLS (worker uses service role key)
CREATE POLICY IF NOT EXISTS "service_role_all" ON webauthn_credentials
  FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

-- ── Comment ───────────────────────────────────────────────────────────────────
COMMENT ON TABLE webauthn_credentials IS
  'FIDO2 / WebAuthn passkey credentials registered by RALD Identity users. '
  'Public key is stored Base64URL-encoded COSE format. '
  'Counter must increase on every authentication to prevent credential cloning.';
