-- RALD Auth Core — Verification Engine Migration
-- Phase 6: Artist, Label, Radio, Advertiser, Media House, Community verification
-- Profiles.RALD.Cloud Hardening Program — LILCKY STUDIO LIMITED
-- 2026-06-06

BEGIN;

CREATE TABLE IF NOT EXISTS auth_verifications (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  verification_type TEXT NOT NULL CHECK (verification_type IN (
    'artist', 'label', 'radio', 'advertiser', 'media_house', 'community'
  )),
  status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
    'pending', 'under_review', 'approved', 'rejected'
  )),
  name              TEXT NOT NULL,
  description       TEXT,
  website           TEXT,
  social_links      JSONB DEFAULT '{}'::jsonb,
  documents         TEXT[]  DEFAULT '{}',
  metadata          JSONB DEFAULT '{}'::jsonb,
  reviewer_id       UUID,
  reviewer_note     TEXT,
  submitted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  reviewed_at       TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_auth_verifications_user_id    ON auth_verifications(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_verifications_status     ON auth_verifications(status);
CREATE INDEX IF NOT EXISTS idx_auth_verifications_type       ON auth_verifications(verification_type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_verifications_user_type_active
  ON auth_verifications(user_id, verification_type)
  WHERE status IN ('pending', 'under_review', 'approved');

-- RLS
ALTER TABLE auth_verifications ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own verifications"
  ON auth_verifications FOR SELECT
  USING (user_id = auth.uid());

CREATE POLICY "Users can insert their own verifications"
  ON auth_verifications FOR INSERT
  WITH CHECK (user_id = auth.uid());

CREATE POLICY "Users can delete their pending verifications"
  ON auth_verifications FOR DELETE
  USING (user_id = auth.uid() AND status IN ('pending'));

CREATE POLICY "Service role has full access"
  ON auth_verifications FOR ALL
  USING (true);

-- Updated_at trigger
CREATE OR REPLACE FUNCTION update_auth_verifications_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_auth_verifications_updated_at
  BEFORE UPDATE ON auth_verifications
  FOR EACH ROW EXECUTE FUNCTION update_auth_verifications_updated_at();

COMMIT;
