-- RALD Auth Core — Trust Engine Schema
-- Sprint: Operator Platform Phase 5 · 2026-06-12
-- Centralized trust score computation replacing per-column trust_level string.
-- Trust score is computed from signals and cached in trust_scores table.
-- Products read trust from trust_scores, not auth_users.trust_level.
-- LILCKY STUDIO LIMITED

-- ── trust_scores — computed trust state ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS trust_scores (
  user_id          UUID PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,

  -- Composite score (0.0 – 1.0)
  score            NUMERIC(4,3) NOT NULL DEFAULT 0.0
                     CHECK (score BETWEEN 0.0 AND 1.0),
  tier             TEXT NOT NULL DEFAULT 'none'
                     CHECK (tier IN ('none','basic','standard','verified','creator','civic','premium')),

  -- Signal breakdown
  signal_phone_verified       BOOLEAN NOT NULL DEFAULT false,
  signal_email_verified       BOOLEAN NOT NULL DEFAULT false,
  signal_username_verified    BOOLEAN NOT NULL DEFAULT false,
  signal_id_verified          BOOLEAN NOT NULL DEFAULT false,
  signal_creator_verified     BOOLEAN NOT NULL DEFAULT false,
  signal_business_verified    BOOLEAN NOT NULL DEFAULT false,
  signal_civic_verified       BOOLEAN NOT NULL DEFAULT false,
  signal_account_age_days     INTEGER NOT NULL DEFAULT 0,
  signal_session_count        INTEGER NOT NULL DEFAULT 0,
  signal_community_standing   TEXT NOT NULL DEFAULT 'good'
                                 CHECK (signal_community_standing IN ('good','warning','restricted','banned')),

  -- History
  previous_score   NUMERIC(4,3),
  previous_tier    TEXT,
  last_computed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS trust_scores_tier_idx   ON trust_scores(tier);
CREATE INDEX IF NOT EXISTS trust_scores_score_idx  ON trust_scores(score DESC);

ALTER TABLE trust_scores ENABLE ROW LEVEL SECURITY;
CREATE POLICY "trust_scores: own read"
  ON trust_scores FOR SELECT USING (user_id = auth.uid());
CREATE POLICY "trust_scores: service write"
  ON trust_scores FOR ALL USING (true) WITH CHECK (true);

-- ── compute_trust_score — the trust engine function ──────────────────────────
CREATE OR REPLACE FUNCTION compute_trust_score(p_user_id UUID)
RETURNS TABLE (
  score NUMERIC,
  tier  TEXT
) LANGUAGE plpgsql AS $$
DECLARE
  v_score    NUMERIC(4,3) := 0.0;
  v_tier     TEXT         := 'none';
  v_cap      identity_capabilities%ROWTYPE;
  v_user     auth_users%ROWTYPE;
  v_age_days INTEGER      := 0;
BEGIN
  -- Fetch user + capabilities
  SELECT * INTO v_user FROM auth_users WHERE id = p_user_id;
  SELECT * INTO v_cap  FROM identity_capabilities WHERE user_id = p_user_id;

  IF NOT FOUND THEN
    RETURN QUERY SELECT 0.0::NUMERIC, 'none'::TEXT;
    RETURN;
  END IF;

  -- Account age
  v_age_days := EXTRACT(EPOCH FROM (now() - v_user.created_at)) / 86400;

  -- Signal scoring (cumulative)
  IF v_cap.phone_verified    THEN v_score := v_score + 0.15; END IF;
  IF v_cap.email_verified    THEN v_score := v_score + 0.10; END IF;
  IF v_cap.username_verified THEN v_score := v_score + 0.05; END IF;

  -- Verification signals (heavy weight)
  IF v_cap.id_verified        THEN v_score := v_score + 0.25; END IF;
  IF v_cap.creator_verified   THEN v_score := v_score + 0.15; END IF;
  IF v_cap.business_verified  THEN v_score := v_score + 0.15; END IF;
  IF v_cap.civic_verified     THEN v_score := v_score + 0.10; END IF;

  -- Account age signal (max 0.05 after 30 days)
  v_score := v_score + LEAST(v_age_days::NUMERIC / 30.0 * 0.05, 0.05);

  -- Cap at 1.0
  v_score := LEAST(v_score, 1.0);

  -- Determine tier from score
  v_tier := CASE
    WHEN v_score >= 0.80 THEN 'premium'
    WHEN v_cap.creator_verified THEN 'creator'
    WHEN v_cap.civic_verified   THEN 'civic'
    WHEN v_cap.business_verified THEN 'premium'
    WHEN v_score >= 0.55 THEN 'verified'
    WHEN v_score >= 0.35 THEN 'standard'
    WHEN v_score >= 0.15 THEN 'basic'
    ELSE 'none'
  END;

  -- Upsert trust_scores
  INSERT INTO trust_scores (
    user_id, score, tier,
    signal_phone_verified, signal_email_verified, signal_username_verified,
    signal_id_verified, signal_creator_verified, signal_business_verified,
    signal_civic_verified, signal_account_age_days,
    last_computed_at, updated_at
  ) VALUES (
    p_user_id, v_score, v_tier,
    v_cap.phone_verified, v_cap.email_verified, v_cap.username_verified,
    v_cap.id_verified, COALESCE(v_cap.creator_verified, false),
    v_cap.business_verified, v_cap.civic_verified,
    v_age_days, now(), now()
  )
  ON CONFLICT (user_id) DO UPDATE SET
    previous_score            = trust_scores.score,
    previous_tier             = trust_scores.tier,
    score                     = EXCLUDED.score,
    tier                      = EXCLUDED.tier,
    signal_phone_verified     = EXCLUDED.signal_phone_verified,
    signal_email_verified     = EXCLUDED.signal_email_verified,
    signal_username_verified  = EXCLUDED.signal_username_verified,
    signal_id_verified        = EXCLUDED.signal_id_verified,
    signal_creator_verified   = EXCLUDED.signal_creator_verified,
    signal_business_verified  = EXCLUDED.signal_business_verified,
    signal_civic_verified     = EXCLUDED.signal_civic_verified,
    signal_account_age_days   = EXCLUDED.signal_account_age_days,
    last_computed_at          = now(),
    updated_at                = now();

  RETURN QUERY SELECT v_score::NUMERIC, v_tier::TEXT;
END;
$$;

COMMENT ON FUNCTION compute_trust_score IS
  'Computes and persists the trust score for a user based on identity signals. Call on any verification event.';
