-- RALD Auth Core — Search RPC Signature Fix
-- Sprint: Public Beta Hardening · 2026-06-14
--
-- PROBLEM: The deployed search_users_public RPC has signature:
--   search_users_public(search_query TEXT, result_limit INTEGER, result_offset INTEGER)
--
-- But routes/search.ts calls:
--   db.rpc("search_users_public", {
--     p_query, p_pattern, p_limit, p_username,
--     p_display_name, p_rald_address, p_location, p_interests
--   })
--
-- FIX: Drop and recreate the RPC with the correct p_-prefixed parameter names
-- plus the additional filtering parameters (location, interests, field-specific).
-- LILCKY STUDIO LIMITED

-- First ensure the auth_user_profiles table has location + interests columns
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'auth_user_profiles' AND column_name = 'location'
  ) THEN
    ALTER TABLE auth_user_profiles ADD COLUMN location TEXT;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'auth_user_profiles' AND column_name = 'interests'
  ) THEN
    ALTER TABLE auth_user_profiles ADD COLUMN interests TEXT[] NOT NULL DEFAULT '{}';
  END IF;
END $$;

-- Drop old signature
DROP FUNCTION IF EXISTS search_users_public(TEXT, INTEGER, INTEGER);

-- Recreate with correct p_-prefixed parameters matching the TypeScript route caller
CREATE OR REPLACE FUNCTION search_users_public(
  p_query        TEXT    DEFAULT NULL,
  p_pattern      TEXT    DEFAULT NULL,   -- ILIKE pattern override (e.g. "@foo%")
  p_limit        INTEGER DEFAULT 20,
  p_username     TEXT    DEFAULT NULL,   -- exact username filter
  p_display_name TEXT    DEFAULT NULL,   -- exact display_name filter
  p_rald_address TEXT    DEFAULT NULL,   -- exact RALD-XXXXXX address
  p_location     TEXT    DEFAULT NULL,   -- city/country substring match
  p_interests    TEXT[]  DEFAULT NULL    -- overlap filter on interests array
)
RETURNS TABLE (
  id            UUID,
  display_name  TEXT,
  username      TEXT,
  avatar_url    TEXT,
  bio           TEXT,
  is_verified   BOOLEAN,
  rald_address  TEXT,
  location      TEXT,
  interests     TEXT[],
  rank          REAL
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  tsq tsquery;
  effective_limit INTEGER := LEAST(COALESCE(p_limit, 20), 100);
BEGIN
  -- Build full-text query from free-text input
  IF p_query IS NOT NULL AND p_query <> '' THEN
    BEGIN
      tsq := plainto_tsquery('english', p_query);
    EXCEPTION WHEN OTHERS THEN
      tsq := NULL;
    END;
  END IF;

  RETURN QUERY
    SELECT
      p.user_id      AS id,
      p.display_name,
      p.username,
      p.avatar_url,
      p.bio,
      COALESCE(p.is_verified, false)  AS is_verified,
      p.rald_address,
      p.location,
      p.interests,
      CASE
        WHEN tsq IS NOT NULL THEN
          ts_rank(
            to_tsvector('english',
              COALESCE(p.display_name, '') || ' ' ||
              COALESCE(p.username, '')     || ' ' ||
              COALESCE(p.bio, '')          || ' ' ||
              COALESCE(p.location, '')
            ),
            tsq
          )::REAL
        ELSE 0.5::REAL
      END AS rank
    FROM auth_user_profiles p
    WHERE
      -- Privacy gate
      COALESCE(p.search_discoverable, true) = true

      -- Full-text match (optional)
      AND (
        tsq IS NULL
        OR to_tsvector('english',
              COALESCE(p.display_name, '') || ' ' ||
              COALESCE(p.username, '')     || ' ' ||
              COALESCE(p.bio, '')          || ' ' ||
              COALESCE(p.location, '')
           ) @@ tsq
        OR p.display_name ILIKE '%' || COALESCE(p_query, '') || '%'
        OR p.username      ILIKE '%' || COALESCE(p_query, '') || '%'
      )

      -- ILIKE pattern override
      AND (
        p_pattern IS NULL
        OR p.username     ILIKE p_pattern
        OR p.display_name ILIKE p_pattern
        OR p.rald_address ILIKE p_pattern
      )

      -- Exact field filters (all optional)
      AND (p_username     IS NULL OR p.username     ILIKE p_username)
      AND (p_display_name IS NULL OR p.display_name ILIKE p_display_name)
      AND (p_rald_address IS NULL OR p.rald_address = p_rald_address)

      -- Location substring
      AND (p_location IS NULL OR p.location ILIKE '%' || p_location || '%')

      -- Interests overlap
      AND (p_interests IS NULL OR p.interests && p_interests)

    ORDER BY rank DESC, p.created_at DESC
    LIMIT effective_limit;
END;
$$;

GRANT EXECUTE ON FUNCTION search_users_public TO service_role;
GRANT EXECUTE ON FUNCTION search_users_public TO anon;

COMMENT ON FUNCTION search_users_public IS
  'Public user search. Parameters use p_ prefix to match the TypeScript route caller. Fixed 2026-06-14.';
