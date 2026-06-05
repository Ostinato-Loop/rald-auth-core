-- ============================================================
-- RALD Auth Core — search_users_public RPC
-- Called by /search/users to find discoverable users by text.
-- Falls back to direct query if RPC not deployed — this RPC
-- is preferred because it handles tsvector ranking.
-- Run at: https://supabase.com/dashboard/project/onxdcikfttdmnhofsuwo/sql/new
-- LILCKY STUDIO LIMITED — 2026-06-05
-- ============================================================

CREATE OR REPLACE FUNCTION search_users_public(
  search_query  TEXT,
  result_limit  INTEGER DEFAULT 20,
  result_offset INTEGER DEFAULT 0
)
RETURNS TABLE (
  id            UUID,
  display_name  TEXT,
  username      TEXT,
  avatar_url    TEXT,
  bio           TEXT,
  is_verified   BOOLEAN,
  rald_address  TEXT,
  rank          REAL
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  tsq tsquery;
BEGIN
  tsq := plainto_tsquery('english', search_query);
  RETURN QUERY
    SELECT
      p.user_id      AS id,
      p.display_name,
      p.username,
      p.avatar_url,
      p.bio,
      COALESCE(p.is_verified, false)       AS is_verified,
      p.rald_address,
      ts_rank(
        to_tsvector('english',
          COALESCE(p.display_name,'') || ' ' ||
          COALESCE(p.username,'')     || ' ' ||
          COALESCE(p.bio,'')
        ),
        tsq
      )::REAL AS rank
    FROM auth_user_profiles p
    WHERE
      COALESCE(p.search_discoverable, true) = true
      AND (
        tsq IS NULL
        OR to_tsvector('english',
              COALESCE(p.display_name,'') || ' ' ||
              COALESCE(p.username,'')     || ' ' ||
              COALESCE(p.bio,'')
           ) @@ tsq
        OR p.display_name ILIKE '%' || search_query || '%'
        OR p.username      ILIKE '%' || search_query || '%'
      )
    ORDER BY rank DESC, p.created_at DESC
    LIMIT  result_limit
    OFFSET result_offset;
END;
$$;

GRANT EXECUTE ON FUNCTION search_users_public TO service_role;
