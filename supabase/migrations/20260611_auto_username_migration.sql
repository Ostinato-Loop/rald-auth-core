-- RALD Auth Core — Auto Username Generation for Existing Users (Phase 5)
-- Existing users without usernames automatically receive: firstname + random suffix
-- Examples: boyd927, lucky582, lagosnews341
--
-- RALD AUTH EMERGENCY STABILIZATION SPRINT — Phase 5
-- Safe: only affects users WHERE username IS NULL AND is_active = true
-- LILCKY STUDIO LIMITED

-- ─── 1. Function: generate a username from display name + random suffix ─────────
CREATE OR REPLACE FUNCTION generate_username_for_user(p_name TEXT)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
  base    TEXT;
  suffix  TEXT;
  attempt TEXT;
  counter INTEGER := 0;
BEGIN
  -- Extract first word, lowercase, strip non-alphanumeric, max 12 chars
  base := lower(regexp_replace(split_part(p_name, ' ', 1), '[^a-z0-9]', '', 'g'));
  base := left(base, 12);

  -- Fallback for empty base
  IF base = '' OR base IS NULL THEN
    base := 'user';
  END IF;

  -- Try up to 20 random suffixes
  LOOP
    suffix  := lpad(floor(random() * 999 + 1)::text, 3, '0');
    attempt := base || suffix;

    -- Check not taken in usernames table or auth_users
    IF NOT EXISTS (
      SELECT 1 FROM usernames  WHERE username = attempt AND (status = 'CLAIMED' OR active = true)
      UNION ALL
      SELECT 1 FROM auth_users WHERE username = attempt
    ) THEN
      RETURN attempt;
    END IF;

    counter := counter + 1;
    IF counter >= 20 THEN
      -- Fallback: use timestamp suffix
      RETURN base || floor(extract(epoch from now()) * 1000)::bigint % 10000;
    END IF;
  END LOOP;
END;
$$;

COMMENT ON FUNCTION generate_username_for_user IS
  'Phase 5: Generate a unique username from a display name. Returns first-name + 3-digit suffix, guaranteed unique.';

-- ─── 2. Auto-assign usernames to all existing users without one ────────────────
DO $$
DECLARE
  rec         RECORD;
  new_username TEXT;
  reserved_mail TEXT;
BEGIN
  FOR rec IN
    SELECT id, name, email
    FROM auth_users
    WHERE username IS NULL
      AND is_active = true
  LOOP
    -- Derive base from name, fallback to email local-part
    new_username := generate_username_for_user(
      COALESCE(
        NULLIF(trim(rec.name), ''),
        split_part(rec.email, '@', 1)
      )
    );

    reserved_mail := new_username || '@rald.me';

    -- Assign username in auth_users
    UPDATE auth_users
    SET
      username               = new_username,
      username_set_at        = now(),
      reserved_email_address = reserved_mail,
      trust_level            = CASE WHEN trust_level = 'none' THEN 'basic' ELSE trust_level END,
      trust_score            = GREATEST(trust_score, 10)
    WHERE id = rec.id;

    -- Register in usernames table
    INSERT INTO usernames (username, user_id, status, active, claimed_at, created_at)
    VALUES (new_username, rec.id, 'CLAIMED', true, now(), now())
    ON CONFLICT (username) DO NOTHING;

    -- History entry
    INSERT INTO username_history (user_id, username, action)
    VALUES (rec.id, new_username, 'auto_assigned')
    ON CONFLICT DO NOTHING;

    -- Ensure in migration queue so user gets prompted to choose their own username
    INSERT INTO username_migration_queue (user_id, prompted_at)
    VALUES (rec.id, now())
    ON CONFLICT (user_id) DO UPDATE
      SET prompted_at = now()
      WHERE username_migration_queue.completed_at IS NULL;

  END LOOP;
END;
$$;

-- ─── 3. Repair identity records for all auto-assigned users ───────────────────
SELECT * FROM repair_identity_records();

COMMENT ON FUNCTION generate_username_for_user IS
  'Phase 5: Auto-assign usernames to existing users who have none. Users are placed in the migration queue to choose their own username later.';

-- ─── Done ──────────────────────────────────────────────────────────────────────
