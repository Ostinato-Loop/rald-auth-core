-- RALD Auth Core — Sync Identity Capabilities Trigger
-- Sprint: Hardening Phase 7 · Database Hardening · 2026-06-12
-- Ensures identity_capabilities stays in sync automatically when auth_users changes.
-- LILCKY STUDIO LIMITED

CREATE OR REPLACE FUNCTION sync_identity_capabilities_from_auth_users()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO identity_capabilities (
    user_id,
    username,         username_verified,
    email,            email_verified,
    phone,            phone_verified,
    trust_level,
    completed_onboarding,
    updated_at
  )
  VALUES (
    NEW.id,
    NEW.username,
    COALESCE(NEW.username_verified, NEW.username IS NOT NULL),
    NEW.email,
    COALESCE(NEW.email_verified, false),
    NEW.phone_number,
    COALESCE(NEW.phone_verified, false),
    COALESCE(NEW.trust_level, 'none'),
    false,
    now()
  )
  ON CONFLICT (user_id) DO UPDATE SET
    username           = EXCLUDED.username,
    username_verified  = EXCLUDED.username_verified,
    email              = EXCLUDED.email,
    email_verified     = EXCLUDED.email_verified,
    phone              = EXCLUDED.phone,
    phone_verified     = EXCLUDED.phone_verified,
    trust_level        = EXCLUDED.trust_level,
    updated_at         = now()
  -- only update fields that actually changed
  WHERE
    identity_capabilities.username          IS DISTINCT FROM EXCLUDED.username          OR
    identity_capabilities.username_verified IS DISTINCT FROM EXCLUDED.username_verified OR
    identity_capabilities.email             IS DISTINCT FROM EXCLUDED.email             OR
    identity_capabilities.email_verified    IS DISTINCT FROM EXCLUDED.email_verified    OR
    identity_capabilities.phone             IS DISTINCT FROM EXCLUDED.phone             OR
    identity_capabilities.phone_verified    IS DISTINCT FROM EXCLUDED.phone_verified    OR
    identity_capabilities.trust_level       IS DISTINCT FROM EXCLUDED.trust_level;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_sync_identity_capabilities ON auth_users;
CREATE TRIGGER trg_sync_identity_capabilities
  AFTER INSERT OR UPDATE OF
    username, username_verified, email, email_verified,
    phone_number, phone_verified, trust_level
  ON auth_users
  FOR EACH ROW
  EXECUTE FUNCTION sync_identity_capabilities_from_auth_users();
