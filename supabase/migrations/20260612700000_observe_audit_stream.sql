-- RALD — OpenObserve Audit Stream
-- Sprint: Hardening C-CERT-004 · 2026-06-12
-- Creates pg_net-based triggers on all RALD audit tables.
-- Each INSERT fires an async HTTP POST to the observe-stream Edge Function,
-- which forwards the payload to OpenObserve for real-time observability.
--
-- Dependencies:
--   pg_net extension (available on Supabase free + pro)
--   observe-stream Edge Function deployed at supabase/functions/observe-stream
--
-- Configuration GUCs (set once after applying this migration):
--   ALTER DATABASE postgres SET app.observe_stream_url    = 'https://onxdcikfttdmnhofsuwo.supabase.co/functions/v1/observe-stream';
--   ALTER DATABASE postgres SET app.observe_stream_secret = '<your-OBSERVE_STREAM_SECRET>';
--
-- LILCKY STUDIO LIMITED

-- ── Enable pg_net (async HTTP from PostgreSQL) ─────────────────────────────────
CREATE EXTENSION IF NOT EXISTS pg_net SCHEMA extensions;

-- ── observe_audit_entry() — generic trigger function ─────────────────────────
-- Fires on INSERT to any audit table.
-- Sends table name, event type, row data, and timestamp to observe-stream.
-- EXCEPTION block ensures observability never breaks the write path.
CREATE OR REPLACE FUNCTION observe_audit_entry()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _url    TEXT;
  _secret TEXT;
  _payload JSONB;
BEGIN
  -- Read config from GUCs — safe to call; returns NULL if not set
  _url    := current_setting('app.observe_stream_url',    true);
  _secret := current_setting('app.observe_stream_secret', true);

  -- Skip if not configured — allows safe deployment before secrets are set
  IF _url IS NULL OR _url = '' THEN
    RETURN NEW;
  END IF;

  _payload := jsonb_build_object(
    'table',     TG_TABLE_NAME,
    'schema',    TG_TABLE_SCHEMA,
    'event',     TG_OP,
    'service',   TG_TABLE_NAME,
    'timestamp', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'data',      to_jsonb(NEW)
  );

  -- Fire-and-forget async HTTP POST — does NOT block the insert
  PERFORM extensions.net.http_post(
    url     := _url,
    body    := _payload::text,
    headers := jsonb_build_object(
      'Content-Type',  'application/json',
      'Authorization', 'Bearer ' || coalesce(_secret, '')
    )::jsonb
  );

  RETURN NEW;
EXCEPTION WHEN OTHERS THEN
  -- Observability must never fail the primary write path
  RAISE WARNING '[observe_audit_entry] trigger error: % — continuing', SQLERRM;
  RETURN NEW;
END;
$$;

-- ── Attach trigger to all RALD audit tables ────────────────────────────────────

-- rald-auth-core: primary audit log
DROP TRIGGER IF EXISTS observe_audit_logs_insert ON audit_logs;
CREATE TRIGGER observe_audit_logs_insert
  AFTER INSERT ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION observe_audit_entry();

-- rald-event-bus: event bus audit log
DROP TRIGGER IF EXISTS observe_event_bus_audit_insert ON event_bus_audit_logs;
CREATE TRIGGER observe_event_bus_audit_insert
  AFTER INSERT ON event_bus_audit_logs
  FOR EACH ROW EXECUTE FUNCTION observe_audit_entry();

-- rald-config: config change audit log
DROP TRIGGER IF EXISTS observe_config_audit_insert ON config_audit_logs;
CREATE TRIGGER observe_config_audit_insert
  AFTER INSERT ON config_audit_logs
  FOR EACH ROW EXECUTE FUNCTION observe_audit_entry();

-- rald-notify: notification audit log
DROP TRIGGER IF EXISTS observe_notification_audit_insert ON notification_audit_log;
CREATE TRIGGER observe_notification_audit_insert
  AFTER INSERT ON notification_audit_log
  FOR EACH ROW EXECUTE FUNCTION observe_audit_entry();

-- rald-auth-core: machine identity audit log
DROP TRIGGER IF EXISTS observe_machine_identity_audit_insert ON machine_identity_audit_log;
CREATE TRIGGER observe_machine_identity_audit_insert
  AFTER INSERT ON machine_identity_audit_log
  FOR EACH ROW EXECUTE FUNCTION observe_audit_entry();

-- ── Index for pg_net response monitoring ───────────────────────────────────────
-- Query: SELECT * FROM extensions.net._http_response ORDER BY created DESC LIMIT 50;
-- This lets you inspect recent observe-stream delivery results.
COMMENT ON FUNCTION observe_audit_entry() IS
  'C-CERT-004: Ships audit log inserts to OpenObserve via pg_net async HTTP. '
  'Configure app.observe_stream_url and app.observe_stream_secret GUCs to activate.';
