-- Add Manilla to the RALD ecosystem app registry
-- Manilla is registered as an SSO-trusted app so users authenticated via
-- profiles.rald.cloud can seamlessly access manilla.rald.cloud.
-- Date: 2026-06-06

INSERT INTO registered_apps (app_id, name, domain, callback_url, logout_url, icon, status)
VALUES
  ('manilla', 'Manilla', 'manilla.rald.cloud',
   'https://manilla.rald.cloud/auth/callback',
   'https://manilla.rald.cloud/logout',
   '🎶', 'active')
ON CONFLICT (app_id) DO NOTHING;

