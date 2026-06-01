-- ============================================================
-- RALD Auth — RECOVERY MIGRATION V1
-- ⚠️  SUPERSEDED — Do NOT run this file.
-- Use: supabase/migrations/20260601_auth_users_table.sql instead.
--
-- REASON: The shared Supabase DB has a `users` table owned by a
-- different product (Manilla music platform). Running this migration
-- would silently no-op on `users` (IF NOT EXISTS) and leave rald-auth
-- with no working tables.
--
-- The correct migration creates the `auth_*` table namespace:
--   auth_users, auth_sessions, auth_devices, auth_product_access, auth_otp_codes
--
-- This file is kept for historical reference only.
-- LILCKY STUDIO LIMITED — superseded 2026-06-01
-- ============================================================

-- This file intentionally left as archive. Do not execute.

