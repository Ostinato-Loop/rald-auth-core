-- RALD Auth Core — Production Schema Migration V2
-- ⚠️  SUPERSEDED — Do NOT run this file.
-- Use: supabase/migrations/20260601_auth_users_table.sql instead.
--
-- REASON: This file references tables named `users`, `sessions`, `user_devices`,
-- `product_access`, `otp_codes`. These names conflict with tables owned by
-- another product (Manilla) on the shared Supabase project.
--
-- The correct migration uses the `auth_*` prefix to create an isolated namespace:
--   auth_users, auth_sessions, auth_devices, auth_product_access, auth_otp_codes
--
-- This file is kept for historical reference only.
-- LILCKY STUDIO LIMITED — superseded 2026-06-01
-- ============================================================

-- This file intentionally left as archive. Do not execute.

