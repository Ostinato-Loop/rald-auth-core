# rald-auth-core

**RALD Auth Core** — standalone Cloudflare Worker providing identity services for the RALD ecosystem.

Deployed at: `https://auth.rald.cloud`

## Routes

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/login` | Email + password login |
| POST | `/auth/register` | Register new user |
| POST | `/auth/send-otp` | Send SMS OTP (Termii) |
| POST | `/auth/verify-otp` | Verify SMS OTP |
| POST | `/auth/register-from-otp` | Register via verified phone |
| POST | `/auth/send-login-email-otp` | Send email OTP (Resend) |
| POST | `/auth/verify-login-email-otp` | Verify email OTP |
| POST | `/auth/request-password-reset` | Request password reset |
| POST | `/auth/reset-password` | Reset password with code |
| GET | `/auth/me` | Get current user |
| GET | `/auth/sessions` | List active sessions |
| DELETE | `/auth/sessions/:id` | Revoke session |
| DELETE | `/auth/sessions` | Revoke all sessions |
| GET | `/devices` | List user devices |
| POST | `/devices/:id/trust` | Trust a device |
| DELETE | `/devices/:id` | Remove device |
| POST | `/sso/exchange` | Exchange JWT for app-scoped token |
| POST | `/sso/verify` | Verify a RALD token |

## Required Secrets (Cloudflare)

```bash
wrangler secret put SUPABASE_URL
wrangler secret put SUPABASE_SERVICE_ROLE_KEY
wrangler secret put RALD_JWT_SECRET
wrangler secret put TERMII_API_KEY
wrangler secret put TERMII_SENDER_ID
wrangler secret put RESEND_API_KEY
```

## Deploy

Automatically deployed on push to `main` via GitHub Actions → Cloudflare Workers.

```bash
npm run deploy
```

---

LILCKY STUDIO LIMITED — operators of RALD.cloud
