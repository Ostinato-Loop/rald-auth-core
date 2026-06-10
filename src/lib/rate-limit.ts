// RALD Auth Core — Rate Limiting
// Cloudflare KV-backed sliding-window rate limiter.
// Fails open (allows) when KV is unavailable — never blocks legitimate traffic on infra failure.
// LILCKY STUDIO LIMITED

export interface RateLimitConfig {
  key: string;
  limit: number;
  windowSeconds: number;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
}

export interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

/**
 * Sliding-window rate limiter backed by Cloudflare KV.
 * Stores a JSON array of unix-second timestamps per key.
 * Falls back to allow-all when KV binding is missing (dev/cold-start).
 */
export async function checkRateLimit(
  kv: KVNamespace | undefined,
  config: RateLimitConfig
): Promise<RateLimitResult> {
  if (!kv) {
    return { allowed: true, remaining: config.limit, resetAt: Math.floor(Date.now() / 1000) + config.windowSeconds };
  }

  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - config.windowSeconds;
  const kvKey = `rl:${config.key}`;

  let timestamps: number[] = [];
  try {
    const raw = await kv.get(kvKey);
    if (raw) timestamps = JSON.parse(raw) as number[];
  } catch { /* corrupt entry — treat as empty */ }

  timestamps = timestamps.filter((t) => t > windowStart);

  const allowed = timestamps.length < config.limit;
  const remaining = Math.max(0, config.limit - timestamps.length - (allowed ? 1 : 0));
  const resetAt = timestamps.length > 0
    ? timestamps[0]! + config.windowSeconds
    : now + config.windowSeconds;

  if (allowed) {
    timestamps.push(now);
    try {
      await kv.put(kvKey, JSON.stringify(timestamps), {
        expirationTtl: config.windowSeconds + 60,
      });
    } catch { /* KV write failure is non-fatal */ }
  }

  return { allowed, remaining, resetAt };
}

// ── Preset configurations ─────────────────────────────────────────────────────

export const RATE_LIMITS = {
  /** OTP send: 3 per phone per 10 minutes */
  otpSendPhone: (phone: string): RateLimitConfig => ({
    key: `otp:phone:${phone}`,
    limit: 3,
    windowSeconds: 600,
  }),
  /** OTP send: 10 per IP per 10 minutes */
  otpSendIp: (ip: string): RateLimitConfig => ({
    key: `otp:ip:${ip}`,
    limit: 10,
    windowSeconds: 600,
  }),
  /** OTP send (email): 3 per email per 10 minutes */
  otpSendEmail: (email: string): RateLimitConfig => ({
    key: `otp:email:${email}`,
    limit: 3,
    windowSeconds: 600,
  }),
  /** Login: 10 attempts per IP per 15 minutes */
  loginIp: (ip: string): RateLimitConfig => ({
    key: `login:ip:${ip}`,
    limit: 10,
    windowSeconds: 900,
  }),
  /** Login: 5 attempts per email per 15 minutes */
  loginEmail: (email: string): RateLimitConfig => ({
    key: `login:email:${email}`,
    limit: 5,
    windowSeconds: 900,
  }),
  /** Register: 5 per IP per hour */
  registerIp: (ip: string): RateLimitConfig => ({
    key: `register:ip:${ip}`,
    limit: 5,
    windowSeconds: 3600,
  }),
  /** Password reset: 3 per email per 15 minutes */
  passwordReset: (email: string): RateLimitConfig => ({
    key: `pwd_reset:${email}`,
    limit: 3,
    windowSeconds: 900,
  }),
} as const;

// ── Client IP extraction ──────────────────────────────────────────────────────

export function getClientIp(request: Request): string {
  return (
    request.headers.get("CF-Connecting-IP") ??
    request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ??
    "unknown"
  );
}

// ── Standard 429 response helper ─────────────────────────────────────────────

export function rateLimitResponse(resetAt: number): Response {
  const retryAfter = Math.max(0, resetAt - Math.floor(Date.now() / 1000));
  return Response.json(
    { error: "Too many requests. Please try again later." },
    {
      status: 429,
      headers: {
        "Retry-After": String(retryAfter),
        "X-RateLimit-Reset": String(resetAt),
      },
    }
  );
}
