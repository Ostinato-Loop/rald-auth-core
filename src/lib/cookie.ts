// RALD Auth Core — Secure Cookie Utilities
// domain=.rald.cloud HttpOnly session cookies for cross-product silent SSO.
// SESSION-P1-001 (2026-06-13): Upgraded SameSite=Lax → SameSite=None
//   (required for credentialed cross-origin requests during SSO redirects
//   between *.rald.cloud subdomains). Requires Secure=true (enforced).
// LILCKY STUDIO LIMITED

const COOKIE_NAME   = "rald_session";
const COOKIE_DOMAIN = ".rald.cloud";
const SESSION_TTL_S = 2_592_000; // 30 days — sliding window; refreshed by /auth/silent on every app open

/** Build Set-Cookie header value for the RALD ecosystem session cookie. */
export function buildSessionCookie(token: string, ttlSeconds = SESSION_TTL_S): string {
  return [
    `${COOKIE_NAME}=${token}`,
    `Domain=${COOKIE_DOMAIN}`,
    "Path=/",
    `Max-Age=${ttlSeconds}`,
    "HttpOnly",
    "Secure",
    "SameSite=None",
  ].join("; ");
}

/** Build Set-Cookie that clears the session cookie ecosystem-wide. */
export function clearSessionCookie(): string {
  return [
    `${COOKIE_NAME}=`,
    `Domain=${COOKIE_DOMAIN}`,
    "Path=/",
    "Max-Age=0",
    "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
    "HttpOnly",
    "Secure",
    "SameSite=None",
  ].join("; ");
}

/** Extract rald_session value from a Cookie request header. */
export function parseSessionCookie(cookieHeader: string | null | undefined): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key?.trim() === COOKIE_NAME) return rest.join("=").trim() || null;
  }
  return null;
}
