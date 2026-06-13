// RALD Auth Core — Ecosystem Redirect Validation
// Enforces: only *.rald.cloud and *.ostloop.name.ng redirects allowed
// LILCKY STUDIO LIMITED

const ALLOWED_PATTERNS: RegExp[] = [
  /^https:\/\/rald\.cloud(\/.*)?$/,
  /^https:\/\/[\w-]+\.rald\.cloud(\/.*)?$/,
  /^https:\/\/ostloop\.name\.ng(\/.*)?$/,
  /^https:\/\/[\w-]+\.ostloop\.name\.ng(\/.*)?$/,
];

/** Returns true only for safe RALD ecosystem redirect URLs. */
export function validateRedirectUrl(url: string | null | undefined): boolean {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") return false;
    return ALLOWED_PATTERNS.some((r) => r.test(url.split("?")[0] + (url.includes("?") ? "" : "")));
  } catch {
    return false;
  }
}

/** Returns the redirect URL if valid, or the fallback. */
export function safeRedirect(url: string | null | undefined, fallback = "https://profiles.rald.cloud"): string {
  return validateRedirectUrl(url) ? url! : fallback;
}

export const ECOSYSTEM_APPS = [
  { id: "manilla",       name: "Manilla",      url: "https://manilla.rald.cloud",        icon: "\uD83C\uDFB6" },
  { id: "profiles",      name: "Profile",      url: "https://profiles.rald.cloud",       icon: "\uD83D\uDC64" },
  { id: "loop",          name: "Loop",         url: "https://loop.rald.cloud",            icon: "\uD83C\uDFB5" },
  { id: "messenger",     name: "Messenger",    url: "https://chat.rald.cloud",            icon: "\uD83D\uDCAC" },
  { id: "rald-inbox",    name: "Inbox",        url: "https://inbox.rald.cloud",           icon: "\uD83D\uDCE5" },
  { id: "payrald",       name: "PayRald",      url: "https://pay.rald.cloud",             icon: "\uD83D\uDCB3" },
  { id: "dunarald",      name: "DunaRald",     url: "https://duna.rald.cloud",            icon: "\uD83D\uDED2" },
  { id: "gitrald",       name: "GitRald",      url: "https://git.rald.cloud",             icon: "\u2699\uFE0F"  },
  { id: "raldtics",      name: "Raldtics",     url: "https://analytics.rald.cloud",       icon: "\uD83D\uDCCA" },
] as const;

export type EcosystemAppId = typeof ECOSYSTEM_APPS[number]["id"];

