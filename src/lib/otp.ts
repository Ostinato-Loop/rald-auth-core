// RALD Auth Core — OTP Service
// SMS via Termii, Email via Resend
// All vendor names are internal only — never visible to end users.
// LILCKY STUDIO LIMITED

// ── SMS OTP (Termii) ─────────────────────────────────────────────────────────

export async function sendSmsOtp(
  phone: string,
  apiKey: string,
  senderId = "N-Alert"
): Promise<{ pinId: string }> {
  const attemptSend = async (sid: string, channel: string) => {
    const body: Record<string, unknown> = {
      api_key: apiKey,
      message_type: "NUMERIC",
      to: phone,
      channel,
      pin_attempts: 3,
      pin_time_to_live: 10,
      pin_length: 6,
      pin_placeholder: "< 1234 >",
      message_text: "Your RALD verification code is < 1234 >. Valid for 10 minutes. Do not share. RALD by LILCKY STUDIO LIMITED.",
      pin_type: "NUMERIC",
    };
    if (channel !== "generic") body.from = sid;
    const res = await fetch("https://api.ng.termii.com/api/sms/otp/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    return (await res.json()) as { pinId?: string; message?: string };
  };

  // Try configured sender on dnd channel first
  let data = await attemptSend(senderId, "dnd");

  // If sender not approved, try N-Alert on dnd
  if (!data.pinId && (data.message?.includes("ApplicationSenderId not found") || data.message?.includes("sender"))) {
    if (senderId !== "N-Alert") {
      console.warn("[otp] sender '" + senderId + "' not approved — retrying with N-Alert/dnd");
      data = await attemptSend("N-Alert", "dnd");
    }
    // Final fallback: generic channel (Termii shared pool, no sender approval needed)
    if (!data.pinId && (data.message?.includes("ApplicationSenderId not found") || data.message?.includes("sender"))) {
      console.warn("[otp] N-Alert not approved — falling back to generic channel");
      data = await attemptSend("", "generic");
    }
  }

  if (!data.pinId) throw new Error(data.message ?? "Failed to send verification code");
  return { pinId: data.pinId };
}

export async function verifySmsOtp(pinId: string, pin: string, apiKey: string): Promise<boolean> {
  const res = await fetch("https://api.ng.termii.com/api/sms/otp/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ api_key: apiKey, pin_id: pinId, pin }),
  });
  const data = (await res.json()) as { verified?: string | boolean };
  return data.verified === "True" || data.verified === true;
}

// ── OTP Utilities ─────────────────────────────────────────────────────────────

export function generateNumericOtp(length = 6): string {
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return Array.from(arr)
    .map((b) => b % 10)
    .join("");
}

export async function hashOtpCode(code: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(code));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function verifyOtpCode(code: string, hash: string): Promise<boolean> {
  return (await hashOtpCode(code)) === hash;
}

// ── Email OTP (Resend) ────────────────────────────────────────────────────────

const RESEND_API = "https://api.resend.com/emails";
const FROM_IDENTITY = "RALD Identity <auth@rald.cloud>";

async function sendResendEmail(payload: object, apiKey: string): Promise<void> {
  const res = await fetch(RESEND_API, {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = (await res.json()) as { message?: string };
    throw new Error(err.message ?? "Email delivery failed");
  }
}

export async function sendEmailOtp(to: string, code: string, apiKey: string): Promise<void> {
  await sendResendEmail(
    {
      from: FROM_IDENTITY,
      to: [to],
      subject: `RALD: Your verification code is ${code}`,
      html: otpEmailHtml(code, "verify", to),
    },
    apiKey
  );
}

export async function sendLoginEmailOtp(to: string, code: string, apiKey: string): Promise<void> {
  await sendResendEmail(
    {
      from: FROM_IDENTITY,
      to: [to],
      subject: `RALD: Your sign-in code is ${code}`,
      html: otpEmailHtml(code, "login", to),
    },
    apiKey
  );
}

export async function sendWelcomeEmail(to: string, name: string, apiKey: string): Promise<void> {
  await sendResendEmail(
    {
      from: FROM_IDENTITY,
      to: [to],
      subject: "Welcome to RALD",
      html: welcomeEmailHtml(name, to),
    },
    apiKey
  );
}

function otpEmailHtml(code: string, purpose: "login" | "verify", email: string): string {
  const title = purpose === "login" ? "Sign in to RALD" : "Verify your email";
  const subtitle =
    purpose === "login"
      ? "Use this code to sign in to your RALD account. It expires in 10 minutes."
      : "Enter this code to verify your email address. It expires in 10 minutes.";
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RALD</title></head>
<body style="margin:0;padding:0;background:#040C18;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#040C18;">
<tr><td align="center" style="padding:40px 16px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="520" style="max-width:520px;background:#070E1A;border-radius:16px;border:1px solid #1E3A5F;">
  <tr><td style="padding:32px 40px 24px;border-bottom:1px solid #1E3A5F;">
    <span style="font-size:28px;font-weight:900;letter-spacing:-1px;color:#FFFFFF;">R</span><span style="font-size:28px;font-weight:900;letter-spacing:-1px;color:#2ECFA3;">A</span><span style="font-size:28px;font-weight:900;letter-spacing:-1px;color:#FFFFFF;">LD</span>
    <span style="margin-left:10px;background:#2ECFA322;border:1px solid #2ECFA344;color:#2ECFA3;font-size:10px;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;padding:3px 8px;border-radius:20px;">Identity</span>
  </td></tr>
  <tr><td style="padding:32px 40px;">
    <h2 style="font-size:20px;font-weight:700;color:#F0F4F8;margin:0 0 8px;">${title}</h2>
    <p style="color:#64748B;font-size:14px;line-height:1.6;margin:0 0 28px;">${subtitle}</p>
    <div style="background:#0D1929;border:1px solid #1E3A5F;border-radius:12px;padding:32px;text-align:center;margin:0 0 28px;">
      <span style="font-size:44px;font-weight:900;letter-spacing:0.25em;color:#F0F4F8;font-variant-numeric:tabular-nums;">${code}</span>
    </div>
    <p style="color:#374151;font-size:12px;line-height:1.6;margin:0;">If you didn't request this code, you can safely ignore this email.<br>Never share this code with anyone.</p>
  </td></tr>
  <tr><td style="padding:16px 40px 28px;border-top:1px solid #1E3A5F;text-align:center;">
    <p style="color:#374151;font-size:11px;line-height:1.6;margin:0;">
      Sent to <strong style="color:#475569;">${email}</strong> by <strong style="color:#475569;">LILCKY STUDIO LIMITED</strong>, operators of RALD.cloud.<br>
      <a href="https://rald.cloud/privacy" style="color:#2ECFA3;text-decoration:none;">Privacy</a> &nbsp;·&nbsp;
      <a href="https://rald.cloud/terms" style="color:#2ECFA3;text-decoration:none;">Terms</a> &nbsp;·&nbsp;
      <a href="mailto:support@rald.cloud" style="color:#2ECFA3;text-decoration:none;">Support</a>
    </p>
  </td></tr>
</table>
</td></tr></table>
</body></html>`;
}

function welcomeEmailHtml(name: string, email: string): string {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Welcome to RALD</title></head>
<body style="margin:0;padding:0;background:#040C18;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#040C18;">
<tr><td align="center" style="padding:40px 16px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="520" style="max-width:520px;background:#070E1A;border-radius:16px;border:1px solid #1E3A5F;">
  <tr><td style="padding:32px 40px 24px;border-bottom:1px solid #1E3A5F;">
    <span style="font-size:28px;font-weight:900;letter-spacing:-1px;color:#FFFFFF;">R</span><span style="font-size:28px;font-weight:900;letter-spacing:-1px;color:#2ECFA3;">A</span><span style="font-size:28px;font-weight:900;letter-spacing:-1px;color:#FFFFFF;">LD</span>
  </td></tr>
  <tr><td style="padding:32px 40px;">
    <h2 style="font-size:20px;font-weight:700;color:#F0F4F8;margin:0 0 8px;">Welcome, ${name}!</h2>
    <p style="color:#64748B;font-size:14px;line-height:1.6;margin:0 0 20px;">Your RALD account is ready. You now have access to the entire RALD ecosystem.</p>
    <a href="https://rald.cloud" style="display:inline-block;background:#2ECFA3;color:#040C18;font-weight:700;font-size:14px;padding:12px 28px;border-radius:8px;text-decoration:none;">Get Started</a>
  </td></tr>
  <tr><td style="padding:16px 40px 28px;border-top:1px solid #1E3A5F;text-align:center;">
    <p style="color:#374151;font-size:11px;margin:0;">Sent to <strong style="color:#475569;">${email}</strong> by <strong style="color:#475569;">LILCKY STUDIO LIMITED</strong></p>
  </td></tr>
</table>
</td></tr></table>
</body></html>`;
}
