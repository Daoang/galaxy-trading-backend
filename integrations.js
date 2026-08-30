/**
 * integrations.js — server-side calls to the external APIs.
 *
 * Only the captcha providers are external now. One-time passcodes for
 * high-value sales are generated and verified in-process — no SMS gateway.
 * Captcha degrades gracefully: with no secret set, verification is skipped so
 * the system is runnable on day one.
 */
const crypto = require("crypto");
const config = require("./config");

// ---------------------------------------------------------------------------
// One-time passcodes for high-value sales.
//
// There is no SMS provider any more: the code is generated, hashed and expired
// here, and handed back to the staff screen that asked for it. Generation and
// verification were always local — only delivery used a third party.
// Kept in memory keyed by phone. For production, persist these in a table.
// ---------------------------------------------------------------------------
const OTP_STORE = new Map(); // phone -> { hash, expires }
const OTP_TTL = 300; // 5 minutes

function hashOtp(code) {
  return crypto.createHash("sha256").update(code + config.SECRET_KEY).digest("hex");
}

async function sendOtp(phone) {
  if (!phone) return { ok: false, error: "Phone number required" };
  const code = String(Math.floor(Math.random() * 1000000)).padStart(6, "0");
  OTP_STORE.set(phone, { hash: hashOtp(code), expires: Date.now() / 1000 + OTP_TTL });

  // No SMS gateway: the code goes straight back to the staff screen that
  // requested it, and is also logged for the terminal.
  console.log(`[OTP] ${phone} -> ${code}`);
  return { ok: true, sent_via_sms: false, dev_code: code };
}

async function verifyOtp(phone, code) {
  const rec = OTP_STORE.get(phone);
  if (!rec) return { ok: false, error: "No code requested for this number" };
  if (Date.now() / 1000 > rec.expires) {
    OTP_STORE.delete(phone);
    return { ok: false, error: "Code expired — request a new one" };
  }
  if (hashOtp(code) !== rec.hash) return { ok: false, error: "Incorrect code" };
  OTP_STORE.delete(phone);
  return { ok: true };
}

// ---------------------------------------------------------------------------
// hCaptcha + Cloudflare Turnstile — verify the client-side token
// ---------------------------------------------------------------------------
async function verifyCaptcha(token, provider = "turnstile") {
  // If enforcement is off (no secret configured), let everything through so
  // the app is usable out of the box.
  if (!config.CAPTCHA_REQUIRED) return { ok: true, skipped: true };
  const secret = provider === "turnstile" ? config.TURNSTILE_SECRET : config.HCAPTCHA_SECRET;
  if (!secret) return { ok: true, skipped: true };
  const url =
    provider === "turnstile"
      ? "https://challenges.cloudflare.com/turnstile/v0/siteverify"
      : "https://hcaptcha.com/siteverify";
  try {
    const params = new URLSearchParams({ secret, response: token });
    const r = await fetch(url, {
      method: "POST",
      body: params,
      signal: AbortSignal.timeout(8000),
    });
    const data = await r.json();
    return { ok: !!data.success };
  } catch (e) {
    return { ok: false, error: `Captcha verify failed: ${e.message}` };
  }
}

module.exports = { sendOtp, verifyOtp, verifyCaptcha };
