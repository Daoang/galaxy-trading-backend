/**
 * integrations.js — server-side calls to the external APIs.
 *
 * Only the captcha providers are external. (High-value sales used to need an
 * SMS one-time code; that step was removed, along with its /api/otp routes.)
 * Captcha degrades gracefully: with no secret set, verification is skipped so
 * the system is runnable on day one.
 */
const config = require("./config");

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

module.exports = { verifyCaptcha };
