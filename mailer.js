/**
 * mailer.js — sends the storefront's sign-up OTP emails.
 *
 * Two senders, chosen by EMAIL_PROVIDER in .env (see config.js / .env.example):
 *   gmail  — Gmail's mail server (smtp.gmail.com) with an App Password.
 *   resend — the Resend HTTP API (https://api.resend.com/emails).
 * Brevo was used before and has been removed.
 *
 * THE ONE RULE
 *   An OTP is sent to the mailbox and nowhere else. It is never put in an
 *   HTTP response. If it were, anyone could "verify" an address they do not
 *   own just by reading the reply, and the check would prove nothing. The
 *   credentials likewise stay in this process: read from .env, only ever sent
 *   to Gmail or Resend.
 *
 * WITHOUT CREDENTIALS
 *   On localhost the code is printed in the server's terminal so sign-up can
 *   still be tested. On any other host that is refused instead: a deployed
 *   site must not create accounts whose owners were never actually sent a code.
 */
const nodemailer = require("nodemailer");
const config = require("./config");

const GENERIC_FAILURE = "We couldn't send the verification email just now. Please try again shortly.";

function isConfigured() {
  if (config.EMAIL_PROVIDER === "gmail") return !!(config.GMAIL_USER && config.GMAIL_APP_PASSWORD);
  if (config.EMAIL_PROVIDER === "resend") return !!(config.EMAIL_API_KEY && config.EMAIL_FROM);
  return false;
}

/** For the admin health panel: which service is sending, if any. */
function providerLabel() {
  return { gmail: "Gmail", resend: "Resend" }[config.EMAIL_PROVIDER] || "not set";
}

/** Is this request coming in to a development host? */
function isLocalHost(req) {
  const host = String((req && req.headers && req.headers.host) || "").split(":")[0];
  return /^(localhost|127\.0\.0\.1|\[?::1\]?)$/i.test(host) ||
    /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host);
}

const isLoopback = (host) => /^(127\.0\.0\.1|localhost|::1)$/i.test(String(host));

/** Why the configured provider can't send, for the server log. */
function whatIsMissing() {
  if (config.EMAIL_PROVIDER === "gmail") {
    return "EMAIL_PROVIDER is gmail but GMAIL_USER or GMAIL_APP_PASSWORD is empty.";
  }
  if (config.EMAIL_PROVIDER === "resend") {
    if (/^xkeysib-/.test(config.EMAIL_API_KEY)) {
      return "EMAIL_API_KEY holds a Brevo key. Brevo is no longer used: set up Gmail or Resend (see .env.example).";
    }
    return "EMAIL_PROVIDER is resend but EMAIL_API_KEY or EMAIL_FROM is empty.";
  }
  return "No email service is set up (EMAIL_PROVIDER, GMAIL_* or EMAIL_API_KEY in .env).";
}

// ---------------------------------------------------------------------------
//  The message itself — identical whichever service sends it.
// ---------------------------------------------------------------------------
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function buildMessage(code, minutes) {
  const brand = config.EMAIL_FROM_NAME || "Galaxy Trading";
  return {
    brand,
    subject: `Your ${brand} verification code: ${code}`,
    text:
      `Your ${brand} verification code is ${code}\n\n` +
      `Enter it on the sign-up page to verify your email and activate your account. ` +
      `It expires in ${minutes} minutes.\n\n` +
      `If you did not try to sign up, you can ignore this email — no account is ` +
      `created without this code.`,
    html:
      `<div style="font-family:Arial,Helvetica,sans-serif;max-width:460px;margin:0 auto;color:#1a2233">` +
      `<h2 style="margin:0 0 12px;font-size:20px">Verify your email</h2>` +
      `<p style="margin:0 0 18px;font-size:14px;line-height:1.6">Enter this code on the ${escapeHtml(brand)} ` +
      `sign-up page to activate your account.</p>` +
      `<div style="font-size:32px;font-weight:700;letter-spacing:8px;background:#f1f4fb;` +
      `border-radius:10px;padding:18px;text-align:center">${code}</div>` +
      `<p style="margin:18px 0 0;font-size:13px;color:#5b6478;line-height:1.6">It expires in ${minutes} ` +
      `minutes. If you did not try to sign up, ignore this email — no account is created without this code.</p>` +
      `</div>`,
  };
}

// ---------------------------------------------------------------------------
//  Gmail (SMTP with an App Password)
// ---------------------------------------------------------------------------
let gmailTransport = null;
function gmail() {
  if (!gmailTransport) {
    const host = config.EMAIL_SMTP_HOST;
    const port = config.EMAIL_SMTP_PORT;
    gmailTransport = nodemailer.createTransport({
      host,
      port,
      secure: port === 465,                 // Gmail: TLS from the first byte on 465
      requireTLS: !isLoopback(host),        // never log in over plain text off this machine
      auth: { user: config.GMAIL_USER, pass: config.GMAIL_APP_PASSWORD },
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 15000,
    });
  }
  return gmailTransport;
}

function explainGmail(err) {
  const code = err && (err.responseCode || err.code);
  const msg = String((err && (err.response || err.message)) || "").slice(0, 200);
  if (err && (err.code === "EAUTH" || err.responseCode === 535 || err.responseCode === 534)) {
    return "Gmail refused the login. GMAIL_APP_PASSWORD must be a 16-letter App Password " +
      "(Google Account > Security > 2-Step Verification > App passwords), not your normal " +
      "Gmail password, and GMAIL_USER must be that same Gmail address. " + msg;
  }
  if (err && ["ETIMEDOUT", "ECONNECTION", "ESOCKET", "ECONNREFUSED", "EDNS"].includes(err.code)) {
    return `Could not reach ${config.EMAIL_SMTP_HOST}:${config.EMAIL_SMTP_PORT} (network or firewall). ${msg}`;
  }
  if (/limit/i.test(msg)) return "Gmail's daily sending limit was reached (about 500 a day). " + msg;
  return `Gmail returned ${code || "an error"}: ${msg}`;
}

async function sendViaGmail(email, m) {
  try {
    await gmail().sendMail({
      // Gmail always sends as the account that logged in, so that is the From.
      from: { name: m.brand.replace(/["<>]/g, "").slice(0, 70), address: config.GMAIL_USER },
      to: email,
      subject: m.subject,
      text: m.text,
      html: m.html,
    });
    return { ok: true, delivery: "email" };
  } catch (err) {
    console.error("[EMAIL] Gmail send failed — " + explainGmail(err));
    return { ok: false, status: 502, error: GENERIC_FAILURE };
  }
}

// ---------------------------------------------------------------------------
//  Resend (HTTP API) — POST /emails, "Authorization: Bearer re_...",
//  success is 200 { id }, errors are { statusCode, name, message }.
// ---------------------------------------------------------------------------

/** The API key is only ever sent over HTTPS — or to this machine, for tests. */
function safeEndpoint(url) {
  return /^https:\/\//i.test(url) || /^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?\//i.test(url);
}

function explainResend(status, body) {
  const msg = String((body && (body.message || body.name)) || "").trim();
  if (/own email address|verify a domain|not verified/i.test(msg)) {
    return `Resend will only email your own address until a domain is verified (${msg}). ` +
      "In Resend go to Domains, add your domain, create the DNS records it shows, then " +
      "set EMAIL_FROM to an address on that domain.";
  }
  if (status === 401 || (status === 403 && /api key/i.test(msg))) {
    return `Resend rejected the API key (${msg || "unauthorized"}). Check EMAIL_API_KEY.`;
  }
  if (status === 429) return `Resend rate or daily limit reached (${msg}).`;
  return `Resend returned HTTP ${status}${msg ? ": " + msg : ""}.`;
}

async function sendViaResend(email, m) {
  if (!safeEndpoint(config.EMAIL_API_URL)) {
    console.error("[EMAIL] EMAIL_API_URL must be https:// — refusing to send the API key over plain HTTP.");
    return { ok: false, status: 500, error: GENERIC_FAILURE };
  }
  let res;
  let body = {};
  try {
    res = await fetch(config.EMAIL_API_URL, {
      method: "POST",
      headers: {
        authorization: "Bearer " + config.EMAIL_API_KEY,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        from: `${m.brand.replace(/["<>]/g, "").slice(0, 70)} <${config.EMAIL_FROM}>`,
        to: [email],
        subject: m.subject,
        html: m.html,
        text: m.text,
      }),
      // Give up rather than hang a sign-up request on a slow network.
      signal: AbortSignal.timeout(10000),
    });
    try { body = await res.json(); } catch (e) { body = {}; }
  } catch (e) {
    console.error("[EMAIL] could not reach Resend:", e.message);
    return { ok: false, status: 502, error: GENERIC_FAILURE };
  }
  if (res.ok && body && body.id) return { ok: true, delivery: "email" };
  console.error("[EMAIL] Resend send failed — " + explainResend(res.status, body));
  return { ok: false, status: 502, error: GENERIC_FAILURE };
}

/**
 * Send a sign-up OTP. Resolves to
 *   { ok: true, delivery: "email" | "console" }
 *   { ok: false, status, error }
 */
async function sendVerificationCode(req, email, code, minutes) {
  if (!isConfigured()) {
    if (!isLocalHost(req)) {
      console.error("[EMAIL] Cannot send the sign-up code: " + whatIsMissing());
      return {
        ok: false,
        status: 503,
        error: "Sign-up is temporarily unavailable: this site cannot send email yet.",
      };
    }
    // Development only. The code stays on the server; the browser is told only
    // that a code exists.
    console.log(
      `\n[EMAIL] Sign-up code for ${email}: ${code}\n` +
      `        (Email sending is not set up, so it is shown here instead of being` +
      ` emailed. Expires in ${minutes} min.)\n`
    );
    return { ok: true, delivery: "console" };
  }

  const m = buildMessage(code, minutes);
  return config.EMAIL_PROVIDER === "gmail" ? sendViaGmail(email, m) : sendViaResend(email, m);
}

// ---------------------------------------------------------------------------
//  Used by check-email.js only: prove the settings work before going live.
// ---------------------------------------------------------------------------

/** Gmail: log in to smtp.gmail.com without sending anything. */
async function verifyGmailLogin() {
  try {
    await gmail().verify();
    return { ok: true };
  } catch (err) {
    return { ok: false, error: explainGmail(err) };
  }
}

/** Send one plain test message through whichever service is set up. */
async function sendTestEmail(to) {
  if (!isConfigured()) return { ok: false, error: whatIsMissing() };
  const brand = config.EMAIL_FROM_NAME || "Galaxy Trading";
  const m = {
    brand,
    subject: `${brand}: email is working`,
    text: `This is a test from the ${brand} server. Sign-up codes will be sent the same way.`,
    html: `<p style="font-family:Arial,Helvetica,sans-serif;font-size:14px">This is a test from the ` +
          `${escapeHtml(brand)} server. Sign-up codes will be sent the same way.</p>`,
  };
  return config.EMAIL_PROVIDER === "gmail" ? sendViaGmail(to, m) : sendViaResend(to, m);
}

module.exports = {
  sendVerificationCode, isConfigured, providerLabel,
  verifyGmailLogin, sendTestEmail, whatIsMissing,
};
