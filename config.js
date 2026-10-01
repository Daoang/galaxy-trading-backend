/**
 * config.js — central configuration for the Galaxy Trading backend.
 *
 * All secrets and environment-specific values live here, read from a .env file
 * (see .env.example). Nothing in the codebase hard-codes a key.
 */
require("dotenv").config({ path: require("path").join(__dirname, ".env") });

function bool(name, def = false) {
  const v = process.env[name];
  if (v === undefined) return def;
  return ["1", "true", "yes", "on"].includes(String(v).trim().toLowerCase());
}

// ----- MySQL (XAMPP defaults: user 'root', empty password, port 3306) -------
const DB_HOST = process.env.DB_HOST || "127.0.0.1";
const DB_PORT = parseInt(process.env.DB_PORT || "3306", 10);
const DB_USER = process.env.DB_USER || "root";
const DB_PASSWORD = process.env.DB_PASSWORD || ""; // XAMPP root has no password by default
const DB_NAME = process.env.DB_NAME || "galaxy_trading_thesis1";

// Where customer design photos and GCash receipts are written. By default they
// sit in the site folder (galaxytrading/uploads). On a host with a mounted
// disk — Render, for example — point UPLOAD_DIR at that disk so the pictures
// survive a redeploy.
const UPLOAD_DIR = (process.env.UPLOAD_DIR || "").trim();

// Sites allowed to call this API from a browser, comma-separated, e.g.
// "https://galaxytradingshop.store,https://www.galaxytradingshop.store".
// Needed when the pages are hosted apart from the API (Hostinger + Render).
// Same-origin requests never need this.
const ALLOWED_ORIGINS = String(process.env.ALLOWED_ORIGINS || "")
  .split(",").map((o) => o.trim().replace(/\/+$/, "")).filter(Boolean);

// Managed MySQL (Aiven, PlanetScale, some Hostinger plans) requires TLS.
// Set DB_SSL=true when the provider asks for it.
const DB_SSL = bool("DB_SSL", false);

// ----- App / security -------------------------------------------------------
const SECRET_KEY = process.env.SECRET_KEY || "dev-change-me-in-production";
const TOKEN_TTL_HOURS = parseInt(process.env.TOKEN_TTL_HOURS || "12", 10);
const PORT = parseInt(process.env.PORT || "5000", 10);

// Shop logo, relative to the site root. Shown on the staff 2FA setup screen.
const BRAND_LOGO = process.env.BRAND_LOGO || "images/galaxyshop.jpg";
// Shown if BRAND_LOGO is missing from disk, so a typo never leaves a blank box.
const BRAND_LOGO_FALLBACK = "images/gt-logo.jpg";

/** BRAND_LOGO if the file is really there, otherwise the fallback. */
function brandLogo() {
  const path = require("path");
  const fs = require("fs");
  const root = path.resolve(__dirname, "..");
  const wanted = BRAND_LOGO.replace(/^\/+/, "");
  try {
    if (fs.existsSync(path.join(root, wanted))) return wanted;
  } catch (e) { /* fall through */ }
  return BRAND_LOGO_FALLBACK;
}

// ----- External APIs (fill these in .env to go live) ------------------------
// hCaptcha + Cloudflare Turnstile — server-side verification secrets
const HCAPTCHA_SECRET = process.env.HCAPTCHA_SECRET || "";
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || "";
// When no secret is set, captcha verification is skipped (so the app runs
// out-of-the-box). Set the secrets in .env to enforce it.
const CAPTCHA_REQUIRED = bool("CAPTCHA_REQUIRED", false);

// ----- Walk-in POS / VAT receipt --------------------------------------------
// Flat door-to-door delivery fee for a walk-in sale: the POS adds it as a
// fixed "Delivery Fee" line that cannot be typed in.
const DELIVERY_FEE = 150;

// What the storefront charges a customer for delivery. Kept apart from the
// walk-in figure above because the shop prices the two differently.
// (checkout.html shows the same ₱500 to customers.)
const ONLINE_DELIVERY_FEE = 500;
const VAT_RATE = parseFloat(process.env.VAT_RATE || "0.12"); // 12% VAT (Philippines), VAT-inclusive

// Business header printed on the official receipt. Edit to match your BIR permit.
const BUSINESS = {
  name: process.env.BIZ_NAME || "KINGKONG GALAXY TRADING",
  proprietor: process.env.BIZ_PROPRIETOR || "QUEEN PEARL M. RAMIREZ - Proprietress",
  tin: process.env.BIZ_TIN || "302-812-298-00000",
  address:
    process.env.BIZ_ADDRESS ||
    "36-B Regalado Ave. North Fairview 1121, Quezon City NCR, " +
      "Second District Philippines",
  contact: process.env.BIZ_CONTACT || "Tel. No.: (02) 8642-2204 / Cell No.: 0995-128-2580",
};

// ----- Outgoing email: sign-up OTP codes -----------------------------------
// Two ways to send, picked with EMAIL_PROVIDER (see .env.example for setup):
//   gmail  — a Gmail account + App Password, over Gmail's own mail server.
//            Reaches any customer's inbox, no domain needed, 500 emails/day.
//   resend — the Resend email API. Needs a domain you own verified in Resend
//            before it will email anyone but yourself. 100 emails/day free.
// These values are read on the server only and are never sent to the browser.
//
// With nothing configured, on localhost the OTP is printed in the server
// terminal instead of emailed. On any other host sign-up is refused, so a
// deployed site can never create an account whose owner was never sent a code.
const GMAIL_USER = (process.env.GMAIL_USER || "").trim();
// Google shows an App Password as four groups of four letters; the spaces are
// dropped so it can be pasted either way.
const GMAIL_APP_PASSWORD = (process.env.GMAIL_APP_PASSWORD || "").replace(/\s+/g, "");
const EMAIL_API_KEY = (process.env.EMAIL_API_KEY || "").trim();   // Resend key, starts "re_"
const EMAIL_FROM = (process.env.EMAIL_FROM || "").trim();         // Resend sender address
const EMAIL_FROM_NAME = (process.env.EMAIL_FROM_NAME || "Galaxy Trading").trim();

// Which service sends. Left blank, it follows whichever credentials are filled
// in (Gmail first). Anything else, e.g. the old "brevo", counts as not set.
const EMAIL_PROVIDER = (() => {
  const v = String(process.env.EMAIL_PROVIDER || "").trim().toLowerCase();
  if (v === "gmail" || v === "resend") return v;
  if (v) console.warn(`[EMAIL] EMAIL_PROVIDER="${v}" is not supported. Use gmail or resend.`);
  if (GMAIL_USER && GMAIL_APP_PASSWORD) return "gmail";
  if (EMAIL_API_KEY) return "resend";
  return "";
})();

// Overridable only so the tests can point these at local stand-ins.
const EMAIL_API_URL = process.env.EMAIL_API_URL || "https://api.resend.com/emails";
const EMAIL_SMTP_HOST = process.env.EMAIL_SMTP_HOST || "smtp.gmail.com";
const EMAIL_SMTP_PORT = parseInt(process.env.EMAIL_SMTP_PORT || "465", 10);

// How long a sign-up OTP stays valid. Clamped to 1-60 minutes so a typo in
// .env cannot produce a code that never expires.
const OTP_EXPIRES_MINUTES = Math.min(60, Math.max(1,
  parseInt(process.env.OTP_EXPIRES_MINUTES || "10", 10) || 10));

module.exports = {
  DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME, DB_SSL, UPLOAD_DIR, ALLOWED_ORIGINS,
  SECRET_KEY, TOKEN_TTL_HOURS, PORT,
  BRAND_LOGO, BRAND_LOGO_FALLBACK, brandLogo,
  HCAPTCHA_SECRET, TURNSTILE_SECRET, CAPTCHA_REQUIRED,
  VAT_RATE, DELIVERY_FEE, ONLINE_DELIVERY_FEE,
  BUSINESS,
  EMAIL_PROVIDER, GMAIL_USER, GMAIL_APP_PASSWORD,
  EMAIL_API_KEY, EMAIL_FROM, EMAIL_FROM_NAME, EMAIL_API_URL,
  EMAIL_SMTP_HOST, EMAIL_SMTP_PORT, OTP_EXPIRES_MINUTES,
};
