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

// ----- App / security -------------------------------------------------------
const SECRET_KEY = process.env.SECRET_KEY || "dev-change-me-in-production";
const TOKEN_TTL_HOURS = parseInt(process.env.TOKEN_TTL_HOURS || "12", 10);
const PORT = parseInt(process.env.PORT || "5000", 10);

// ----- External APIs (fill these in .env to go live) ------------------------
// hCaptcha + Cloudflare Turnstile — server-side verification secrets
const HCAPTCHA_SECRET = process.env.HCAPTCHA_SECRET || "";
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || "";
// When no secret is set, captcha verification is skipped (so the app runs
// out-of-the-box). Set the secrets in .env to enforce it.
const CAPTCHA_REQUIRED = bool("CAPTCHA_REQUIRED", false);

// ----- Walk-in POS / VAT receipt --------------------------------------------
// Sales at or above this peso amount require a one-time code to complete.
const HIGH_VALUE_THRESHOLD = parseFloat(process.env.HIGH_VALUE_THRESHOLD || "10000");
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

// Firebase — optional. The portal can authenticate against this MySQL backend
// directly (works today) OR you can wire Firebase Auth on the client and verify
// ID tokens here with the Firebase Admin SDK + a service-account JSON.
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID || "";

module.exports = {
  DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME,
  SECRET_KEY, TOKEN_TTL_HOURS, PORT,
  HCAPTCHA_SECRET, TURNSTILE_SECRET, CAPTCHA_REQUIRED,
  HIGH_VALUE_THRESHOLD, VAT_RATE,
  BUSINESS,
  FIREBASE_PROJECT_ID,
};
