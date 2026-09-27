/**
 * security.js — HTTP hardening applied to every request.
 *
 * Deliberately dependency-free: these are plain headers, and adding a package
 * for them would be one more thing to keep patched on a shared host.
 *
 * What this DOES cover: transport security, clickjacking, MIME sniffing,
 * referrer leakage, a resource allowlist, and blanket API rate limiting.
 *
 * What it does NOT cover, so nobody is misled:
 *   - The certificate itself. HSTS and the redirect only matter once Hostinger
 *     has issued the SSL certificate for the domain.
 *   - Inline scripts. Every page in this project keeps its logic in an inline
 *     <script> block, so the policy below must allow 'unsafe-inline' for
 *     scripts and styles. That materially weakens CSP's XSS protection: it
 *     still blocks loading code from an unapproved domain, but it cannot stop
 *     injected inline code. Removing that caveat means moving every page's
 *     script into its own .js file — a real refactor, not a config change.
 */
const rateLimit = require("express-rate-limit");
const config = require("./config");

// Origins the frontend genuinely loads from. Anything else is blocked.
const CDN = [
  "https://cdn.jsdelivr.net",        // ApexCharts
  "https://cdnjs.cloudflare.com",    // jsPDF + AutoTable
  "https://unpkg.com",               // Leaflet
  "https://challenges.cloudflare.com" // Turnstile widget
];
const FONTS = ["https://fonts.googleapis.com", "https://fonts.gstatic.com"];
const TILES = ["https://*.tile.openstreetmap.org", "https://unpkg.com"];

const CSP = [
  "default-src 'self'",
  // 'unsafe-inline' is required by the inline <script> blocks - see the note above.
  `script-src 'self' 'unsafe-inline' ${CDN.join(" ")}`,
  `style-src 'self' 'unsafe-inline' ${FONTS[0]} https://unpkg.com`,   // Leaflet ships a stylesheet
  `font-src 'self' ${FONTS[1]} data:`,
  `img-src 'self' data: blob: ${TILES.join(" ")}`,
  `connect-src 'self' ${CDN.join(" ")}`,
  "frame-src https://challenges.cloudflare.com",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'self'",
].join("; ");

/** True when the request reached us over TLS (directly or via a proxy). */
function isSecure(req) {
  return req.secure || (req.headers["x-forwarded-proto"] || "").split(",")[0].trim() === "https";
}

function securityHeaders(req, res, next) {
  // Only assert HSTS on a real HTTPS request - sending it over plain HTTP, or
  // on localhost, would pin a browser to a scheme the dev server cannot serve.
  if (isSecure(req)) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "geolocation=(self), camera=(), microphone=(), payment=()");
  res.setHeader("Content-Security-Policy", CSP);
  res.removeHeader("X-Powered-By"); // stop advertising Express
  next();
}

/**
 * Send browsers to HTTPS in production. Skipped on localhost so the XAMPP
 * workflow keeps working, and skipped unless a proxy tells us the original
 * scheme - otherwise this would loop forever behind a TLS-terminating proxy.
 */
function forceHttps(req, res, next) {
  const host = String(req.headers.host || "");
  const local = /^(localhost|127\.0\.0\.1|\[::1\])(:|$)/.test(host);
  if (local || isSecure(req) || !req.headers["x-forwarded-proto"]) return next();
  return res.redirect(301, "https://" + host + req.originalUrl);
}

/**
 * Blanket limit on the API. The login/register limiters stay much stricter;
 * this one is the backstop against scraping and brute-force against everything
 * else, and is generous enough that normal dashboard use never trips it.
 */
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) =>
    res.status(429).json({ error: "Too many requests. Please slow down and try again shortly." }),
});

/**
 * CORS: the site itself, plus any origin listed in ALLOWED_ORIGINS.
 *
 * With the pages and the API on one host, "the site itself" is all that is
 * ever needed. Hosting them apart (pages on Hostinger, API on Render) means
 * naming the pages' address in ALLOWED_ORIGINS — nothing else may call the
 * API from a browser.
 */
function sameOriginCors(req, res, next) {
  const origin = req.headers.origin;
  if (origin) {
    const host = String(req.headers.host || "");
    let sameHost = false;
    try { sameHost = new URL(origin).host === host; } catch (e) { sameHost = false; }
    const listed = config.ALLOWED_ORIGINS.includes(String(origin).replace(/\/+$/, ""));
    if (sameHost || listed) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Credentials", "true");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS");
      // Cache the preflight so every API call is not preceded by a second trip.
      res.setHeader("Access-Control-Max-Age", "600");
    }
    // A cross-origin request simply gets no CORS headers, so the browser blocks it.
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
}

// ---------------------------------------------------------------------------
//  Password policy - applied wherever a password is set or changed.
// ---------------------------------------------------------------------------
const MIN_LENGTH = 12;
const COMMON = new Set([
  "password", "password1", "password123", "12345678", "123456789", "1234567890",
  "qwertyuiop", "admin123", "administrator", "letmein123", "welcome123",
  "changeme123", "galaxytrading", "iloveyou123", "qwerty123456", "passw0rd123",
]);

/**
 * Returns null when acceptable, otherwise a message explaining what is wrong.
 *
 * Follows NIST SP 800-63B: length is the control that actually matters, and
 * forced composition rules ("must contain a capital and a symbol") are
 * explicitly discouraged there - they push people toward predictable
 * substitutions without adding real entropy. So this checks length, screens a
 * blocklist, and rejects the password being the username itself.
 */
function checkPasswordStrength(password, username) {
  const pw = String(password || "");
  if (pw.length < MIN_LENGTH) {
    return `Password must be at least ${MIN_LENGTH} characters.`;
  }
  if (pw.length > 200) {
    return "Password must be 200 characters or fewer.";
  }
  if (COMMON.has(pw.toLowerCase())) {
    return "That password is too common. Choose something less predictable.";
  }
  if (username && pw.toLowerCase() === String(username).toLowerCase()) {
    return "Password must not be the same as the username.";
  }
  if (/^(.)\1+$/.test(pw)) {
    return "Password must not be a single repeated character.";
  }
  return null;
}

// The customer policy lives in ../password-rules.js so the Sign Up page and
// this server read the exact same rules.
const PasswordRules = require("../password-rules.js");

/**
 * Customer passwords (storefront sign-up and change-password).
 *
 * Stricter than checkPasswordStrength above: 12+ characters, at least 3 of
 * lower / upper / number / special, and no more than 2 identical characters in
 * a row. Staff accounts keep checkPasswordStrength, because the staff
 * passwords already in use follow a name.surname.role! pattern that has only
 * two of those four kinds and would be refused here.
 *
 * Returns null when acceptable, otherwise a message.
 */
function checkCustomerPassword(password, email) {
  const pw = String(password || "");
  const problem = PasswordRules.firstProblem(pw);
  if (problem) return problem;
  if (COMMON.has(pw.toLowerCase())) {
    return "That password is too common. Choose something less predictable.";
  }
  const e = String(email || "").toLowerCase();
  if (e && (pw.toLowerCase() === e || pw.toLowerCase() === e.split("@")[0])) {
    return "Password must not be your email address.";
  }
  return null;
}

module.exports = {
  securityHeaders,
  forceHttps,
  apiLimiter,
  sameOriginCors,
  checkPasswordStrength,
  checkCustomerPassword,
  isSecure,
  MIN_LENGTH,
};
