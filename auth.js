/**
 * auth.js — authentication & role-based access control.
 *
 *   * Password hashing uses only Node's crypto (PBKDF2-SHA256), so the seed
 *     hashes in database/schema.sql (pbkdf2_sha256$iters$salt$hash) verify
 *     as-is — no dependency needed.
 *   * Session tokens are signed with HMAC-SHA256 (a URLSafeTimedSerializer
 *     equivalent) — carries {user_id, username, role} and expires.
 *   * requireRole(...) guards endpoints by role name.
 */

const crypto = require("crypto");
const config = require("./config");

const ITER = 120000;
const SALT = "galaxy-auth";

function signingKey() {
  return crypto.createHash("sha256").update(`${config.SECRET_KEY}:${SALT}`).digest();
}

// --------------------------------------------------------------------------
// Password hashing  (format: pbkdf2_sha256$iterations$salt_hex$hash_hex)
// --------------------------------------------------------------------------
function hashPassword(password, salt = null) {
  if (!salt) salt = crypto.randomBytes(16);
  const dk = crypto.pbkdf2Sync(password, salt, ITER, 32, "sha256");
  return `pbkdf2_sha256$${ITER}$${salt.toString("hex")}$${dk.toString("hex")}`;
}

function verifyPassword(password, stored) {
  try {
    const [algo, iters, saltHex, hashHex] = stored.split("$");
    if (algo !== "pbkdf2_sha256") return false;
    const salt = Buffer.from(saltHex, "hex");
    const dk = crypto.pbkdf2Sync(password, salt, parseInt(iters, 10), hashHex.length / 2, "sha256");
    const a = dk.toString("hex");
    return a.length === hashHex.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(hashHex));
  } catch (e) {
    return false;
  }
}

// --------------------------------------------------------------------------
// Token issue / verify
// --------------------------------------------------------------------------
function base64url(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Buffer.from(str, "base64");
}

/**
 * Issue a session token.
 *
 * `opts.remember` is the "Stay signed in" tick. The chosen lifetime is written
 * INTO the signed payload rather than read from config at verification time,
 * so a long-lived token stays long-lived and a short one cannot be stretched:
 * editing the ttl breaks the signature.
 */
const REMEMBER_TTL_HOURS = 24 * 30; // 30 days

function issueToken(user, opts) {
  const remember = !!(opts && opts.remember);
  const payload = {
    user_id: user.user_id,
    username: user.username,
    role: user.role_name,
    ttl: remember ? REMEMBER_TTL_HOURS : config.TOKEN_TTL_HOURS,
  };
  const payloadB64 = base64url(Buffer.from(JSON.stringify(payload)));
  const ts = Math.floor(Date.now() / 1000);
  const tsB64 = base64url(Buffer.from(String(ts)));
  const signed = `${payloadB64}.${tsB64}`;
  const sig = base64url(crypto.createHmac("sha256", signingKey()).update(signed).digest());
  return `${signed}.${sig}`;
}

function decodeToken(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [payloadB64, tsB64, sig] = parts;
    const signed = `${payloadB64}.${tsB64}`;
    const expected = base64url(crypto.createHmac("sha256", signingKey()).update(signed).digest());
    if (expected.length !== sig.length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))) {
      return null;
    }
    const ts = parseInt(base64urlDecode(tsB64).toString("utf8"), 10);
    const ageSeconds = Math.floor(Date.now() / 1000) - ts;
    const payload = JSON.parse(base64urlDecode(payloadB64).toString("utf8"));
    // Honour the lifetime baked into the token; tokens issued before this
    // existed simply fall back to the configured default.
    const ttlHours = Number(payload.ttl) > 0 ? Number(payload.ttl) : config.TOKEN_TTL_HOURS;
    if (ageSeconds > ttlHours * 3600) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

// --------------------------------------------------------------------------
// Middleware
// --------------------------------------------------------------------------
function extractToken(req) {
  const header = req.headers["authorization"] || "";
  if (header.startsWith("Bearer ")) return header.slice(7);
  return req.query.token;
}

function loginRequired(req, res, next) {
  const token = extractToken(req);
  const data = token ? decodeToken(token) : null;
  if (!data) return res.status(401).json({ error: "Authentication required" });
  req.user = data;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    const token = extractToken(req);
    const data = token ? decodeToken(token) : null;
    if (!data) return res.status(401).json({ error: "Authentication required" });
    if (!roles.includes(data.role)) {
      return res.status(403).json({ error: "Forbidden: your role cannot access this resource" });
    }
    req.user = data;
    next();
  };
}

module.exports = {
  REMEMBER_TTL_HOURS,
  hashPassword,
  verifyPassword,
  issueToken,
  decodeToken,
  loginRequired,
  requireRole,
};
