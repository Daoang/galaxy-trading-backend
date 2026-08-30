/**
 * totp.js — time-based one-time passwords (RFC 6238) for staff two-factor auth.
 *
 * Implemented on Node's crypto alone: TOTP is a short, well-specified algorithm
 * and this avoids adding a dependency that would need patching on a shared
 * host. Verified against the RFC 6238 published test vectors (see the test
 * script), so it interoperates with Google Authenticator, Microsoft
 * Authenticator, Authy and 1Password.
 *
 * Design notes:
 *   - SHA-1 with 6 digits and a 30-second step. Those are the defaults every
 *     authenticator app assumes; changing them breaks scanning a plain
 *     otpauth:// URI.
 *   - Verification accepts the adjacent time steps (+/- 1) so a phone clock
 *     that drifts a few seconds still works. Wider windows weaken the control.
 *   - Recovery codes are stored only as hashes, exactly like passwords, and are
 *     single use.
 */
const crypto = require("crypto");

const DIGITS = 6;
const STEP_SECONDS = 30;
const DRIFT_STEPS = 1; // accept the previous and next step

// --- base32 (RFC 4648, no padding) - what authenticator apps expect ---------
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buf) {
  let bits = 0, value = 0, out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  const clean = String(str || "").toUpperCase().replace(/=+$/, "").replace(/\s+/g, "");
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx === -1) throw new Error("Invalid base32 character: " + ch);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** A fresh 20-byte secret, base32 encoded (the size RFC 4226 recommends). */
function generateSecret() {
  return base32Encode(crypto.randomBytes(20));
}

/**
 * The HOTP value for a counter (RFC 4226), which TOTP builds on.
 * `algorithm` is exposed only so the RFC 6238 test vectors (which use
 * SHA-256/512) can be checked; live use stays on SHA-1.
 */
function hotp(secretBuf, counter, algorithm = "sha1", digits = DIGITS) {
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);

  const hmac = crypto.createHmac(algorithm, secretBuf).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(bin % 10 ** digits).padStart(digits, "0");
}

/** The current code for a base32 secret. */
function generateCode(secretB32, atMs = Date.now(), algorithm = "sha1", digits = DIGITS, step = STEP_SECONDS) {
  const counter = Math.floor(atMs / 1000 / step);
  return hotp(base32Decode(secretB32), counter, algorithm, digits);
}

/**
 * Check a user-supplied code. Returns true only for an exact match within the
 * drift window. Comparison is constant-time so a timing side channel cannot
 * reveal how many leading digits were right.
 */
function verifyCode(secretB32, code, atMs = Date.now()) {
  const clean = String(code || "").replace(/\D/g, "");
  if (clean.length !== DIGITS) return false;
  const counter = Math.floor(atMs / 1000 / STEP_SECONDS);
  const key = base32Decode(secretB32);
  for (let d = -DRIFT_STEPS; d <= DRIFT_STEPS; d++) {
    const expected = hotp(key, counter + d);
    const a = Buffer.from(expected);
    const b = Buffer.from(clean);
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
  }
  return false;
}

/** The otpauth:// URI an authenticator app scans from a QR code. */
function otpauthUri(secretB32, account, issuer = "Galaxy Trading") {
  const label = encodeURIComponent(issuer) + ":" + encodeURIComponent(account);
  const params = new URLSearchParams({
    secret: secretB32,
    issuer,
    algorithm: "SHA1",
    digits: String(DIGITS),
    period: String(STEP_SECONDS),
  });
  return "otpauth://totp/" + label + "?" + params.toString();
}

// ---------------------------------------------------------------------------
//  Recovery codes - the way back in when the phone is lost.
// ---------------------------------------------------------------------------
const RECOVERY_COUNT = 8;

function hashRecovery(code) {
  return crypto.createHash("sha256").update(String(code).toUpperCase().replace(/-/g, "")).digest("hex");
}

/** Returns { plain: [...], hashes: [...] }. Show `plain` exactly once. */
function generateRecoveryCodes(count = RECOVERY_COUNT) {
  const plain = [];
  for (let i = 0; i < count; i++) {
    const raw = crypto.randomBytes(5).toString("hex").toUpperCase(); // 10 chars
    plain.push(raw.slice(0, 5) + "-" + raw.slice(5));
  }
  return { plain, hashes: plain.map(hashRecovery) };
}

/**
 * Consume a recovery code. Returns the remaining hashes when it matched, or
 * null when it did not - so the caller can persist the shortened list and the
 * code cannot be reused.
 */
function consumeRecoveryCode(code, storedHashes) {
  const target = hashRecovery(code);
  const list = Array.isArray(storedHashes) ? storedHashes : [];
  const idx = list.indexOf(target);
  if (idx === -1) return null;
  return list.filter((_, i) => i !== idx);
}

module.exports = {
  generateSecret,
  generateCode,
  verifyCode,
  otpauthUri,
  generateRecoveryCodes,
  consumeRecoveryCode,
  hashRecovery,
  hotp,
  base32Encode,
  base32Decode,
  DIGITS,
  STEP_SECONDS,
};
