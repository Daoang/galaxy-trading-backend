/**
 * twofactor.js — enrolment and verification endpoints for TOTP two-factor auth.
 *
 * Login becomes two steps for anyone who has enrolled:
 *   1. POST /api/auth/login          -> { requires_2fa: true, challenge } (no session yet)
 *   2. POST /api/auth/2fa/verify     -> { token } once the 6-digit code checks out
 *
 * The challenge is a short-lived signed value that proves step 1 succeeded. It
 * is NOT a session token: it carries no role and is accepted only by the verify
 * endpoint, so intercepting it does not grant access to anything.
 *
 * Accounts without 2FA are untouched — step 1 still returns a session token
 * directly, so enabling this feature never locks anyone out.
 */
const crypto = require("crypto");
const express = require("express");
const auth = require("./auth");
const db = require("./db");
const config = require("./config");
const totp = require("./totp");

const router = express.Router();

const CHALLENGE_TTL_SECONDS = 300; // 5 minutes to type a code

function h(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}
function clientIp(req) {
  return req.headers["x-forwarded-for"] || req.socket.remoteAddress;
}

// --- the interim challenge between password and code ------------------------
function signChallenge(userId) {
  const payload = userId + "." + Math.floor(Date.now() / 1000);
  const sig = crypto.createHmac("sha256", config.SECRET_KEY + ":2fa").update(payload).digest("hex");
  return Buffer.from(payload + "." + sig).toString("base64url");
}

function readChallenge(challenge) {
  try {
    const raw = Buffer.from(String(challenge), "base64url").toString("utf8");
    const [userId, issued, sig] = raw.split(".");
    const expect = crypto.createHmac("sha256", config.SECRET_KEY + ":2fa")
      .update(userId + "." + issued).digest("hex");
    const a = Buffer.from(sig || "");
    const b = Buffer.from(expect);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    if (Math.floor(Date.now() / 1000) - Number(issued) > CHALLENGE_TTL_SECONDS) return null;
    return parseInt(userId, 10);
  } catch (e) {
    return null;
  }
}

async function loadUser(userId) {
  return db.query(
    "SELECT u.user_id, u.username, u.full_name, u.is_active, u.totp_secret, " +
      "       u.totp_enabled, u.totp_recovery, r.role_name " +
      "FROM tbl_users u JOIN tbl_roles r ON r.role_id = u.role_id WHERE u.user_id = ?",
    [userId], true
  );
}

/** Shared by the login route: has this account turned 2FA on? */
function requiresTwoFactor(user) {
  return !!(user && user.totp_enabled && user.totp_secret);
}

/** The challenge handed back instead of a session token. */
function challengeResponse(user) {
  return { requires_2fa: true, challenge: signChallenge(user.user_id), username: user.username };
}

// ===========================================================================
//  STEP 2 OF LOGIN — exchange a valid code for a real session
// ===========================================================================
router.post(
  "/api/auth/2fa/verify",
  h(async (req, res) => {
    const b = req.body || {};
    const userId = readChallenge(b.challenge);
    if (!userId) {
      return res.status(401).json({ error: "That sign-in attempt expired. Please log in again." });
    }
    const user = await loadUser(userId);
    if (!user || !user.is_active || !requiresTwoFactor(user)) {
      return res.status(401).json({ error: "Two-factor is not active for this account." });
    }

    const code = String(b.code || "").trim();
    let ok = totp.verifyCode(user.totp_secret, code);
    let usedRecovery = false;

    // A recovery code is the way in when the phone is gone. Single use.
    if (!ok && code.length >= 10) {
      let stored = [];
      try { stored = JSON.parse(user.totp_recovery || "[]"); } catch (e) { stored = []; }
      const remaining = totp.consumeRecoveryCode(code, stored);
      if (remaining) {
        await db.execute("UPDATE tbl_users SET totp_recovery=? WHERE user_id=?",
                         [JSON.stringify(remaining), user.user_id]);
        ok = true;
        usedRecovery = true;
        await db.audit(user.user_id,
          `Signed in with a recovery code (${remaining.length} left)`, "tbl_users", clientIp(req));
      }
    }

    if (!ok) {
      await db.audit(user.user_id, "Failed two-factor code", "tbl_users", clientIp(req));
      return res.status(401).json({ error: "Incorrect code. Check your authenticator app and try again." });
    }

    if (!usedRecovery) {
      await db.audit(user.user_id, `Logged in with 2FA (${user.role_name})`, "tbl_users", clientIp(req));
    }
    res.json({
      token: auth.issueToken(user, { remember: !!b.remember }),
      used_recovery_code: usedRecovery,
      user: {
        user_id: user.user_id, username: user.username,
        full_name: user.full_name, role: user.role_name,
      },
    });
  })
);

// ===========================================================================
//  ENROLMENT — a signed-in user managing their own second factor
// ===========================================================================
router.get(
  "/api/account/2fa/status",
  auth.loginRequired,
  h(async (req, res) => {
    const u = await loadUser(req.user.user_id);
    let remaining = 0;
    try { remaining = JSON.parse(u.totp_recovery || "[]").length; } catch (e) {}
    res.json({
      enabled: !!u.totp_enabled,
      pending: !!(u.totp_secret && !u.totp_enabled),
      recovery_codes_left: u.totp_enabled ? remaining : 0,
    });
  })
);

/** Start enrolment: mint a secret and hand back the QR payload. */
router.post(
  "/api/account/2fa/setup",
  auth.loginRequired,
  h(async (req, res) => {
    const u = await loadUser(req.user.user_id);
    if (u.totp_enabled) {
      return res.status(400).json({ error: "Two-factor is already switched on for this account." });
    }
    const secret = totp.generateSecret();
    // Stored but NOT enabled - it only counts once a code is confirmed below.
    await db.execute("UPDATE tbl_users SET totp_secret=?, totp_enabled=0 WHERE user_id=?",
                     [secret, u.user_id]);
    // No `image=` parameter here on purpose. A logo URL pushed the otpauth URI
    // past what a QR at error-correction level H can hold (1636 bits into a
    // 1056-bit code) and the QR failed to render at all — and Microsoft and
    // Google Authenticator ignore that parameter anyway, so it bought nothing.
    // The shop logo is drawn over the middle of the QR by the page instead.
    res.json({
      secret,
      otpauth_uri: totp.otpauthUri(secret, u.username),
      digits: totp.DIGITS,
      period: totp.STEP_SECONDS,
      logo_url: "../" + config.brandLogo(),
    });
  })
);

/** Confirm enrolment with a live code, then issue the recovery codes. */
router.post(
  "/api/account/2fa/enable",
  auth.loginRequired,
  h(async (req, res) => {
    const u = await loadUser(req.user.user_id);
    if (u.totp_enabled) return res.status(400).json({ error: "Already switched on." });
    if (!u.totp_secret) return res.status(400).json({ error: "Start setup first." });

    if (!totp.verifyCode(u.totp_secret, String((req.body || {}).code || ""))) {
      return res.status(400).json({ error: "That code did not match. Check your app's clock and try again." });
    }

    const rec = totp.generateRecoveryCodes();
    await db.execute(
      "UPDATE tbl_users SET totp_enabled=1, totp_recovery=?, totp_enrolled_at=NOW() WHERE user_id=?",
      [JSON.stringify(rec.hashes), u.user_id]
    );
    await db.audit(u.user_id, "Enabled two-factor authentication", "tbl_users", clientIp(req));
    // The only time the plaintext recovery codes ever exist.
    res.json({ ok: true, recovery_codes: rec.plain });
  })
);

/** Turn it off. Requires the account password AND a current code. */
router.post(
  "/api/account/2fa/disable",
  auth.loginRequired,
  h(async (req, res) => {
    const b = req.body || {};
    const u = await loadUser(req.user.user_id);
    if (!u.totp_enabled) return res.status(400).json({ error: "Two-factor is not switched on." });

    const row = await db.query("SELECT password_hash FROM tbl_users WHERE user_id=?", [u.user_id], true);
    if (!row || !auth.verifyPassword(String(b.password || ""), row.password_hash)) {
      return res.status(400).json({ error: "Password is incorrect." });
    }
    if (!totp.verifyCode(u.totp_secret, String(b.code || ""))) {
      return res.status(400).json({ error: "Current authenticator code is required to switch this off." });
    }

    await db.execute(
      "UPDATE tbl_users SET totp_enabled=0, totp_secret=NULL, totp_recovery=NULL, totp_enrolled_at=NULL WHERE user_id=?",
      [u.user_id]
    );
    await db.audit(u.user_id, "Disabled two-factor authentication", "tbl_users", clientIp(req));
    res.json({ ok: true });
  })
);

// ===========================================================================
//  ADMIN — reset a locked-out employee (phone lost, no recovery codes left)
// ===========================================================================
router.post(
  "/api/admin/users/:uid/2fa/reset",
  auth.requireRole("Administrator"),
  h(async (req, res) => {
    const uid = parseInt(req.params.uid, 10);
    const target = await loadUser(uid);
    if (!target) return res.status(404).json({ error: "User not found" });
    await db.execute(
      "UPDATE tbl_users SET totp_enabled=0, totp_secret=NULL, totp_recovery=NULL, totp_enrolled_at=NULL WHERE user_id=?",
      [uid]
    );
    await db.audit(req.user.user_id,
      `Reset two-factor for '${target.username}'`, "tbl_users", clientIp(req));
    res.json({ ok: true, username: target.username });
  })
);

module.exports = { router, requiresTwoFactor, challengeResponse };
