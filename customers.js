/**
 * customers.js — storefront customer accounts, address book and order history.
 *
 * These used to live entirely in the browser's localStorage, which meant a
 * customer account only existed on the one machine that created it: it was
 * lost on a new browser, a cleared cache, a different origin, and it was never
 * part of the project folder when it was zipped. Everything here now persists
 * in MySQL alongside the staff accounts, reusing the same tbl_users table and
 * the same PBKDF2 hashing the staff portal uses.
 *
 * Mounted by app.js. Run database/migration_customer_accounts.sql first.
 */
const crypto = require("crypto");
const express = require("express");
const auth = require("./auth");
const db = require("./db");
const config = require("./config");
const security = require("./security");
const payments = require("./payments");
const mailer = require("./mailer");
const twofactor = require("./twofactor");
// The storefront catalog. Read here only to know which products may be
// customized (CUSTOMIZABLE_NAMES), so page and server share one list.
const catalog = require("./products.js");

const CUSTOMER_ROLE_ID = 6; // tbl_roles: 6 = 'Customer'

// Checkout pricing. These live on the SERVER so the amount a customer is
// charged never depends on numbers posted by the browser.
const CUT_FEE = 20;        // pesos per cut
const BEND_FEE = 20;       // pesos per bend
const DELIVERY_FEE = config.DELIVERY_FEE;  // flat door-to-door fee; pick-up is free
const SPLIT_RATE = 0.5;    // split payment = 50% now

const peso = (n) => Math.round((Number(n) || 0) * 100) / 100;

/**
 * Look a voucher up and work out what it is worth against a given subtotal.
 *
 * Always resolves to { ok, ... }: `ok:false` carries a reason the UI can show,
 * `ok:true` carries the row and the computed discount. Called from BOTH the
 * "check this code" endpoint and order creation, so what the customer is shown
 * and what they are actually charged come from the same code path.
 *
 * `subtotal` is merchandise + customization: shipping is never discounted.
 */
async function evaluateVoucher(code, subtotal, userId) {
  const clean = String(code || "").trim().toUpperCase();
  if (!clean) return { ok: false, error: "Enter a voucher code." };

  const v = await db.query("SELECT * FROM tbl_vouchers WHERE code = ?", [clean], true);
  if (!v) return { ok: false, error: "That voucher code was not found." };
  if (!v.is_active) return { ok: false, error: "That voucher is no longer active." };

  if (v.expires_on) {
    // Compare calendar dates, not instants - a voucher is good all through its
    // final day regardless of the time of day.
    const exp = new Date(v.expires_on);
    const today = new Date();
    const expDay = new Date(exp.getFullYear(), exp.getMonth(), exp.getDate());
    const nowDay = new Date(today.getFullYear(), today.getMonth(), today.getDate());
    if (nowDay > expDay) {
      return { ok: false, error: "That voucher expired on " + expDay.toDateString().slice(4) + "." };
    }
  }
  if (v.uses_left <= 0) return { ok: false, error: "That voucher has been fully redeemed." };

  const sub = peso(subtotal);
  if (sub < parseFloat(v.min_order)) {
    return { ok: false, error: "This voucher needs a subtotal of at least PHP " +
             parseFloat(v.min_order).toLocaleString("en-PH", { minimumFractionDigits: 2 }) + "." };
  }

  // One redemption per customer per voucher.
  if (userId) {
    const used = await db.query(
      "SELECT 1 FROM tbl_voucher_redemptions WHERE voucher_id=? AND user_id=?",
      [v.voucher_id, userId], true);
    if (used) return { ok: false, error: "You have already used this voucher." };
  }

  let discount = v.discount_type === "percent"
    ? sub * (parseFloat(v.value) / 100)
    : parseFloat(v.value);
  if (v.max_discount != null) discount = Math.min(discount, parseFloat(v.max_discount));
  // Never let a discount exceed the goods, which would make the order negative.
  discount = peso(Math.max(0, Math.min(discount, sub)));

  return {
    ok: true,
    voucher: v,
    code: v.code,
    discount,
    description: v.description || "",
    discount_type: v.discount_type,
    value: parseFloat(v.value),
  };
}

const router = express.Router();

/** Wrap async handlers so rejected promises reach Express error handling. */
function h(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function clientIp(req) {
  return req.headers["x-forwarded-for"] || req.socket.remoteAddress;
}

/**
 * Format a DATE column as YYYY-MM-DD.
 *
 * mysql2 hands back a Date at LOCAL midnight for a DATE column, so
 * .toISOString() would shift a Philippine (UTC+8) date one day backwards.
 * A birthday is a calendar date, not an instant — read the local parts.
 */
function dateOnly(value) {
  if (!value) return "";
  const d = value instanceof Date ? value : new Date(value);
  if (isNaN(d)) return "";
  const pad = (n) => String(n).padStart(2, "0");
  return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate());
}

/**
 * Shape a tbl_users row the way the storefront's Auth.user expects, so the
 * frontend keeps reading .username/.name/.email/.phone as it always has.
 */
function publicProfile(row) {
  return {
    user_id: row.user_id,
    username: row.username,
    // Sign-up no longer asks for a name, so fall back to the first part of
    // the email rather than the generated internal username.
    name: row.full_name || (row.email ? String(row.email).split("@")[0] : row.username),
    full_name: row.full_name || "",
    email: row.email || "",
    phone: row.phone || "",
    dob: dateOnly(row.date_of_birth),
    gender: row.gender || "",
    avatar: row.avatar || "",
    role: row.role_name || "Customer",
  };
}

async function loadProfile(userId) {
  const row = await db.query(
    "SELECT u.user_id, u.username, u.full_name, u.email, u.phone, u.date_of_birth, " +
      "       u.gender, u.avatar, r.role_name " +
      "FROM tbl_users u JOIN tbl_roles r ON r.role_id = u.role_id " +
      "WHERE u.user_id = ?",
    [userId],
    true
  );
  return row ? publicProfile(row) : null;
}

// ===========================================================================
//  REGISTRATION  (public — the storefront sign-up form)
//
//  Email is the only identifier a customer supplies. Sign-up is:
//    1. POST /api/auth/register/start   { email, password, confirm_password }
//         -> password rules checked, a 6-digit OTP is emailed, and the
//            browser gets a signup_token (NOT the OTP) naming this attempt
//    2. POST /api/auth/register/verify  { email, signup_token, code }
//         -> the account is created only if the OTP matches
//       POST /api/auth/register/resend  { email, signup_token }
//         -> a fresh OTP for the same attempt; the old one stops working
//  No account exists until the owner of the mailbox has typed the code.
//
//  The chosen password waits between steps 1 and 2 as a PBKDF2 hash in
//  tbl_email_verifications (never plain text) and is wiped once used.
//
//  There used to be Google and Facebook buttons. They were not real sign-in:
//  each logged every visitor into one shared account with a password written
//  into app.js. They and that route are gone.
// ===========================================================================

const CODE_TTL_MIN = config.OTP_EXPIRES_MINUTES; // OTP_EXPIRES_MINUTES in .env, default 10
const CODE_MAX_ATTEMPTS = 5;      // wrong guesses before a code is dead
const RESEND_GAP_SEC = 60;        // no more than one code a minute per address
const MAX_CODES_PER_HOUR = 5;     // and a ceiling on how often a mailbox is emailed

const SIGNUP_EXPIRED = "This sign-up has expired. Go back and enter your details again.";
const ALREADY_REGISTERED = "An account already uses this email. Log in instead.";

/** Lower-case, trimmed, and plausibly an address. Returns null if not. */
function normaliseEmail(raw) {
  const email = String(raw || "").trim().toLowerCase();
  if (!email || email.length > 120) return null;
  // Deliberately simple: something@something.tld with no spaces. The real
  // proof that an address works is that the customer receives the code.
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return null;
  return email;
}

/** HMAC of the code, bound to the address, so a stored row reveals nothing. */
function hashCode(email, code) {
  return crypto.createHmac("sha256", config.SECRET_KEY + ":email-verify")
    .update(email + ":" + code).digest("hex");
}

/** Only a hash of the sign-up token is stored, like the code itself. */
function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

/** A well-formed token is 64 hex characters; anything else matches nothing. */
function cleanToken(raw) {
  const t = String(raw || "").trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(t) ? t : null;
}

/** An internal username the customer never has to know or type. */
async function makeUsername(email) {
  const base = email.split("@")[0].replace(/[^a-z0-9._]/g, "").slice(0, 20) || "customer";
  for (let i = 0; i < 8; i++) {
    const candidate = `${base}_${crypto.randomBytes(3).toString("hex")}`;
    if (!(await db.query("SELECT 1 FROM tbl_users WHERE username=?", [candidate], true))) {
      return candidate;
    }
  }
  return `customer_${crypto.randomBytes(6).toString("hex")}`;
}

const emailTaken = (email) => db.query("SELECT 1 FROM tbl_users WHERE email=?", [email], true);

/**
 * Per-address throttle shared by start and resend. Resolves to null when a
 * code may be sent, otherwise to { status, body } to reply with.
 */
async function codeThrottle(email) {
  // Keep the table from growing forever: anything a day old is useless.
  await db.execute(
    "DELETE FROM tbl_email_verifications WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 DAY)");

  const recent = await db.query(
    "SELECT COUNT(*) AS hour_count, " +
      "       COALESCE(TIMESTAMPDIFF(SECOND, MAX(created_at), NOW()), 999999) AS since_last " +
      "FROM tbl_email_verifications " +
      "WHERE email=? AND purpose='signup' AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)",
    [email], true);
  if (recent && recent.since_last < RESEND_GAP_SEC) {
    const wait = RESEND_GAP_SEC - recent.since_last;
    return { status: 429, body: { error: `Please wait ${wait} seconds before asking for another code.`,
                                  retry_after: wait } };
  }
  if (recent && recent.hour_count >= MAX_CODES_PER_HOUR) {
    return { status: 429, body: { error: "Too many codes requested for this email. Try again in an hour." } };
  }
  return null;
}

/**
 * Email a new OTP for one sign-up attempt and record it. Earlier codes for the
 * same attempt are retired, so only the newest one works.
 * Resolves to { ok:true, delivery } or { ok:false, status, error }.
 */
async function issueCode(req, email, tokenHash, passwordHash) {
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
  const sent = await mailer.sendVerificationCode(req, email, code, CODE_TTL_MIN);
  if (!sent.ok) return sent;

  await db.execute(
    "UPDATE tbl_email_verifications SET consumed_at=NOW(), password_hash=NULL " +
      "WHERE signup_token=? AND consumed_at IS NULL",
    [tokenHash]);
  await db.execute(
    "INSERT INTO tbl_email_verifications " +
      "(email, purpose, code_hash, password_hash, signup_token, expires_at, ip_address) " +
      "VALUES (?, 'signup', ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE), ?)",
    [email, hashCode(email, code), passwordHash, tokenHash, CODE_TTL_MIN,
     String(clientIp(req) || "").slice(0, 45)]);
  return { ok: true, delivery: sent.delivery };
}

/** The live (unused) row for one sign-up attempt, or null. */
function pendingSignup(email, tokenHash) {
  return db.query(
    "SELECT verification_id, code_hash, password_hash, attempts, expires_at < NOW() AS expired " +
      "FROM tbl_email_verifications " +
      "WHERE email=? AND signup_token=? AND purpose='signup' AND consumed_at IS NULL " +
      "ORDER BY verification_id DESC LIMIT 1",
    [email, tokenHash], true);
}

router.post(
  "/api/auth/register/start",
  h(async (req, res) => {
    const b = req.body || {};
    const email = normaliseEmail(b.email);
    const password = String(b.password || "");
    const confirm = String(b.confirm_password == null ? "" : b.confirm_password);

    // The same rules the Sign Up checklist shows (password-rules.js), enforced
    // here because the page can be bypassed.
    if (!email) return res.status(400).json({ error: "Enter a valid email address.", field: "email" });
    const pwErr = security.checkCustomerPassword(password, email);
    if (pwErr) return res.status(400).json({ error: pwErr, field: "password" });
    if (password !== confirm) {
      return res.status(400).json({ error: "Passwords do not match.", field: "confirm" });
    }
    if (await emailTaken(email)) {
      return res.status(409).json({ error: ALREADY_REGISTERED, field: "email" });
    }

    const limited = await codeThrottle(email);
    if (limited) return res.status(limited.status).json(limited.body);

    // Names this attempt. Only the browser holding it can resend or verify, so
    // a stranger who starts a sign-up for the same address (with a password of
    // their own) can never get it activated by the real owner's code.
    const token = crypto.randomBytes(32).toString("hex");
    const sent = await issueCode(req, email, hashToken(token), auth.hashPassword(password));
    if (!sent.ok) return res.status(sent.status || 502).json({ error: sent.error });

    // Deliberately no code in this response — see mailer.js.
    res.json({ ok: true, email, signup_token: token, expires_in: CODE_TTL_MIN * 60,
               resend_after: RESEND_GAP_SEC, delivery: sent.delivery });
  })
);

router.post(
  "/api/auth/register/resend",
  h(async (req, res) => {
    const b = req.body || {};
    const email = normaliseEmail(b.email);
    const token = cleanToken(b.signup_token);
    if (!email || !token) return res.status(400).json({ error: SIGNUP_EXPIRED, restart: true });

    const tokenHash = hashToken(token);
    const pending = await pendingSignup(email, tokenHash);
    if (!pending || !pending.password_hash) {
      return res.status(400).json({ error: SIGNUP_EXPIRED, restart: true });
    }
    if (await emailTaken(email)) return res.status(409).json({ error: ALREADY_REGISTERED });

    const limited = await codeThrottle(email);
    if (limited) return res.status(limited.status).json(limited.body);

    const sent = await issueCode(req, email, tokenHash, pending.password_hash);
    if (!sent.ok) return res.status(sent.status || 502).json({ error: sent.error });
    res.json({ ok: true, email, expires_in: CODE_TTL_MIN * 60,
               resend_after: RESEND_GAP_SEC, delivery: sent.delivery });
  })
);

router.post(
  "/api/auth/register/verify",
  h(async (req, res) => {
    const b = req.body || {};
    const email = normaliseEmail(b.email);
    const token = cleanToken(b.signup_token);
    const code = String(b.code || "").replace(/\D/g, "");

    if (!email || !token) return res.status(400).json({ error: SIGNUP_EXPIRED, restart: true });
    if (code.length !== 6) return res.status(400).json({ error: "Enter the 6-digit code we emailed you." });

    const pending = await pendingSignup(email, hashToken(token));
    if (!pending || !pending.password_hash) {
      return res.status(400).json({ error: SIGNUP_EXPIRED, restart: true });
    }
    if (pending.expired) {
      return res.status(400).json({ error: "That code has expired. Tap Resend OTP for a new one." });
    }
    if (pending.attempts >= CODE_MAX_ATTEMPTS) {
      return res.status(400).json({ error: "Too many wrong codes. Tap Resend OTP for a new one.",
                                    attempts_left: 0 });
    }

    const a = Buffer.from(hashCode(email, code));
    const e = Buffer.from(pending.code_hash);
    if (a.length !== e.length || !crypto.timingSafeEqual(a, e)) {
      await db.execute(
        "UPDATE tbl_email_verifications SET attempts = attempts + 1 WHERE verification_id=?",
        [pending.verification_id]);
      const left = Math.max(0, CODE_MAX_ATTEMPTS - (pending.attempts + 1));
      return res.status(400).json({
        error: left > 0
          ? `That code is not right. ${left} attempt${left === 1 ? "" : "s"} left.`
          : "Too many wrong codes. Tap Resend OTP for a new one.",
        attempts_left: left,
      });
    }

    // Spend the code before creating anything, so a replayed request cannot
    // create a second account from one email.
    const spent = await db.pool.query(
      "UPDATE tbl_email_verifications SET consumed_at=NOW() " +
        "WHERE verification_id=? AND consumed_at IS NULL",
      [pending.verification_id]);
    if (!spent[0].affectedRows) {
      return res.status(409).json({ error: "That code has already been used." });
    }

    const username = await makeUsername(email);
    let uid;
    try {
      uid = await db.execute(
        "INSERT INTO tbl_users (username, password_hash, email, email_verified_at, role_id) " +
          "VALUES (?,?,?,NOW(),?)",
        [username, pending.password_hash, email, CUSTOMER_ROLE_ID]);
    } catch (err) {
      // Someone finished signing up with this address a moment earlier.
      if (err && err.code === "ER_DUP_ENTRY") {
        return res.status(409).json({ error: ALREADY_REGISTERED });
      }
      throw err;
    } finally {
      // The hash now lives in tbl_users, or is no longer wanted: either way no
      // pending copy for this address should stay behind.
      await db.execute(
        "UPDATE tbl_email_verifications SET password_hash=NULL " +
          "WHERE email=? AND password_hash IS NOT NULL",
        [email]);
    }
    await db.audit(uid, "Customer account created (email verified by OTP)", "tbl_users", clientIp(req));

    const profile = await loadProfile(uid);
    res.json({
      ok: true,
      token: auth.issueToken({ user_id: uid, username, role_name: "Customer" },
                             { remember: !!b.remember }),
      user: profile,
    });
  })
);

// ===========================================================================
//  LOG IN  (storefront — email + password, customers only)
//
//  The staff portal keeps its own username login at /api/auth/login. This one
//  accepts only customer accounts, and that one no longer accepts customers,
//  so neither door lets the other kind of account through.
// ===========================================================================

// Verified against when no account matches, so "no such email" and "wrong
// password" take the same time and cannot be told apart by timing.
const DUMMY_HASH = auth.hashPassword(crypto.randomBytes(24).toString("hex"));

router.post(
  "/api/auth/customer/login",
  h(async (req, res) => {
    const b = req.body || {};
    const email = normaliseEmail(b.email);
    const password = String(b.password || "");
    const fail = () => res.status(401).json({ error: "Incorrect email or password." });
    if (!email || !password) return fail();

    const user = await db.query(
      "SELECT u.user_id, u.username, u.password_hash, u.full_name, u.is_active, " +
        "       u.totp_enabled, u.totp_secret, r.role_name " +
        "FROM tbl_users u JOIN tbl_roles r ON r.role_id = u.role_id " +
        "WHERE u.email = ? AND r.role_name = 'Customer'",
      [email], true);

    const ok = auth.verifyPassword(password, user ? user.password_hash : DUMMY_HASH);
    if (!user || !ok || !user.is_active) {
      if (user) await db.audit(user.user_id, "Failed storefront login", "tbl_users", clientIp(req));
      return fail();
    }

    // Same second-factor gate the staff login uses, so the storefront door is
    // never the weaker one.
    if (twofactor.requiresTwoFactor(user)) {
      return res.json(twofactor.challengeResponse(user));
    }

    await db.audit(user.user_id, "Logged in (storefront)", "tbl_users", clientIp(req));
    res.json({
      ok: true,
      token: auth.issueToken(user, { remember: !!b.remember }),
      user: { user_id: user.user_id, username: user.username, full_name: user.full_name, role: user.role_name },
    });
  })
);

// ===========================================================================
//  PROFILE
// ===========================================================================
router.get(
  "/api/account/profile",
  auth.loginRequired,
  h(async (req, res) => {
    const profile = await loadProfile(req.user.user_id);
    if (!profile) return res.status(404).json({ error: "Account no longer exists." });
    res.json({ user: profile });
  })
);

router.patch(
  "/api/account/profile",
  auth.loginRequired,
  h(async (req, res) => {
    const b = req.body || {};

    // Email is the login, and it was proven by a code at sign-up. Letting it be
    // edited here would swap the login to an address nobody has verified — or
    // to someone else's. The account page always sends the current value back,
    // so an unchanged email is accepted and only a real change is refused.
    if ("email" in b) {
      const current = await db.query("SELECT email FROM tbl_users WHERE user_id=?",
                                     [req.user.user_id], true);
      const sent = String(b.email || "").trim().toLowerCase();
      const had = String((current && current.email) || "").toLowerCase();
      if (sent !== had) {
        return res.status(400).json({
          error: "Your email is your login and can't be changed here.",
        });
      }
      delete b.email;
    }

    // Only these columns are editable from the account page; anything else in
    // the body is ignored so a crafted request cannot change a role.
    const map = {
      name: "full_name",
      full_name: "full_name",
      phone: "phone",
      dob: "date_of_birth",
      gender: "gender",
      avatar: "avatar",
    };
    const sets = [];
    const params = [];
    for (const [key, column] of Object.entries(map)) {
      if (!(key in b)) continue;
      if (sets.some((s) => s.startsWith(column + "="))) continue; // name and full_name are aliases
      let value = b[key];
      if (typeof value === "string") value = value.trim();
      sets.push(column + "=?");
      params.push(value === "" || value === undefined ? null : value);
    }
    if (sets.length) {
      params.push(req.user.user_id);
      await db.execute("UPDATE tbl_users SET " + sets.join(", ") + " WHERE user_id=?", params);
      await db.audit(req.user.user_id, "Updated own profile", "tbl_users", clientIp(req));
    }
    res.json({ ok: true, user: await loadProfile(req.user.user_id) });
  })
);

router.post(
  "/api/account/password",
  auth.loginRequired,
  h(async (req, res) => {
    const b = req.body || {};
    const current = String(b.current_password || b.old || "");
    const next = String(b.new_password || b.new || "");
    const row = await db.query("SELECT password_hash, email FROM tbl_users WHERE user_id=?",
                               [req.user.user_id], true);
    // Customers follow the same rules as the Sign Up page; staff keep theirs.
    const pwErr = req.user.role === "Customer"
      ? security.checkCustomerPassword(next, row && row.email)
      : security.checkPasswordStrength(next, req.user.username);
    if (pwErr) return res.status(400).json({ error: pwErr });
    if (!row || !auth.verifyPassword(current, row.password_hash)) {
      return res.status(400).json({ error: "Current password is incorrect" });
    }
    await db.execute("UPDATE tbl_users SET password_hash=? WHERE user_id=?", [
      auth.hashPassword(next),
      req.user.user_id,
    ]);
    await db.audit(req.user.user_id, "Changed own password", "tbl_users", clientIp(req));
    res.json({ ok: true });
  })
);

router.delete(
  "/api/account",
  auth.loginRequired,
  h(async (req, res) => {
    // Staff accounts are referenced by orders/deliveries/fabrication logs with
    // ON DELETE RESTRICT, so only a customer can self-delete here.
    if (req.user.role !== "Customer") {
      return res.status(403).json({ error: "Only customer accounts can be deleted from here." });
    }
    // Audit first: tbl_audit_logs keeps the user_id, so the trail is written
    // while the row still exists.
    await db.audit(req.user.user_id, "Deleted own account", "tbl_users", clientIp(req));
    await db.execute("DELETE FROM tbl_users WHERE user_id=?", [req.user.user_id]);
    res.json({ ok: true });
  })
);

// ===========================================================================
//  ADDRESS BOOK
//
//  account.html edits addresses by list index and hands back the whole array,
//  so the write endpoint replaces the customer's list in one transaction. That
//  keeps the existing UI code working without an id round-trip per row.
// ===========================================================================
function addressOut(row) {
  return {
    name: row.recipient_name || "",
    phone: row.phone || "",
    street: row.street || "",
    city: row.city || "",
    postal: row.postal || "",
    label: row.label || "Home",
    default: !!row.is_default,
  };
}

router.get(
  "/api/account/addresses",
  auth.loginRequired,
  h(async (req, res) => {
    const rows = await db.query(
      "SELECT * FROM tbl_customer_addresses WHERE user_id=? ORDER BY sort_order, address_id",
      [req.user.user_id]
    );
    res.json({ addresses: rows.map(addressOut) });
  })
);

router.put(
  "/api/account/addresses",
  auth.loginRequired,
  h(async (req, res) => {
    const list = Array.isArray(req.body && req.body.addresses) ? req.body.addresses : [];
    const conn = await db.pool.getConnection();
    try {
      await conn.beginTransaction();
      await conn.query("DELETE FROM tbl_customer_addresses WHERE user_id=?", [req.user.user_id]);
      for (let i = 0; i < list.length; i++) {
        const a = list[i] || {};
        await conn.query(
          "INSERT INTO tbl_customer_addresses " +
            "(user_id, label, recipient_name, phone, street, city, postal, is_default, sort_order) " +
            "VALUES (?,?,?,?,?,?,?,?,?)",
          [
            req.user.user_id,
            a.label || "Home",
            a.name || null,
            a.phone || null,
            a.street || null,
            a.city || null,
            a.postal || null,
            a.default ? 1 : 0,
            i,
          ]
        );
      }
      await conn.commit();
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }
    res.json({ ok: true, count: list.length });
  })
);

// ===========================================================================
//  ONLINE ORDERS
// ===========================================================================
function orderOut(row, items, fab) {
  const iso = new Date(row.ordered_at).toISOString();
  return {
    assignedTo: fab && fab.assigned_to !== null ? fab.assigned_to : null,
    assignedName: (fab && fab.assigned_name) || null,
    helper1: fab && fab.helper_1 !== null ? fab.helper_1 : null,
    helper1Name: (fab && fab.helper_1_name) || null,
    helper2: fab && fab.helper_2 !== null ? fab.helper_2 : null,
    helper2Name: (fab && fab.helper_2_name) || null,
    fabJobs: fab ? Number(fab.jobs) : 0,
    fabJobsDone: fab ? Number(fab.jobs_done) : 0,
    // Both names are emitted because the account page reads `ref` while the
    // staff sales page reads `id` — same order, same reference string.
    id: row.order_ref,
    ref: row.order_ref,
    // The numeric key, which the fabrication release/assign endpoints address.
    orderId: row.online_order_id,
    fabricationDoneAt: row.fabrication_done_at
      ? new Date(row.fabrication_done_at).toISOString() : null,
    releasedToDeliveryAt: row.released_to_delivery_at
      ? new Date(row.released_to_delivery_at).toISOString() : null,
    username: row.username,
    customerName: row.customer_name || row.username,
    address: row.address || "",
    status: row.status,
    total: parseFloat(row.total),
    date: iso,
    fulfillment: row.fulfillment,
    payment: row.payment_method,
    shippingFee: parseFloat(row.shipping_fee),
    paidNow: parseFloat(row.paid_now),
    balance: parseFloat(row.balance),
    pickupLocation: row.pickup_location,
    processedAt: row.processed_at ? new Date(row.processed_at).toISOString() : null,
    merchandise_subtotal: parseFloat(row.merchandise_subtotal || 0),
    voucher_code: row.voucher_code || "",
    voucher_discount: parseFloat(row.voucher_discount || 0),
    cut_fee: parseFloat(row.cut_fee || 0),
    bend_fee: parseFloat(row.bend_fee || 0),
    payment_channel: row.payment_channel || "cash",
    payment_status: row.payment_status || "unpaid",
    gcash_reference: row.gcash_reference || "",
    gcash_receipt: row.gcash_receipt || "",
    items: items.map((it) => ({
      id: it.product_ref,
      name: it.item_name,
      size: it.item_size || "",
      price: parseFloat(it.unit_price),
      qty: it.quantity,
      image: it.image || "",
      is_custom: !!it.is_custom,
      custom_photo: it.custom_photo || "",
      cuts: Number(it.cuts || 0),
      bends: Number(it.bends || 0),
      custom_instructions: it.custom_instructions || "",
      custom_fee: parseFloat(it.custom_fee || 0),
    })),
  };
}

/** Load orders plus their line items in two queries (no N+1 per order). */
async function loadOrders(where, params) {
  const orders = await db.query(
    "SELECT o.*, u.username FROM tbl_online_orders o " +
      "JOIN tbl_users u ON u.user_id = o.user_id " +
      where +
      " ORDER BY o.ordered_at DESC, o.online_order_id DESC",
    params
  );
  if (!orders.length) return [];
  const ids = orders.map((o) => o.online_order_id);
  const items = await db.query(
    "SELECT * FROM tbl_online_order_items WHERE online_order_id IN (" +
      ids.map(() => "?").join(",") +
      ") ORDER BY item_id",
    ids
  );
  const byOrder = new Map(ids.map((id) => [id, []]));
  for (const it of items) byOrder.get(it.online_order_id).push(it);

  // Who on the shop floor is holding this order, and how far along it is. The
  // sales page needs it to pre-select the right name and to know when the
  // order is finished enough to release to delivery.
  const fab = await db.query(
    "SELECT f.online_order_id, MAX(f.assigned_to) AS assigned_to, " +
      "       MAX(u.full_name) AS assigned_name, COUNT(*) AS jobs, " +
      // The helpers the Sales Manager named alongside the main fabricator.
      "       MAX(f.helper_1) AS helper_1, MAX(h1.full_name) AS helper_1_name, " +
      "       MAX(f.helper_2) AS helper_2, MAX(h2.full_name) AS helper_2_name, " +
      "       SUM(f.production_status = 'completed') AS jobs_done " +
      "FROM tbl_fabrication_logs f LEFT JOIN tbl_users u ON u.user_id = f.assigned_to " +
      "LEFT JOIN tbl_users h1 ON h1.user_id = f.helper_1 " +
      "LEFT JOIN tbl_users h2 ON h2.user_id = f.helper_2 " +
      "WHERE f.online_order_id IN (" + ids.map(() => "?").join(",") + ") " +
      "GROUP BY f.online_order_id",
    ids
  );
  const fabBy = new Map(fab.map((f) => [f.online_order_id, f]));

  return orders.map((o) =>
    orderOut(o, byOrder.get(o.online_order_id), fabBy.get(o.online_order_id))
  );
}

// ---------------------------------------------------------------------------
//  VOUCHERS
// ---------------------------------------------------------------------------

/** What the customer can browse in "My Vouchers". */
router.get(
  "/api/account/vouchers",
  auth.loginRequired,
  h(async (req, res) => {
    const rows = await db.query(
      "SELECT v.code, v.discount_type, v.value, v.description, v.min_order, " +
      "       v.uses_left, v.total_uses, v.expires_on, v.is_active, " +
      "       (SELECT COUNT(*) FROM tbl_voucher_redemptions r " +
      "         WHERE r.voucher_id = v.voucher_id AND r.user_id = ?) AS already_used " +
      "FROM tbl_vouchers v ORDER BY v.is_active DESC, v.expires_on IS NULL, v.expires_on",
      [req.user.user_id]
    );
    res.json({
      vouchers: rows.map((v) => ({
        code: v.code,
        type: v.discount_type,
        value: parseFloat(v.value),
        description: v.description || "",
        min_order: parseFloat(v.min_order),
        uses_left: v.uses_left,
        total_uses: v.total_uses,
        // dateOnly, not toISOString: an expiry is a calendar date, and UTC
        // conversion would show it a day early in Philippine time.
        expires: v.expires_on ? dateOnly(v.expires_on) : null,
        active: !!v.is_active,
        already_used: !!v.already_used,
      })),
    });
  })
);

/** Check a code against a live subtotal, without committing to anything. */
router.post(
  "/api/account/voucher/check",
  auth.loginRequired,
  h(async (req, res) => {
    const b = req.body || {};
    const result = await evaluateVoucher(b.code, b.subtotal, req.user.user_id);
    if (!result.ok) return res.status(400).json({ error: result.error });
    res.json({
      ok: true,
      code: result.code,
      discount: result.discount,
      description: result.description,
      discount_type: result.discount_type,
      value: result.value,
    });
  })
);

router.get(
  "/api/account/orders",
  auth.loginRequired,
  h(async (req, res) => {
    res.json({ orders: await loadOrders("WHERE o.user_id = ?", [req.user.user_id]) });
  })
);

router.post(
  "/api/account/orders",
  auth.loginRequired,
  h(async (req, res) => {
    const b = req.body || {};
    const items = Array.isArray(b.items) ? b.items : [];
    if (!items.length) return res.status(400).json({ error: "An order needs at least one item." });

    // ---- validate + price every line ------------------------------------
    // Totals are recomputed here from the line data. Anything the browser sent
    // as a total is ignored, so a tampered page cannot change what is charged.
    let merchandise = 0, cutFee = 0, bendFee = 0;
    const priced = [];
    for (const it of items) {
      const qty = Math.max(1, parseInt(it.qty, 10) || 1);
      const unit = peso(it.price);
      const isCustom = !!it.is_custom;
      const cuts = isCustom ? Math.max(0, parseInt(it.cuts, 10) || 0) : 0;
      const bends = isCustom ? Math.max(0, parseInt(it.bends, 10) || 0) : 0;

      // Only the products in CUSTOMIZABLE_NAMES can be cut or bent. The page
      // hides the option for the rest; this stops a crafted request too.
      if (isCustom && !catalog.isCustomizable(String(it.id || ""))) {
        return res.status(400).json({
          error: `"${it.name || "This item"}" can't be customized. Only these products can be ` +
                 "cut or bent to order: " + catalog.CUSTOMIZABLE_NAMES.join(", ") + ".",
        });
      }

      if (isCustom && !it.custom_photo) {
        return res.status(400).json({
          error: `"${it.name || "An item"}" is marked for customization, so a reference photo is required.`,
        });
      }
      const lineCut = cuts * CUT_FEE;
      const lineBend = bends * BEND_FEE;
      merchandise += unit * qty;
      cutFee += lineCut;
      bendFee += lineBend;

      priced.push({
        product_ref: it.id != null ? String(it.id) : null,
        name: it.name || "Item",
        size: it.size || null,
        unit, qty,
        image: it.image || null,
        is_custom: isCustom ? 1 : 0,
        custom_photo: isCustom ? String(it.custom_photo).slice(0, 255) : null,
        cuts, bends,
        instructions: isCustom ? String(it.custom_instructions || "").slice(0, 500) : null,
        custom_fee: peso(lineCut + lineBend),
      });
    }

    const fulfillment = b.fulfillment === "pickup" ? "pickup" : "delivery";
    const shipping = fulfillment === "pickup" ? 0 : DELIVERY_FEE;
    merchandise = peso(merchandise);
    cutFee = peso(cutFee);
    bendFee = peso(bendFee);

    // ---- voucher, re-checked here ----------------------------------------
    // The browser's claimed discount is ignored: the code is looked up and the
    // amount recomputed against the subtotal the server just calculated.
    let voucherCode = null, voucherDiscount = 0, voucherRow = null;
    if (b.voucher_code) {
      const vr = await evaluateVoucher(b.voucher_code, merchandise + cutFee + bendFee, req.user.user_id);
      if (!vr.ok) return res.status(400).json({ error: vr.error });
      voucherCode = vr.code;
      voucherDiscount = vr.discount;
      voucherRow = vr.voucher;
    }

    const total = peso(merchandise + cutFee + bendFee - voucherDiscount + shipping);
    const split = b.payment === "split";
    const paidNow = split ? peso(total * SPLIT_RATE) : total;
    const balance = peso(total - paidNow);

    // ---- payment channel --------------------------------------------------
    const channel = b.payment_channel === "gcash" ? "gcash" : "cash";
    let gcashRef = null, gcashReceipt = null, paymentStatus = "unpaid";
    if (channel === "gcash") {
      // Same rule the counter uses, so one reference cannot pass one route and
      // fail the other.
      const v = payments.normaliseReference(b.gcash_reference);
      if (!v.ok) return res.status(400).json({ error: v.error });
      gcashRef = v.ref;
      gcashReceipt = String(b.gcash_receipt || "").trim();
      if (!gcashReceipt) return res.status(400).json({ error: "Upload a photo of your GCash receipt." });
      // Never auto-mark as paid: a human confirms the transfer arrived.
      // A reference already used elsewhere does not block the order — it is
      // saved and shown to the Sales Manager in red.
      paymentStatus = "pending_verification";
    }

    const ref = String(b.ref || b.id || "").trim() || "GT-" + Date.now().toString(36).toUpperCase();
    const conn = await db.pool.getConnection();
    let orderId;
    try {
      await conn.beginTransaction();
      const [result] = await conn.query(
        "INSERT INTO tbl_online_orders " +
          "(order_ref, user_id, customer_name, address, status, total, fulfillment, " +
          " payment_method, shipping_fee, paid_now, balance, pickup_location, " +
          " merchandise_subtotal, cut_fee, bend_fee, payment_channel, payment_status, " +
          " gcash_reference, gcash_receipt, voucher_code, voucher_discount) " +
          "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [
          ref, req.user.user_id, b.customerName || null, b.address || null,
          b.status || "pending", total, fulfillment,
          split ? "split" : "full", shipping, paidNow, balance, b.pickupLocation || null,
          merchandise, cutFee, bendFee, channel, paymentStatus, gcashRef, gcashReceipt,
          voucherCode, voucherDiscount,
        ]
      );
      orderId = result.insertId;
      for (const it of priced) {
        await conn.query(
          "INSERT INTO tbl_online_order_items " +
            "(online_order_id, product_ref, item_name, item_size, unit_price, quantity, image, " +
            " is_custom, custom_photo, cuts, bends, custom_instructions, custom_fee) " +
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
          [orderId, it.product_ref, it.name, it.size, it.unit, it.qty, it.image,
           it.is_custom, it.custom_photo, it.cuts, it.bends, it.instructions, it.custom_fee]
        );
      }
      // Spend the voucher in the SAME transaction as the order, so a failure
      // cannot leave a redemption recorded against an order that never existed.
      if (voucherRow) {
        const [dec] = await conn.query(
          "UPDATE tbl_vouchers SET uses_left = uses_left - 1 " +
          "WHERE voucher_id = ? AND uses_left > 0", [voucherRow.voucher_id]);
        if (!dec.affectedRows) throw new Error("VOUCHER_EXHAUSTED");
        await conn.query(
          "INSERT INTO tbl_voucher_redemptions " +
          "(voucher_id, user_id, online_order_id, order_ref, discount_amount) VALUES (?,?,?,?,?)",
          [voucherRow.voucher_id, req.user.user_id, orderId, ref, voucherDiscount]);
      }
      await conn.commit();
    } catch (e) {
      await conn.rollback();
      if (e.message === "VOUCHER_EXHAUSTED") {
        return res.status(400).json({ error: "That voucher was just fully redeemed. Please remove it." });
      }
      throw e;
    } finally {
      conn.release();
    }

    await db.audit(req.user.user_id,
      `Placed online order ${ref} (${channel}${channel === "gcash" ? ", awaiting verification" : ""})`,
      "tbl_online_orders", clientIp(req));
    const [order] = await loadOrders("WHERE o.online_order_id = ?", [orderId]);
    res.json({ ok: true, order });
  })
);

// ---------------------------------------------------------------------------
//  Checkout uploads - the customization reference photo and the GCash receipt.
//  Stored under /uploads with a generated name; the original filename is never
//  used to build a path.
// ---------------------------------------------------------------------------
router.post(
  "/api/account/upload",
  auth.loginRequired,
  (req, res, next) => req.app.locals.checkoutUpload(req, res, next),
  h(async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No file received." });
    const kind = String((req.body || {}).kind || "custom").replace(/[^a-z]/g, "") || "custom";
    const ext = (req.file.mimetype === "image/png") ? "png" : "jpg";
    const name = `${kind}_${req.user.user_id}_${Date.now()}_${Math.floor(Math.random() * 1e4)}.${ext}`;
    const stored = await req.app.locals.saveUpload(req.file, name, req.user.user_id);
    res.json({ ok: true, path: stored });
  })
);

// ---------------------------------------------------------------------------
//  STAFF VOUCHER MANAGEMENT
//
//  A voucher created here is immediately visible to every customer, because
//  both sides read the one tbl_vouchers table - there is nothing to sync and
//  no per-customer copy to go stale.
// ---------------------------------------------------------------------------
function staffVoucherOut(v) {
  return {
    code: v.code,
    type: v.discount_type,
    value: parseFloat(v.value),
    desc: v.description || "",
    min_order: parseFloat(v.min_order),
    uses_left: v.uses_left,
    total_uses: v.total_uses,
    expires: v.expires_on ? dateOnly(v.expires_on) : null,
    active: !!v.is_active,
    redeemed: Number(v.redeemed || 0),
    // What the old hardcoded screen called "status".
    status: !v.is_active || v.uses_left <= 0 ? "expired" : "active",
  };
}

router.get(
  "/api/sales/vouchers",
  auth.requireRole("Sales Manager", "Administrator"),
  h(async (req, res) => {
    const rows = await db.query(
      "SELECT v.*, (SELECT COUNT(*) FROM tbl_voucher_redemptions r WHERE r.voucher_id = v.voucher_id) AS redeemed " +
      "FROM tbl_vouchers v ORDER BY v.is_active DESC, v.created_at DESC"
    );
    res.json({ vouchers: rows.map(staffVoucherOut) });
  })
);

router.post(
  "/api/sales/vouchers",
  auth.requireRole("Sales Manager", "Administrator"),
  h(async (req, res) => {
    const b = req.body || {};
    const code = String(b.code || "").trim().toUpperCase();
    if (!/^[A-Z0-9_-]{3,32}$/.test(code)) {
      return res.status(400).json({ error: "Code must be 3-32 characters: letters, numbers, - or _ only." });
    }
    const type = b.type === "fixed" ? "fixed" : "percent";
    const value = parseFloat(b.value);
    if (!(value > 0)) return res.status(400).json({ error: "Enter a discount value greater than zero." });
    if (type === "percent" && value > 100) {
      return res.status(400).json({ error: "A percentage discount cannot exceed 100%." });
    }
    const minOrder = Math.max(0, parseFloat(b.min_order) || 0);
    const limit = Math.max(1, parseInt(b.uses_left || b.total_uses, 10) || 1);
    const expires = String(b.expires || "").trim() || null;   // YYYY-MM-DD
    if (expires && !/^\d{4}-\d{2}-\d{2}$/.test(expires)) {
      return res.status(400).json({ error: "Expiry date must be a valid date." });
    }

    if (await db.query("SELECT 1 FROM tbl_vouchers WHERE code = ?", [code], true)) {
      return res.status(409).json({ error: "That voucher code already exists." });
    }

    await db.execute(
      "INSERT INTO tbl_vouchers (code, discount_type, value, description, min_order, " +
      " uses_left, total_uses, expires_on, is_active, created_by) VALUES (?,?,?,?,?,?,?,?,1,?)",
      [code, type, value, String(b.desc || "").slice(0, 255) || null, minOrder,
       limit, limit, expires, req.user.user_id]
    );
    await db.audit(req.user.user_id, `Created voucher ${code}`, "tbl_vouchers", clientIp(req));

    const row = await db.query("SELECT * FROM tbl_vouchers WHERE code = ?", [code], true);
    res.json({ ok: true, voucher: staffVoucherOut(row) });
  })
);

/** Revoke: keeps the row (and its redemption history) but stops new use. */
router.patch(
  "/api/sales/vouchers/:code",
  auth.requireRole("Sales Manager", "Administrator"),
  h(async (req, res) => {
    const code = String(req.params.code || "").toUpperCase();
    const row = await db.query("SELECT * FROM tbl_vouchers WHERE code = ?", [code], true);
    if (!row) return res.status(404).json({ error: "Voucher not found." });

    const b = req.body || {};
    if ("active" in b) {
      await db.execute("UPDATE tbl_vouchers SET is_active = ? WHERE voucher_id = ?",
                       [b.active ? 1 : 0, row.voucher_id]);
      await db.audit(req.user.user_id,
        `${b.active ? "Re-activated" : "Revoked"} voucher ${code}`, "tbl_vouchers", clientIp(req));
    }
    const updated = await db.query("SELECT * FROM tbl_vouchers WHERE voucher_id = ?", [row.voucher_id], true);
    res.json({ ok: true, voucher: staffVoucherOut(updated) });
  })
);

// --- Staff view of the same order book -------------------------------------
router.get(
  "/api/online-orders",
  auth.requireRole("Sales Manager", "Administrator"),
  h(async (req, res) => {
    const status = String(req.query.status || "all");
    if (status !== "all") {
      return res.json({ orders: await loadOrders("WHERE o.status = ?", [status]) });
    }
    res.json({ orders: await loadOrders("", []) });
  })
);

router.patch(
  "/api/online-orders/:ref",
  auth.requireRole("Sales Manager", "Administrator"),
  h(async (req, res) => {
    const allowed = ["pending", "accepted", "declined"];
    const status = String((req.body || {}).status || "");
    if (!allowed.includes(status)) {
      return res.status(400).json({ error: "status must be one of: " + allowed.join(", ") });
    }
    await db.execute(
      "UPDATE tbl_online_orders SET status=?, processed_at=? WHERE order_ref=?",
      [status, status === "pending" ? null : new Date(), req.params.ref]
    );
    await db.audit(
      req.user.user_id,
      "Set online order " + req.params.ref + " to '" + status + "'",
      "tbl_online_orders",
      clientIp(req)
    );
    res.json({ ok: true });
  })
);

module.exports = router;
