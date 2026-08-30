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
const express = require("express");
const auth = require("./auth");
const db = require("./db");
const security = require("./security");

const CUSTOMER_ROLE_ID = 6; // tbl_roles: 6 = 'Customer'

// Checkout pricing. These live on the SERVER so the amount a customer is
// charged never depends on numbers posted by the browser.
const CUT_FEE = 20;        // pesos per cut
const BEND_FEE = 20;       // pesos per bend
const DELIVERY_FEE = 150;  // flat door-to-door fee; pick-up is free
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
    name: row.full_name || row.username,
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
//  REGISTRATION  (public — this is the storefront sign-up form)
// ===========================================================================
router.post(
  "/api/auth/register",
  h(async (req, res) => {
    const b = req.body || {};
    const username = String(b.username || "").trim();
    const password = String(b.password || "");
    const fullName = String(b.name || b.full_name || "").trim();
    const phone = String(b.phone || "").trim();
    const email = String(b.email || "").trim();

    if (!username || !password || !fullName) {
      return res.status(400).json({ error: "Username, full name and password are required." });
    }
    const pwErr = security.checkPasswordStrength(password, username);
    if (pwErr) return res.status(400).json({ error: pwErr });
    if (await db.query("SELECT 1 FROM tbl_users WHERE username=?", [username], true)) {
      return res.status(409).json({ error: "Username already taken. Choose another." });
    }

    const uid = await db.execute(
      "INSERT INTO tbl_users (username, password_hash, full_name, email, phone, role_id) " +
        "VALUES (?,?,?,?,?,?)",
      [username, auth.hashPassword(password), fullName, email || null, phone || null, CUSTOMER_ROLE_ID]
    );
    await db.audit(uid, "Customer account created", "tbl_users", clientIp(req));

    const profile = await loadProfile(uid);
    // Sign the customer straight in, matching the old client-side behaviour.
    res.json({
      ok: true,
      token: auth.issueToken({ user_id: uid, username, role_name: "Customer" },
                             { remember: !!b.remember }),
      user: profile,
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
    // Only these columns are editable from the account page; anything else in
    // the body is ignored so a crafted request cannot change a role.
    const map = {
      name: "full_name",
      full_name: "full_name",
      email: "email",
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
    const pwErr = security.checkPasswordStrength(next, req.user.username);
    if (pwErr) return res.status(400).json({ error: pwErr });
    const row = await db.query("SELECT password_hash FROM tbl_users WHERE user_id=?", [req.user.user_id], true);
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
function orderOut(row, items) {
  const iso = new Date(row.ordered_at).toISOString();
  return {
    // Both names are emitted because the account page reads `ref` while the
    // staff sales page reads `id` — same order, same reference string.
    id: row.order_ref,
    ref: row.order_ref,
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
  return orders.map((o) => orderOut(o, byOrder.get(o.online_order_id)));
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
      gcashRef = String(b.gcash_reference || "").trim();
      gcashReceipt = String(b.gcash_receipt || "").trim();
      if (!gcashRef) return res.status(400).json({ error: "Enter the GCash reference number." });
      if (!gcashReceipt) return res.status(400).json({ error: "Upload a photo of your GCash receipt." });
      // Never auto-mark as paid: a human confirms the transfer arrived.
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
    req.app.locals.saveUpload(req.file, name);
    res.json({ ok: true, path: "uploads/" + name });
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
