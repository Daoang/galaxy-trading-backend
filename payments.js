/**
 * payments.js — GCash reference handling, shared by the counter and the
 * storefront, plus the transaction history the Sales Manager reads.
 *
 * WHY A SHARED MODULE
 *   The same reference number can arrive from two places: the POS when a
 *   walk-in customer pays by GCash, and the checkout when an online customer
 *   does. A duplicate only means something if both places are checked, so the
 *   rule for what a reference looks like, and the lookup for whether it has
 *   been claimed before, live here rather than in either panel.
 *
 * ON DUPLICATES
 *   A repeated reference does NOT block the sale. Legitimate reasons exist —
 *   a mistyped digit, one transfer covering two orders, a customer re-sending
 *   the same screenshot by accident — and refusing the sale at the counter
 *   over it would be worse than recording it. The order is saved and flagged,
 *   and the Sales Manager sees it in red on the transaction list.
 *
 * Mounted by app.js. Run database/migration_gcash_payments.sql first.
 */
const express = require("express");

const auth = require("./auth");
const db = require("./db");

const router = express.Router();

const h = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// GCash reference numbers are digits only, at most 13 of them.
const GCASH_REF_MAX = 13;
const GCASH_REF_RE = /^\d{1,13}$/;

/**
 * Check a reference the user typed.
 * Returns { ok: true, ref } or { ok: false, error } — never throws, so both
 * the POS and the checkout can report the same wording.
 */
function normaliseReference(raw) {
  // People paste references with spaces or dashes out of the GCash app.
  const ref = String(raw || "").replace(/[\s-]/g, "").trim();
  if (!ref) return { ok: false, error: "Enter the GCash reference number." };
  if (!/^\d+$/.test(ref)) {
    return { ok: false, error: "The GCash reference number is digits only." };
  }
  if (ref.length > GCASH_REF_MAX) {
    return { ok: false, error: `The GCash reference number is at most ${GCASH_REF_MAX} digits.` };
  }
  return { ok: true, ref };
}

/**
 * Has this reference been claimed before? Looks at BOTH order books.
 * `skip` lets a row exclude itself when re-checking after a save.
 */
async function findReferenceUses(ref, skip) {
  if (!ref) return [];
  const walkin = await db.query(
    "SELECT o.order_id AS id, 'walk-in' AS source, o.invoice_no AS label, o.order_date AS at, " +
      "       o.total_amount AS amount, u.full_name AS customer " +
      "FROM tbl_orders o LEFT JOIN tbl_users u ON u.user_id = o.customer_id " +
      "WHERE o.gcash_reference = ?" + (skip && skip.walkin ? " AND o.order_id <> ?" : ""),
    skip && skip.walkin ? [ref, skip.walkin] : [ref]
  );
  const online = await db.query(
    "SELECT oo.online_order_id AS id, 'storefront' AS source, oo.order_ref AS label, " +
      "       oo.ordered_at AS at, oo.total AS amount, oo.customer_name AS customer " +
      "FROM tbl_online_orders oo WHERE oo.gcash_reference = ?" +
      (skip && skip.online ? " AND oo.online_order_id <> ?" : ""),
    skip && skip.online ? [ref, skip.online] : [ref]
  );
  return walkin.concat(online);
}

// ===========================================================================
//  TRANSACTION HISTORY
// ===========================================================================
//
//  One list from two order books. The Sales Manager panel used to render a
//  hard-coded array of three invented sales, so a real sale — online or at the
//  counter — never showed up here at all.
//
router.get(
  "/api/sales/transactions",
  auth.requireRole("Sales Manager", "Administrator"),
  h(async (req, res) => {
    const vatRate = 0.12;

    const walkin = await db.query(
      "SELECT o.order_id, o.invoice_no, o.order_reference, o.order_date, o.total_amount, " +
        "       o.discount_amount, o.vat_amount, o.payment_method, o.payment_channel, " +
        "       o.gcash_reference, o.payment_status, o.order_status, " +
        "       u.full_name AS customer, " +
        "       (SELECT COUNT(*) FROM tbl_order_items i WHERE i.order_id = o.order_id) AS items " +
        "FROM tbl_orders o LEFT JOIN tbl_users u ON u.user_id = o.customer_id " +
        "ORDER BY o.order_date DESC, o.order_id DESC LIMIT 300"
    );

    const online = await db.query(
      "SELECT oo.online_order_id, oo.order_ref, oo.ordered_at, oo.total, oo.voucher_discount, " +
        "       oo.payment_channel, oo.gcash_reference, oo.payment_status, oo.status, " +
        "       oo.customer_name, " +
        "       (SELECT COUNT(*) FROM tbl_online_order_items i " +
        "         WHERE i.online_order_id = oo.online_order_id) AS items " +
        "FROM tbl_online_orders oo ORDER BY oo.ordered_at DESC, oo.online_order_id DESC LIMIT 300"
    );

    const num = (v) => Math.round((parseFloat(v) || 0) * 100) / 100;

    const rows = [];
    for (const o of walkin) {
      const total = num(o.total_amount);
      rows.push({
        key: "w" + o.order_id,
        source: "walk-in",
        invoice: o.invoice_no || o.order_reference,
        date: o.order_date,
        customer: o.customer || "Walk-in customer",
        items: Number(o.items) || 0,
        gross: num(Number(total) + num(o.discount_amount)),
        discount: num(o.discount_amount),
        vat: o.vat_amount !== null ? num(o.vat_amount) : num(total - total / (1 + vatRate)),
        total,
        channel: (o.payment_channel || o.payment_method || "cash").toLowerCase() === "gcash"
          ? "gcash" : "cash",
        gcash_reference: o.gcash_reference || null,
        payment_status: o.payment_status || "paid",
        status: o.order_status,
      });
    }
    for (const o of online) {
      const total = num(o.total);
      rows.push({
        key: "o" + o.online_order_id,
        source: "storefront",
        invoice: o.order_ref,
        date: o.ordered_at,
        customer: o.customer_name || "Online customer",
        items: Number(o.items) || 0,
        gross: num(total + num(o.voucher_discount)),
        discount: num(o.voucher_discount),
        vat: num(total - total / (1 + vatRate)),
        total,
        channel: (o.payment_channel || "cash").toLowerCase() === "gcash" ? "gcash" : "cash",
        gcash_reference: o.gcash_reference || null,
        payment_status: o.payment_status || "unpaid",
        status: o.status,
      });
    }

    // Flag every row whose reference appears more than once across both books.
    const seen = {};
    rows.forEach((r) => {
      if (!r.gcash_reference) return;
      (seen[r.gcash_reference] = seen[r.gcash_reference] || []).push(r);
    });
    Object.keys(seen).forEach((ref) => {
      if (seen[ref].length < 2) return;
      seen[ref].forEach((r) => {
        r.duplicate_reference = true;
        // What else claims this number, so the panel can name them.
        r.duplicate_with = seen[ref]
          .filter((x) => x.key !== r.key)
          .map((x) => ({ invoice: x.invoice, source: x.source, customer: x.customer }));
      });
    });

    rows.sort((a, b) => new Date(b.date) - new Date(a.date));

    const flagged = rows.filter((r) => r.duplicate_reference).length;
    res.json({
      transactions: rows,
      summary: {
        count: rows.length,
        revenue: num(rows.reduce((a, r) => a + r.total, 0)),
        vat: num(rows.reduce((a, r) => a + r.vat, 0)),
        discounts: num(rows.reduce((a, r) => a + r.discount, 0)),
        gcash: rows.filter((r) => r.channel === "gcash").length,
        duplicate_references: flagged,
      },
    });
  })
);

/**
 * Look a reference up before saving, so the counter can warn the cashier while
 * the customer is still standing there.
 */
router.get(
  "/api/sales/gcash-reference/:ref",
  auth.requireRole("Sales Manager", "Administrator"),
  h(async (req, res) => {
    const v = normaliseReference(req.params.ref);
    if (!v.ok) return res.status(400).json({ error: v.error });
    const uses = await findReferenceUses(v.ref);
    res.json({ reference: v.ref, used: uses.length > 0, uses });
  })
);

module.exports = router;
module.exports.normaliseReference = normaliseReference;
module.exports.findReferenceUses = findReferenceUses;
module.exports.GCASH_REF_MAX = GCASH_REF_MAX;
module.exports.GCASH_REF_RE = GCASH_REF_RE;
