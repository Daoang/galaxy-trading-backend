/**
 * suppliers.js — the supplier directory.
 *
 * WHY THIS EXISTS
 *   The Inventory Manager panel used to render a hard-coded JavaScript array of
 *   four made-up suppliers. Editing it changed nothing: the array was rebuilt
 *   from source on every page load, so a supplier "added" there vanished on
 *   refresh and was never visible to anyone else.
 *
 * WHO CAN DO WHAT
 *   Administrator  add, edit, archive.
 *   Everyone else  read only. Inventory needs the list to raise restock
 *                  requests, Sales quotes lead times from it.
 *
 * KEEPING THE PANELS IN STEP
 *   Every write bumps tbl_suppliers.updated_at. GET /api/suppliers returns the
 *   newest of those as `version`, so a panel can poll that one small number and
 *   only redraw when it actually changes.
 *
 * Mounted by app.js. Run database/migration_supplier_admin.sql first.
 */
const express = require("express");

const auth = require("./auth");
const db = require("./db");

const router = express.Router();

const h = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const clientIp = (req) =>
  (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress || "";

// Any signed-in staff member may read the directory; only an Administrator writes.
const READERS = ["Administrator", "Inventory Manager", "Sales Manager", "Employee",
                 "Fabrication", "Delivery Personnel"];

const SELECT =
  "SELECT s.supplier_id, s.supplier_name, s.contact_person, s.phone, s.email, " +
  "       s.address, s.materials_supplied, s.payment_terms, s.notes, " +
  "       s.is_active, s.created_at, s.updated_at, " +
  "       COUNT(po.po_id) AS purchase_orders, " +
  "       MAX(po.order_date) AS last_order_at " +
  "FROM tbl_suppliers s " +
  "LEFT JOIN tbl_purchase_orders po ON po.supplier_id = s.supplier_id ";

const GROUP = "GROUP BY s.supplier_id ORDER BY s.is_active DESC, s.supplier_name";

function shape(r) {
  return {
    supplier_id: r.supplier_id,
    name: r.supplier_name,
    contact: r.contact_person || "",
    phone: r.phone || "",
    email: r.email || "",
    address: r.address || "",
    materials: r.materials_supplied || "",
    terms: r.payment_terms || "",
    notes: r.notes || "",
    is_active: !!r.is_active,
    purchase_orders: Number(r.purchase_orders) || 0,
    last_order_at: r.last_order_at || null,
    updated_at: r.updated_at,
  };
}

/**
 * Newest updated_at across the table — the number panels poll.
 *
 * updated_at is DATETIME(3), so UNIX_TIMESTAMP returns milliseconds. Whole
 * seconds were not enough: two edits inside the same second produced the same
 * version and a reader polling across that boundary never noticed the second
 * one. The row count is folded in as well, so a deletion still moves it even
 * if the remaining rows are untouched.
 */
async function currentVersion() {
  const row = await db.query(
    "SELECT COALESCE(UNIX_TIMESTAMP(MAX(updated_at)), 0) AS v, COUNT(*) AS n FROM tbl_suppliers",
    [], true);
  return `${(row && row.v) || 0}-${(row && row.n) || 0}`;
}

// ---------------------------------------------------------------------------
//  Reading
// ---------------------------------------------------------------------------

/** The directory. ?include_archived=1 for the Administrator's own view. */
router.get(
  "/api/suppliers",
  auth.requireRole(...READERS),
  h(async (req, res) => {
    const all = req.query.include_archived === "1";
    const rows = await db.query(
      SELECT + (all ? "" : "WHERE s.is_active = 1 ") + GROUP);
    res.json({ suppliers: rows.map(shape), version: await currentVersion() });
  })
);

/**
 * Just the version, for polling. Deliberately tiny: the Inventory panel asks
 * for this every few seconds and only re-reads the list when it changes.
 */
router.get(
  "/api/suppliers/version",
  auth.requireRole(...READERS),
  h(async (req, res) => {
    res.json({ version: await currentVersion() });
  })
);

// ---------------------------------------------------------------------------
//  Writing — Administrator only
// ---------------------------------------------------------------------------

function readBody(b) {
  const s = (v, n) => (v === undefined || v === null ? null : String(v).trim().slice(0, n) || null);
  return {
    name: s(b.name, 120),
    contact: s(b.contact, 120),
    phone: s(b.phone, 40),
    email: s(b.email, 120),
    address: s(b.address, 255),
    materials: s(b.materials, 255),
    terms: s(b.terms, 40),
    notes: s(b.notes, 500),
  };
}

router.post(
  "/api/admin/suppliers",
  auth.requireRole("Administrator"),
  h(async (req, res) => {
    const f = readBody(req.body || {});
    if (!f.name) return res.status(400).json({ error: "A supplier name is required." });

    const clash = await db.query(
      "SELECT supplier_id FROM tbl_suppliers WHERE supplier_name = ?", [f.name], true);
    if (clash) return res.status(409).json({ error: "A supplier with that name already exists." });

    const id = await db.execute(
      "INSERT INTO tbl_suppliers (supplier_name, contact_person, phone, email, address, " +
        "materials_supplied, payment_terms, notes, is_active) VALUES (?,?,?,?,?,?,?,?,1)",
      [f.name, f.contact, f.phone, f.email, f.address, f.materials, f.terms, f.notes]);

    await db.audit(req.user.user_id, `Added supplier '${f.name}'`, "tbl_suppliers", clientIp(req));
    const row = await db.query(SELECT + "WHERE s.supplier_id = ? " + GROUP, [id], true);
    res.json({ ok: true, supplier: shape(row), version: await currentVersion() });
  })
);

router.patch(
  "/api/admin/suppliers/:id",
  auth.requireRole("Administrator"),
  h(async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const existing = await db.query(
      "SELECT supplier_id, supplier_name FROM tbl_suppliers WHERE supplier_id = ?", [id], true);
    if (!existing) return res.status(404).json({ error: "Supplier not found." });

    const f = readBody(req.body || {});
    if (!f.name) return res.status(400).json({ error: "A supplier name is required." });

    const clash = await db.query(
      "SELECT supplier_id FROM tbl_suppliers WHERE supplier_name = ? AND supplier_id <> ?",
      [f.name, id], true);
    if (clash) return res.status(409).json({ error: "Another supplier already uses that name." });

    await db.execute(
      "UPDATE tbl_suppliers SET supplier_name=?, contact_person=?, phone=?, email=?, " +
        "address=?, materials_supplied=?, payment_terms=?, notes=? WHERE supplier_id=?",
      [f.name, f.contact, f.phone, f.email, f.address, f.materials, f.terms, f.notes, id]);

    await db.audit(req.user.user_id, `Updated supplier '${f.name}'`, "tbl_suppliers", clientIp(req));
    const row = await db.query(SELECT + "WHERE s.supplier_id = ? " + GROUP, [id], true);
    res.json({ ok: true, supplier: shape(row), version: await currentVersion() });
  })
);

/**
 * Archive or restore. Never a DELETE: tbl_purchase_orders points here, so
 * removing the row would strand its order history.
 */
router.post(
  "/api/admin/suppliers/:id/archive",
  auth.requireRole("Administrator"),
  h(async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const active = (req.body || {}).active === true ? 1 : 0;
    const existing = await db.query(
      "SELECT supplier_id, supplier_name FROM tbl_suppliers WHERE supplier_id = ?", [id], true);
    if (!existing) return res.status(404).json({ error: "Supplier not found." });

    await db.execute("UPDATE tbl_suppliers SET is_active=? WHERE supplier_id=?", [active, id]);
    await db.audit(req.user.user_id,
      `${active ? "Restored" : "Archived"} supplier '${existing.supplier_name}'`,
      "tbl_suppliers", clientIp(req));

    const row = await db.query(SELECT + "WHERE s.supplier_id = ? " + GROUP, [id], true);
    res.json({ ok: true, supplier: shape(row), version: await currentVersion() });
  })
);

module.exports = router;
